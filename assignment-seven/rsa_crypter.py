import os
import sys
import argparse
import textwrap
import subprocess
from pathlib import Path

from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes


class Shellcode:
    def __init__(self, shellcode_src: str = None) -> None:
        """ Links, assembles, and loads shellcode from various sources.

        OS Executable Dependencies:
            from .asm/.nasm
                ld
                nasm
                objdump
            from linked/assembled binary
                objdump
            from msfvenom ... -f raw output
                None
            from encrypted shellcode generated with this tool
                None

        :param shellcode_src: source file used to generate/load shellcode
        """
        self.shellcode: bytes = None
        self.shellcode_src: str = shellcode_src

    def _run_cmd(self, cmd: str) -> subprocess.CompletedProcess:
        """ Run shell command, capture stdout, and return the results.

        :param cmd: shell command to be run by subprocess.run
        :return: CompletedProcess returned by subprocess.run(cmd)
        """
        completed_proc: subprocess.CompletedProcess

        try:
            completed_proc = subprocess.run(cmd, stdout=subprocess.PIPE, shell=True)
        except OSError as e:
            if e.errno == os.errno.ENOENT:
                print(f'{cmd.split()[0]} not installed', file=sys.stderr)
            else:
                print(e.with_traceback(), file=sys.stderr)
            raise SystemExit
        return completed_proc

    def load(self, src_type: str = None) -> None:
        """ Depending on src_type; links, assembles, dumps, and loads shellcode from various sources.

        Valid source types are
            bin
                previously linked/assembled binary
            asm
                .asm/.nasm source code
            raw
                shellcode previously encrypted by this tool
                msfvenom ... -f raw output file

        :param src_type: type of source file (bin, asm, raw)
        """
        objfile: str
        _shellcode: bytes
        proc: subprocess.CompletedProcess
        _shellcode_src: Path = Path(self.shellcode_src)

        # link/assemble .nasm/.asm
        if src_type == 'asm':
            objfile = f"{_shellcode_src.stem}.o"
            self._run_cmd(f'nasm -f elf64 {_shellcode_src} -o {objfile}')
            self._run_cmd(f"ld {objfile} -o {_shellcode_src.stem}")

        # dump shellcode from binary (includes types bin/asm)
        if src_type != 'raw':
            proc = self._run_cmd(f"objdump -d {_shellcode_src.stem} | grep '^ ' | cut -f 2")
            _shellcode = br"\x" + br"\x".join(proc.stdout.split())
            self.shellcode = _shellcode

        # do nothing special for '-f raw' and encrypted shellcode
        if src_type == 'raw':
            self.shellcode = _shellcode_src.read_bytes()

    def print(self) -> None:
        """ Simple helper to display loaded shellcode """
        print(self.shellcode.decode())

    def execute(self) -> None:
        """ Exectutes the loaded shellcode.

        Dependencies:
            gcc

        Uses gcc to compile a shellcode skeleton and then exec's the compiled program over the running instance of
        this tool.
        """
        template: str
        skeleton: Path

        template = f"""\
        #include <stdio.h>
        #include <string.h>

        unsigned char code[] = \\
        "{self.shellcode.decode()}";

        int main() {{
            printf("Shellcode length: %zu\\n", strlen(code));
            int (*ret)() = (int(*)())code;
            ret();
        }}
        """
        skeleton = Path("shellcode-skeleton.c")
        skeleton.write_text(textwrap.dedent(template))
        self._run_cmd(f'gcc -o {skeleton.stem} {skeleton} -fno-stack-protector -z execstack')
        os.execv(skeleton.stem, (skeleton.stem,))


class KeyManager:
    def __init__(self, passphrase: str = None) -> None:
        """ Creates, saves, and loads both private and public RSA keys used for asymmetric encryption.

        If a passphrase is specified, KeyManager will encrypt private key file with said passphrase.  The scrypt key
        derivation function is used to guard against dictionary attacks.

        :param passphrase: Optional - passphrase used to encrypt private key file
        """
        self.privkey: RSA.RsaKey
        self.pubkey: RSA.RsaKey
        self.passphrase = passphrase

    def create_keys(self, key_size: int) -> None:
        """ Create private and public RSA keys to be used in asymmetric encryption.

        :param key_size: size of the key used in bits
        """
        key: RSA.RsaKey

        key = RSA.generate(key_size)

        protection = 'scryptAndAES128-CBC' if self.passphrase else None

        self.privkey = key.export_key(passphrase=self.passphrase, pkcs=8, protection=protection)
        self.pubkey = key.publickey().export_key()

    def save_keys(self, privkey_outfile: str, pubkey_outfile: str) -> None:
        """ Write private and public RSA keys to disk.

        :param privkey_outfile: path to private key file (default: private.pem)
        :param pubkey_outfile: path to public key file (default: public.pem)
        """
        privkey_outfile = Path(privkey_outfile)
        privkey_outfile.write_bytes(data=self.privkey)

        pubkey_outfile = Path(pubkey_outfile)
        pubkey_outfile.write_bytes(data=self.pubkey)

    def load_key(self, key_type: str, infile: str) -> None:
        """ Load either a private or public RSA key from disk.

        :param key_type: Required - Expects string of either "public" or "private"
        :param infile: Required - path to key file
        """
        if key_type == 'private':
            self.privkey = RSA.import_key(Path(infile).read_bytes())
        elif key_type == 'public':
            self.pubkey = RSA.import_key(Path(infile).read_bytes())


class Crypter:
    def __init__(self, keymgr: KeyManager, shellcode: Shellcode) -> None:
        """ Encrypts and decrypts shellcode

        If the crypter class is being instantiated, it's assumed that shellcode to either decrypt or encrypt is loaded
        into a Shellcode isntance and will be available via self.shellcode.  Similarly, either a public or private key
        is expected to be loaded into a KeyManager instance and will be available via self.keymgr.

        :param keymgr: KeyManager instance
        :param shellcode: Shellcode instance
        """
        self.keymgr = keymgr
        self.shellcode = shellcode

        self.tag: bytes
        self.nonce: bytes
        self.ciphertext: bytes
        self.encrypted_session_key: bytes

    def encrypt(self) -> None:
        """ Encrypts piece of shellcode using recipient's public RSA key.

        Since we want to be able to encrypt an arbitrary amount of data, we use a hybrid encryption scheme.
        We use RSA with PKCS#1 OAEP for asymmetric encryption of an AES session key. The session key can then be
        used to encrypt all the actual data.

        We use the EAX mode to allow detection of unauthorized modifications.
        - https://pycryptodome.org/en/latest/src/examples.html
        """
        session_key: bytes = get_random_bytes(16)

        rsa_cipher: RSA.RsaKey = PKCS1_OAEP.new(self.keymgr.pubkey)
        self.encrypted_session_key = rsa_cipher.encrypt(session_key)

        aes_cipher = AES.new(session_key, AES.MODE_EAX)
        self.nonce = aes_cipher.nonce
        self.ciphertext, self.tag = aes_cipher.encrypt_and_digest(self.shellcode.shellcode)

    def save(self, outfile='shellcode.enc') -> None:
        """ Simple helper to write shellcode to disk """
        with open(outfile, 'wb') as f:
            for byte in (self.encrypted_session_key, self.nonce, self.tag, self.ciphertext):
                f.write(byte)

    def decrypt(self):
        """ Decrypts piece of shellcode using private RSA key.

        At this point, it's assumed that both the private key and the encrypted shellcode have been loaded by their
        respective classes.
        """
        key_sib = self.keymgr.privkey.size_in_bytes()

        self.encrypted_session_key = self.shellcode.shellcode[:key_sib]
        self.nonce = self.shellcode.shellcode[key_sib:key_sib + 16]
        self.tag = self.shellcode.shellcode[key_sib + 16:key_sib + 32]
        self.ciphertext = self.shellcode.shellcode[key_sib + 32:]

        # use private key to decrypt session key
        cipher_rsa = PKCS1_OAEP.new(self.keymgr.privkey)
        session_key = cipher_rsa.decrypt(self.encrypted_session_key)

        # use decrypted session key to decrypt the shellcode
        cipher_aes = AES.new(session_key, AES.MODE_EAX, self.nonce)
        self.shellcode.shellcode = cipher_aes.decrypt_and_verify(self.ciphertext, self.tag)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Asymmetric Shellcode Encrypter/Decrypter')

    key_opts = parser.add_argument_group('key options', description='creates, saves, and loads both private and public RSA keys used for asymmetric encryption')
    key_opts.add_argument('--key-size', help='size of the key used in bits (default: 2048)', default=2048, choices=[2048, 3072])
    key_opts.add_argument('--privkey-out', help='path to private key file (default: private.pem)', default='private.pem')
    key_opts.add_argument('--pubkey-out', help='path to public key file (default: public.pem)', default='public.pem')
    key_opts.add_argument('--key-type', help='type of key to load', choices=['public', 'private'], default='public')
    key_opts.add_argument('--passphrase', help='passphrase used to en|decrypt private key file')

    in_or_out = key_opts.add_mutually_exclusive_group()
    in_or_out.add_argument('--load-key', dest='infile', help='load either a private or public RSA key from disk')
    in_or_out.add_argument('--create', action='store_true', help='create private and public RSA keys and save them')

    sc_opts = parser.add_argument_group('shellcode options', description='links, assembles, and loads shellcode from various sources')
    sc_opts.add_argument('--shellcode-src', help='source from which to generate/load shellcode')
    sc_opts.add_argument('--shellcode-type', choices=['asm', 'raw', 'bin'], help='type of source for shellcode')
    sc_opts.add_argument('--print', action="store_true", help='print the loaded shellcode (requires --shellcode-src and --shellcode-type)', default=False)
    sc_opts.add_argument('--execute', action="store_true", help='execute the loaded shellcode (requires --shellcode-src and --shellcode-type)', default=False)

    crypt_opts = parser.add_argument_group('crypter options', description='encrypts and decrypts shellcode')
    crypt_opts.add_argument('--encrypt', action='store_true', help='encrypt shellcode loaded via --shellcode-src && --shellcode-type (expects public key)', default=False)
    crypt_opts.add_argument('--encfile-out', help='path to encrypted shellcode file (default: shellcode.enc)', default='shellcode.enc')
    crypt_opts.add_argument('--decrypt', action='store_true', help='decrypt shellcode loaded via --shellcode-src && --shellcode-type (expects private key)', default=False)

    args = parser.parse_args()

    shellcode: Shellcode
    keymanager: KeyManager = KeyManager(passphrase=args.passphrase)

    # keymanager options
    if args.create:
        keymanager.create_keys(key_size=args.key_size)
        keymanager.save_keys(privkey_outfile=args.privkey_out, pubkey_outfile=args.pubkey_out)
    elif args.infile:
        keymanager.load_key(key_type=args.key_type, infile=args.infile)

    # shellcode options
    if (args.shellcode_src and not args.shellcode_type) or (not args.shellcode_src and args.shellcode_type):
        parser.error(f"shellcode-src and shellcode-type must both be specified if either is used")
    elif args.shellcode_src and args.shellcode_type:
        shellcode = Shellcode(shellcode_src=args.shellcode_src)
        shellcode.load(src_type=args.shellcode_type)
        if args.print:
            shellcode.print()

    # crypter options
    if args.shellcode_src and args.shellcode_type and args.infile:
        crypter = Crypter(keymanager, shellcode)

        if args.encrypt:
            if args.key_type == 'private':
                parser.error(f"if encrypting, you must load a public key (--load-key PUBLIC_KEY && --key-type public)")
            crypter.encrypt()
            crypter.save(outfile=args.encfile_out)
        elif args.decrypt:
            if args.key_type == 'public':
                parser.error(f"if decrypting, you must load a private key (--load-key PRIVATE_KEY && --key-type private)")
            crypter.decrypt()
            crypter.save(outfile=f"{args.encfile_out}.decrypted")
            if args.execute:
                crypter.shellcode.execute()
