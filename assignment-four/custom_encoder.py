import sys
import argparse
import textwrap
from pathlib import Path


def rolling_xor(shellcode: bytes, decode=False, **kwargs) -> bytes:
    """ Perform a rolling xor encoding scheme on `shellcode`.

    :param shellcode: bytes object; data to be [en,de]coded
    :param decode: boolean, decrypt previously xor'd data
    :return: bytes object
    """
    shellcode = bytearray(shellcode)

    if decode:
        shellcode.reverse()
        encoded_payload = bytearray()

        for i, byte in enumerate(shellcode):
            if i == len(shellcode) - 1:
                encoded_payload.append(shellcode[i])  # last byte doesn't need xor'd
            else:
                encoded_payload.append(shellcode[i] ^ shellcode[i + 1])

        encoded_payload.reverse()
    else:
        encoded_payload = bytearray([shellcode.pop(0)])  # first byte left as is in the ciphertext

        for i, byte in enumerate(shellcode):
            encoded_payload.append(byte ^ encoded_payload[i])

    return bytes(encoded_payload)


def print_assembly(shellcode: bytes, outfile: str, **kwargs) -> None:
    """ Print a complete decoder stub with shellcode ready for assembly and linking.

    :param shellcode: bytes object; used as shellcode in the assembly generated
    :param outfile: where to write the generated assemly, default: stdout
    :return: None
    """
    template = f"""\
    global _start

    section .text
    _start:
        jmp short get_address       ; jmp-call-pop for shellcode address
    
    decoder:
        pop rdi                     ; address to encoded_shellcode
        push {len(shellcode) - 1}    
        pop rcx                     ; rolling-xor requires one less xor instruction 
        xor eax, eax                ; than the length of the shellcode
    
    decode:
        mov eax, [rdi + rcx - 1]    ; first byte in xor (earlier of the two)
        xor byte [rdi + rcx], al    ; xor the byte above with the one that directly follows 
        loop decode                 ; the decoder works backwards 
    
    jmp short encoded_shellcode     ; do the thing
    
    get_address:
        call decoder
        encoded_shellcode: db {','.join(hex(x) for x in shellcode)}
    """

    if not outfile:
        outfile = sys.stdout
    else:
        outfile = open(outfile, 'w')

    print(textwrap.dedent(template), file=outfile)

    outfile.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', dest='infile', help='file to encode, expects filetype of data i.e. msfvenom ... -f raw', required=True)
    parser.add_argument('-o', dest='outfile', help='write assembly to file (default: STDOUT)')
    parser.add_argument('-d', dest='decode', default=False, action='store_true', help='Decode what is passed via -f or -s')

    args = parser.parse_args()

    shellcode = Path(args.infile).read_bytes()

    encoded_payload = rolling_xor(shellcode, args.decode)

    print_assembly(encoded_payload, args.outfile)

