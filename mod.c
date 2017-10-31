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

int main(void) {
	void *foo_addr = (void*)foo;
	void *bar_addr = (void*)bar;

	// Change the permissions of the page that contains foo() to read, write, and execute
	// This assumes that foo() is fully contained by a single page
	if(change_page_permissions_of_address(foo_addr) == -1) {
		fprintf(stderr, "Error while changing page permissions of foo(): %s\n", strerror(errno));
		return 1;
	}

	// Call the unmodified foo()
	printf("Calling foo...\n");
	foo();

	char call_func[] =
		"\x55"										// push   %rbp
		"\x48\x89\xe5"								// mov    %rsp,%rbp
		"\xb8\x00\x00\x00\x00" 						// mov    $0x0,%eax
		"\xe8\x00\x00\x00\x00"						// callq  (to fill later)
		"\x90"										// nop
		"\x5d"										// pop %rbp 
		"\xc3";										// retq
	// Holy shit that took me 2hours
	// We need to calculate the value that the callq will use to jump
	// To do that, we take the current address that we will be at when we reach the callq
	// Witch is foo_addr + 9 bytes of instruction before
	// And 5 more bytes for the callq instruction itself
	// And we remove it from the address of bar to get the value
	int call_off = bar_addr-(foo_addr+14);

	// We calculate the little endian 4 byte representation
	char bytes[4];
	bytes[3] = (call_off>>24)&0xFF;
	bytes[2] = (call_off>>16)&0xFF;
	bytes[1] = (call_off>>8)&0xFF;
	bytes[0] = call_off&0xFF;
	//printf("%i %x\n", call_off,call_off);
	//print_hex_memory(bytes,4);
	// Then we replace the placeholder value for the callq with it
	memcpy(call_func+10, bytes, sizeof(bytes));

	// Careful with the length of the shellcode here depending on what is after foo
	memcpy(foo_addr, call_func, sizeof(call_func)-1);

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