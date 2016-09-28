/*
	gcc -fno-omit-frame-pointer -Bdynamic -lc -ldl -lrt -lm -lpthread -lgcc_s -fstack-protector-all -Wformat -Wformat-security -Wconversion -Wsign-conversion -Wl,-z,relro,-z,now -o test_clean test_clean.c
*/

#include <stdio.h>
#include <stdlib.h>

void dummy1()
{
	printf("Hello!\n");
	return;
}

void dummy2()
{
	printf("World!\n");
	return;
}

void dummy3()
{
	printf("Goodbye!\n");
	return;
}

void recurse(int depth, int max, void* leaf_f)
{
	void (*f)();

    if (depth == max)
    {
		f = (void (*)())leaf_f;
		(void)(*f)();
    }
    else
    {
        recurse(depth + 1, max, leaf_f);
    }
}

int main(int argc, char* argv[])
{
	void (*f)();
	f = (void (*)())dummy1;
	(void)(*f)();

	recurse(0, 10, (void*)dummy2);

	dummy3();

	return 0;
}