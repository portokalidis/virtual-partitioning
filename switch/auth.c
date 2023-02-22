#include <stdio.h>

int name()
{
	printf("auth func returns 2\n");
	return 2;
}

int main()
{
	printf("main\n");
	name();
}
