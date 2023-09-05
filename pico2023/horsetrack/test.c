#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

int main(void) {
	intptr_t *b = malloc(10);

	b[0] = (intptr_t)((long)0x7fffffffde00 ^ (long)0x555555559330 >> 12);
	printf("%p\n",b);
}
