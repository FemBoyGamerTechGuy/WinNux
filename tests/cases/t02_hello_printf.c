/* t02: printf family through msvcrt builtin. */
#include <stdio.h>
#include <string.h>
int main(void)
{
    printf("T02 printf %d %s %c %x\n", 42, "str", 'X', 0xBE);
    char buf[128];
    sprintf(buf, "T02 sprintf %05d|%-6s|%p-ish\n", 123, "ab", (void*)0x1000);
    fputs(buf, stdout);
    fprintf(stderr, "T02 fprintf stderr ok\n");
    return 0;
}
