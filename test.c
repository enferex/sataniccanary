#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void horribly_unsafe_function(void)
{
    int i;
    char buf[128];

    for (i=0; i<1024; ++i)
      buf[i] = 0xff;
}


int main(int argc, char **argv)
{
    horribly_unsafe_function();
    return 0;
}
