#include <stdlib.h>

int main (int argc, char *argv[])
{
    argc = 0;
    argv = NULL;

    int *i = malloc(sizeof(*i));
    free(i);
}
