#include <stdlib.h>

int main()
{
    int *data = malloc(sizeof(*data));
    free(data);
}
