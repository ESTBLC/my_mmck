#include <errno.h>
#include <string.h>

#include "error.h"

char *get_error_str()
{
    return strerror(errno);
}
