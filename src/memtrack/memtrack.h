#ifndef MEMTRACK_H
#define MEMTRACK_H

#include <sys/types.h>

#include "intrlist/intrlist.h"

struct memblock {
    void *addr;
    size_t len;
    intrlist_t list;
};

void memtrack(pid_t pid);

#endif
