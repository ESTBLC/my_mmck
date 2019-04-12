#ifndef MEM_H
#define MEM_H

#include <sys/types.h>

#include "intrlist/intrlist.h"

struct memblock {
    void *addr;
    size_t len;
    int prot;
    intrlist_t list;
};

struct memblock *memblock_new(void *addr, size_t len, int prot);
void memblock_insert(intrlist_t *mem_tab, struct memblock *block);
void memblock_remove(struct memblock *block);

struct memblock *memblock_find(intrlist_t *mem_tab, void *addr);
void memblock_split(struct memblock *parent, struct memblock *child);

#endif
