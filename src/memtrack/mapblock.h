#ifndef MEM_H
#define MEM_H

#include <sys/types.h>

#include "intrlist/intrlist.h"

struct mapblock {
    void *addr;
    size_t len;
    int prot;
    intrlist_t list;
};

struct mapblock *mapblock_new(void *addr, size_t len, int prot);
void mapblock_insert(intrlist_t *mem_tab, struct mapblock *block);
void mapblock_remove(struct mapblock *block);

struct mapblock *mapblock_find(intrlist_t *mem_tab, void *addr);
struct mapblock *mapblock_split(struct mapblock *parent, void *addr, size_t len, int prot);

#endif
