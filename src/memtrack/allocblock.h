#ifndef MEM_H
#define MEM_H

#include <sys/types.h>

#include "intrlist/intrlist.h"

struct allocblock {
    void *addr;
    size_t len;
    intrlist_t list;
};

struct allocblock *allocblock_new(void *addr, size_t len);
void allocblock_insert(intrlist_t *mem_tab, struct allocblock *block);
void allocblock_remove(struct allocblock *block);

struct allocblock *allocblock_find(intrlist_t *mem_tab, void *addr);
struct allocblock *allocblock_split(struct allocblock *parent, void *addr, size_t len);

#endif
