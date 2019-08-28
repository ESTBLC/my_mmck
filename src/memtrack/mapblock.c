#include <stdlib.h>

#include "mapblock.h"

static bool mapblock_contain(struct mapblock *block, void *addr);

struct mapblock *mapblock_new(void *addr, size_t len, int prot)
{
    struct mapblock *block = malloc(sizeof(*block));
    block->addr = addr;
    block->len = len;
    block->prot = prot;

    return block;
}

void mapblock_insert(intrlist_t *mem_tab, struct mapblock *block)
{
    intrlist_append(mem_tab, &block->list);
}

void mapblock_remove(struct mapblock *block)
{
    intrlist_remove(&block->list);
    free(block);
}

struct mapblock *mapblock_find(intrlist_t *mem_tab, void *addr)
{
    struct mapblock *block;
    intrlist_foreach(mem_tab, block, list)
    {
        if (mapblock_contain(block, addr))
            return block;
    }

    return NULL;
}

struct mapblock *mapblock_split(struct mapblock *parent, void *addr, size_t len, int prot)
{
    struct mapblock *child = mapblock_new(addr, len, prot);

    void *end_parent = parent->addr + parent->len;
    void *end_child = child->addr + child->len;
    int old_prot = parent->prot;

    if (end_child < end_parent)
    {
        size_t len_end = end_parent - end_child;
        struct mapblock *tmp = mapblock_new(end_child, len_end, old_prot);
        parent->len -= len_end;
        mapblock_insert(&parent->list, tmp);
    }

    mapblock_insert(&parent->list, child);

    if (parent->addr < child->addr) {
        parent->len -= len;
    } else {
        mapblock_remove(parent);
    }

    return child;
}

static bool mapblock_contain(struct mapblock *block, void *addr)
{
    return addr >= block->addr && addr <= block->addr + block->len;
}
