#include <stdlib.h>

#include "mem.h"

static bool memblock_contain(struct memblock *block, void *addr);

struct memblock *memblock_new(void *addr, size_t len)
{
    struct memblock *block = malloc(sizeof(*block));
    block->addr = addr;
    block->len = len;

    return block;
}

void memblock_insert(intrlist_t *mem_tab, struct memblock *block)
{
    intrlist_append(mem_tab, &block->list);
}

void memblock_remove(struct memblock *block)
{
    intrlist_remove(&block->list);
    free(block);
}

struct memblock *memblock_find(intrlist_t *mem_tab, void *addr)
{
    struct memblock *block;
    intrlist_foreach(mem_tab, block, list)
    {
        if (memblock_contain(block, addr))
            return block;
    }

    return NULL;
}

struct memblock *memblock_split(struct memblock *parent, void *addr, size_t len)
{
    struct memblock *child = memblock_new(addr, len);

    void *end_parent = parent->addr + parent->len;
    void *end_child = child->addr + child->len;

    if (end_child < end_parent)
    {
        size_t len_end = end_parent - end_child;
        struct memblock *tmp = memblock_new(end_child, len_end);
        parent->len -= len_end;
        memblock_insert(&parent->list, tmp);
    }

    memblock_insert(&parent->list, child);

    if (parent->addr < child->addr) {
        parent->len -= len;
    } else {
        memblock_remove(parent);
    }

    return child;
}

static bool memblock_contain(struct memblock *block, void *addr)
{
    return addr >= block->addr && addr <= block->addr + block->len;
}
