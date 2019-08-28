#include <stdlib.h>

#include "allocblock.h"

static bool allocblock_contain(struct allocblock *block, void *addr);

struct allocblock *allocblock_new(void *addr, size_t len)
{
    struct allocblock *block = malloc(sizeof(*block));
    block->addr = addr;
    block->len = len;

    return block;
}

void allocblock_insert(intrlist_t *mem_tab, struct allocblock *block)
{
    intrlist_append(mem_tab, &block->list);
}

void allocblock_remove(struct allocblock *block)
{
    intrlist_remove(&block->list);
    free(block);
}

struct allocblock *allocblock_find(intrlist_t *mem_tab, void *addr)
{
    struct allocblock *block;
    intrlist_foreach(mem_tab, block, list)
    {
        if (allocblock_contain(block, addr))
            return block;
    }

    return NULL;
}

struct allocblock *allocblock_split(struct allocblock *parent, void *addr, size_t len)
{
    struct allocblock *child = allocblock_new(addr, len);

    void *end_parent = parent->addr + parent->len;
    void *end_child = child->addr + child->len;

    if (end_child < end_parent)
    {
        size_t len_end = end_parent - end_child;
        struct allocblock *tmp = allocblock_new(end_child, len_end);
        parent->len -= len_end;
        allocblock_insert(&parent->list, tmp);
    }

    allocblock_insert(&parent->list, child);

    if (parent->addr < child->addr) {
        parent->len -= len;
    } else {
        allocblock_remove(parent);
    }

    return child;
}

static bool allocblock_contain(struct allocblock *block, void *addr)
{
    return addr >= block->addr && addr <= block->addr + block->len;
}
