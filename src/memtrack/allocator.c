#include <sys/types.h>
#include <stdio.h>

#include "allocator.h"
#include "mem.h"
#include "tracee/tracee.h"
#include "preload/hook_info.h"
#include "intrlist/intrlist.h"

static void malloc_func(struct hook_info const *info, intrlist_t *mem_table);
static void calloc_func(struct hook_info const *info, intrlist_t *mem_table);
static void free_func(struct hook_info const *info, intrlist_t *mem_table);

void match_libc(struct hook_info *info, intrlist_t *mem_table)
{
    switch (info->type)
    {
        case MALLOC:
            malloc_func(info, mem_table);
            break;
        case CALLOC:
            calloc_func(info, mem_table);
            break;
        case FREE:
            free_func(info, mem_table);
            break;
        default:
            break;
    }
}

static void malloc_func(struct hook_info const *info, intrlist_t *mem_table)
{
    void *addr = (void *)info->return_val;
    size_t len = info->arg1;

    struct memblock *block = memblock_find(mem_table, addr);
    if (block != NULL) {
        block = memblock_split(block, addr, len);

        printf("malloc { addr = %p, len = 0x%lx }\n", addr, len);

        return;
    }

    printf("!!!!!!!!Malloc no block at addr = %p for size = 0x%lx\n", addr, len);
}

static void calloc_func(struct hook_info const *info, intrlist_t *mem_table)
{
    void *addr = (void *)info->return_val;
    size_t len = info->arg1 * info->arg2;

    struct memblock *block = memblock_find(mem_table, addr);
    if (block != NULL) {
        block = memblock_split(block, addr, len);

        printf("calloc { addr = %p, len = 0x%lx }\n", addr, len);

        return;
    }

    printf("!!!!!!!!Calloc no block at addr = %p for size = 0x%lx\n", addr, len);
}

static void free_func(struct hook_info const *info, intrlist_t *mem_table)
{
    void *addr = (void *)info->arg1;

    struct memblock *block = memblock_find(mem_table, addr);
    if (block != NULL) {
        printf("free { addr = %p, len = 0x%lx }\n", addr, block->len);

        memblock_remove(block);

        return;
    }

    printf("!!!!!!!!Free non malloced pointer!!!!!!!!\n");
}
