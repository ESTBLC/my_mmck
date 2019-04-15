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
    block = memblock_split(block, addr, len);

    printf("malloc { addr = %p, len = %lx }\n", addr, len);
}

static void calloc_func(struct hook_info const *info, intrlist_t *mem_table)
{
    void *addr = (void *)info->return_val;
    size_t nmemb = info->arg1;
    size_t size = info->arg2;

    struct memblock *block = memblock_find(mem_table, addr);
    block = memblock_split(block, addr, nmemb * size);

    printf("malloc { addr = %p, nmemb = %lx, size = %lx }\n", addr, nmemb, size);
}

static void free_func(struct hook_info const *info, intrlist_t *mem_table)
{
    void *addr = (void *)info->arg1;

    struct memblock *block = memblock_find(mem_table, addr);

    printf("free { addr = %p, len = %lx }\n", addr, block->len);

    memblock_remove(block);
}
