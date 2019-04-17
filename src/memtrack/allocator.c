#include <sys/types.h>
#include <stdio.h>

#include "allocator.h"
#include "mem.h"
#include "tracee/tracee.h"
#include "preload/hook_info.h"
#include "intrlist/intrlist.h"

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

static void malloc_func(struct hook_info const *info, intrlist_t *mem_table);
static void calloc_func(struct hook_info const *info, intrlist_t *mem_table);
static void realloc_func(struct hook_info const *info, intrlist_t *mem_table);
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
        case REALLOC:
            realloc_func(info, mem_table);
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
    size_t size = info->arg1;

    struct memblock *block = memblock_new(addr, size);
    memblock_insert(mem_table, block);

    printf("malloc { addr = %p, size = 0x%lx }\n", addr, size);
}

static void calloc_func(struct hook_info const *info, intrlist_t *mem_table)
{
    void *addr = (void *)info->return_val;
    size_t size = info->arg1 * info->arg2;

    struct memblock *block = memblock_new(addr, size);
    memblock_insert(mem_table, block);

    printf("calloc { addr = %p, size = 0x%lx }\n", addr, size);
}

static void realloc_func(struct hook_info const *info, intrlist_t *mem_table)
{
    void *addr = (void *)info->return_val;
    void *ptr = (void *)info->arg1;
    size_t size = info->arg2;

    if (ptr == NULL) {
        printf(RED "!!!!!!!!Reallocte NULL addr!!!!!!!!\n" RESET);
        return;
    }

    struct memblock *block = memblock_find(mem_table, ptr);
    block->addr = addr;

    printf("realloc { new_addr = %p, old_addr = %p, size = 0x%lx }\n", addr, ptr, size);
}

static void free_func(struct hook_info const *info, intrlist_t *mem_table)
{
    void *addr = (void *)info->arg1;

    if(addr != NULL) {
        struct memblock *block = memblock_find(mem_table, addr);
        if (block != NULL) {
            printf("free { addr = %p, size = 0x%lx }\n", addr, block->len);

            memblock_remove(block);

            return;
        }

        printf(RED "!!!!!!!!Free non malloced pointer!!!!!!!!\n" RESET);

    } else {
        printf(RED "!!!!!!!!Free NULL pointer!!!!!!!!\n" RESET);
    }
}
