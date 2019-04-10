#include <sys/syscall.h>
#define _DEFAULT_SOURCE
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>

#include "memtrack.h"
#include "strace/strace.h"
#include "intrlist/intrlist.h"

static void match_syscall(struct syscall const *syscall, intrlist_t *mem_table);
static void execve_func(struct syscall const *syscall);
static void mmap_func(struct syscall const *syscall, intrlist_t *mem_table);
static void mprotect_func(struct syscall const *syscall);
static void brk_func(struct syscall const *syscall);

static size_t hfunc(void *);
static bool cmpfunc(void *key1, void *key2);

void memtrack(pid_t pid)
{
    struct memblock mem_table;
    intrlist_init(&mem_table.list);
    while(1)
    {
        struct syscall const *syscall = get_next_syscall(pid);
        if (syscall == NULL)
            return;

        match_syscall(syscall, &mem_table.list);

        free((void *)syscall);
    }
}

static void match_syscall(struct syscall const *syscall, intrlist_t *mem_table)
{
    //TODO Setup test before doing anything
    switch (syscall->id)
    {
       case SYS_execve:
            execve_func(syscall);
            break;
        case SYS_fork:
            printf("fork()\n");
            break;
        case SYS_vfork:
            printf("vfork()\n");
            break;
        case SYS_clone:
            printf("clone()\n");
            break;
        case SYS_exit:
            printf("exit()\n");
            break;
        case SYS_exit_group:
            printf("exit_group()\n");
            break;
        case SYS_mmap:
            mmap_func(syscall, mem_table);
            break;
        case SYS_mremap:
            printf("mremap()\n");
            break;
        case SYS_mprotect:
            mprotect_func(syscall);
            break;
        case SYS_munmap:
            printf("munmap()\n");
            break;
        case SYS_brk:
            brk_func(syscall);
            break;
        default:
            printf("SYSCALL\n");
            return;
    }
}

static bool mmap_is_valid(int flags)
{
    return !(flags & MAP_SHARED) && flags & MAP_ANONYMOUS;
}

static void execve_func(struct syscall const *syscall)
{
    printf("execve() = 0x%lx\n", (int64_t)syscall->return_val);
}

static void mmap_func(struct syscall const *syscall, intrlist_t *mem_table)
{
    printf("mmap() = 0x%lx\n", (uint64_t)syscall->return_val);

    if (mmap_is_valid(syscall->regs_before.r10))
    {
        struct memblock *block = malloc(sizeof(*block));
        block->addr = (void *)syscall->return_val;
        block->len = syscall->regs_before.rsi;

        intrlist_append(mem_table, &block->list);

        printf("Alloc %lu bytes at %p\n", block->len, block->addr);
    }
}

static void mprotect_func(struct syscall const *syscall)
{
    printf("mprotect() = 0x%x\n", (int)syscall->return_val);
}

static void brk_func(struct syscall const *syscall)
{
    printf("brk() = 0x%lx\n", (int64_t)syscall->return_val);
}

//Htab config
static size_t hfunc(void *key)
{
    size_t hash = (size_t)key;
    hash = (~hash) + (hash << 21); // key = (key << 21) - key - 1;
    hash = hash    ^ (hash >> 24);
    hash = (hash   + (hash << 3)) + (hash << 8); // key * 265
    hash = hash    ^ (hash >> 14);
    hash = (hash   + (hash << 2)) + (hash << 4); // key * 21
    hash = hash    ^ (hash >> 28);
    hash = hash    + (hash << 31);

    return hash;
}

static bool cmpfunc(void *key1, void *key2)
{
    return key1 == key2;
}
