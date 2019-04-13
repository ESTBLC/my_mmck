#include <sys/syscall.h>
#define _DEFAULT_SOURCE
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>

#include "memtrack.h"
#include "mem.h"
#include "strace/strace.h"
#include "intrlist/intrlist.h"

static void match_syscall(struct syscall const *syscall, intrlist_t *mem_table);
static void execve_func(struct syscall const *syscall);
static void mmap_func(struct syscall const *syscall, intrlist_t *mem_table);
static void munmap_func(struct syscall const *syscall, intrlist_t *mem_table);
static void mprotect_func(struct syscall const *syscall, intrlist_t *mem_table);
static void brk_func(struct syscall const *syscall);

static bool mmap_is_valid(int flags);
static bool munmap_is_valid(int return_val);
static void print_mem_table(intrlist_t const *mem_table);

void memtrack(pid_t pid)
{
    struct memblock mem_table;
    intrlist_init(&mem_table.list);
    while(1)
    {
        struct syscall const *syscall = get_next_syscall(pid);
        if (syscall == NULL)
            break;

        match_syscall(syscall, &mem_table.list);

        free((void *)syscall);
    }

    print_mem_table(&mem_table.list);
}

static void match_syscall(struct syscall const *syscall, intrlist_t *mem_table)
{
    //TODO Setup test before doing anything
    switch (syscall->id)
    {
       case SYS_execve:
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
            mprotect_func(syscall, mem_table);
            break;
        case SYS_munmap:
            munmap_func(syscall, mem_table);
            break;
        case SYS_brk:
            brk_func(syscall);
            break;
        default:
            return;
    }
}

static bool mmap_is_valid(int flags)
{
    return !(flags & MAP_SHARED) && !(flags & MAP_ANONYMOUS);
}

static bool munmap_is_valid(int return_val)
{
    return return_val == 0;
}

static void execve_func(struct syscall const *syscall)
{
    printf("execve() = 0x%lx\n", (int64_t)syscall->return_val);
}

static void mmap_func(struct syscall const *syscall, intrlist_t *mem_table)
{
    if (!mmap_is_valid(syscall->regs_before.r10))
        return;

    void *addr = (void *)syscall->return_val;
    size_t len = syscall->regs_before.rsi;
    int prot = syscall->regs_before.rdx;

    struct memblock *block = memblock_new(addr, len, prot);
    memblock_insert(mem_table, block);

    printf("mmap { addr = %p, len = 0x%lx, prot = %i }\n", addr, len, prot);
}

static void munmap_func(struct syscall const *syscall, intrlist_t *mem_table)
{
    if (!munmap_is_valid(syscall->return_val))
        return;

    void *addr = (void *)syscall->regs_before.rdi;
    size_t len = syscall->regs_before.rsi;

    struct memblock *block = memblock_find(mem_table, addr);
    if (block != NULL)
    {
        block = memblock_split(block, addr, len);

        printf("munmap { addr = %p, len = 0x%lx, prot = %i }\n", addr, len, block->prot);

        memblock_remove(block);

        return;
    }

    printf("!!!!!!!!munmap: No block found for addr %p!!!!!!!!\n", addr);
}

static void mprotect_func(struct syscall const *syscall, intrlist_t *mem_table)
{
    void *addr = (void *)syscall->regs_before.rdi;
    size_t len = syscall->regs_before.rsi;
    int prot = syscall->regs_before.rdx;

    struct memblock *block = memblock_find(mem_table, addr);
    if (block != NULL)
    {
        block = memblock_split(block, addr, len);

        block->prot = prot;

        printf("mprotect { addr = %p, len = 0x%lx, prot = %i }\n", addr, len, prot);

        return;
    }

    printf("!!!!!!!!mprotect: No block found for addr %p!!!!!!!!\n", addr);
}

static void brk_func(struct syscall const *syscall)
{
    printf("brk() = 0x%lx\n", (int64_t)syscall->return_val);
}

static void print_mem_table(intrlist_t const *mem_table)
{
    printf("\n--------Memory table--------\n");

    struct memblock *block;
    intrlist_foreach(mem_table, block, list)
    {
        printf("Block: Addr = %p\t Size = 0x%lx\t\t Prot = %i\n", block->addr, block->len, block->prot);
    }
}
