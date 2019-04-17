#include <stdlib.h>
#include <stdio.h>

#include "memtrack.h"
/* #include "syscall.h" */
#include "allocator.h"
#include "mem.h"
#include "strace/strace.h"
#include "tracee/tracee.h"
#include "intrlist/intrlist.h"

static void print_mem_table(intrlist_t const *mem_table);

void memtrack(pid_t pid)
{
    single_step_tracee(pid);

    struct memblock mem_table;
    intrlist_init(&mem_table.list);
    while(1)
    {
        int sig = run_tracee(pid);
        if (has_exited(sig)) {
            break;
        } else if (is_on_syscall(sig)) {
            struct syscall *syscall = catch_syscall(pid);
            /* match_syscall(syscall, &mem_table.list); */

            free(syscall);
        } else if (is_on_breakpoint(sig)) {
            struct hook_info hook_info;
            get_hook_info(pid, &hook_info);
            match_libc(&hook_info, &mem_table.list);
        }
    }

    print_mem_table(&mem_table.list);
}

static void print_mem_table(intrlist_t const *mem_table)
{
    printf("\n--------Memory table--------\n");

    struct memblock *block;
    intrlist_foreach(mem_table, block, list)
    {
        printf("Block: Addr = %p\t Size = 0x%lx\n", block->addr, block->len);
    }
}
