#include <stdlib.h>
#include <stdio.h>
#include <link.h>

#include "memtrack.h"
#include "allocator.h"
#include "syscall.h"
#include "mapblock.h"
#include "allocblock.h"
#include "strace/strace.h"
#include "tracee/tracee.h"
#include "intrlist/intrlist.h"
#include "elf/elf.h"
#include "color.h"

static void print_leaks(intrlist_t const *mem_table);

void memtrack(pid_t pid)
{
    struct r_debug dbg;
    get_tracee_r_debug(pid, &dbg);
    void *libc_dyn = find_libc(pid, dbg.r_map);
    void *mprotect_addr = find_symbol(pid, libc_dyn, "mprotect");
    printf("mprotect at %p\n", mprotect_addr);

    struct mapblock map_table;
    intrlist_init(&map_table.list);

    while(1) {
        int sig = run_tracee(pid);
        if (has_exited(sig)) {
            break;
        } else if (is_on_syscall(sig)) {
            /* struct syscall *syscall = catch_syscall(pid); */
            /* match_syscall(syscall, &map_table.list); */
            /*  */
            /* free(syscall); */
        } else if (is_on_breakpoint(sig)) {
            struct hook_info hook_info;
            get_hook_info(pid, &hook_info);
            match_libc(&hook_info, &map_table.list);
        }
    }

    print_leaks(&map_table.list);
}

static void print_leaks(intrlist_t const *mem_table)
{
    printf(RED "\n--------Memory leaks--------\n" RESET);

    struct mapblock *block;
    intrlist_foreach(mem_table, block, list)
    {
        printf(RED "Block: Addr = %p\t Size = 0x%lx\n" RESET, block->addr, block->len);
    }
}
