#include <sys/types.h>
#include <elf.h>

#include "dyn.h"
#include "elf.h"
#include "tracee/tracee.h"

static void get_tracee_dyn(pid_t pid, void *addr, Elf64_Dyn *dyn);

void find_dyn(pid_t pid, void *dyn_addr, Elf64_Dyn *dyn, Elf64_Sxword tag)
{
    while(1) {
        get_tracee_dyn(pid, dyn_addr, dyn);
        if (dyn->d_tag == tag) {
            break;
        }

        dyn_addr += sizeof(*dyn);
    }
}

static void get_tracee_dyn(pid_t pid, void *addr, Elf64_Dyn *dyn)
{
    read_memory(pid, addr, dyn, sizeof(*dyn));
}
