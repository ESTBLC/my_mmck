#include <sys/types.h>
#include <link.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "tracee/tracee.h"
#include "strace/strace.h"
#include "memtrack/memtrack.h"
#include "elf/elf.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("No file specified\n");
        return -1;
    }

    pid_t pid = start_tracee(argv[1], argv + 1);

    struct r_debug *r_debug_addr = get_r_debug_addr(pid);
    struct r_debug r_debug = get_r_debug(pid, r_debug_addr);
    printf("r_debug_tracee->r_version = %i\n", r_debug.r_version);


    memtrack(pid);

    return 0;
}
