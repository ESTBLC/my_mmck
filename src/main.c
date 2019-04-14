#include <sys/types.h>
#include <stdio.h>

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

    struct phdrs_info phdrs_info = get_pid_phdr_info(pid);

    memtrack(pid);

    return 0;
}
