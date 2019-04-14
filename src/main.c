#include <sys/types.h>
#include <link.h>
#include <unistd.h>
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

    struct phdrs_info phdrs_info = get_pid_phdr_info(getpid());
    Elf64_Phdr *phdr = get_dynamic_phdr(&phdrs_info);
    struct r_debug *r_debug = get_r_debug(phdr, phdrs_info.phdrs);
    printf("r_debug->r_verion = %i\n", r_debug->r_version);

    memtrack(pid);

    return 0;
}
