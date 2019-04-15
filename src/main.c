#include <sys/types.h>
#include <link.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#include "tracee/tracee.h"
#include "strace/strace.h"
#include "memtrack/memtrack.h"

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("No file specified\n");
        return -1;
    }

    pid_t pid = start_tracee(argv[1], argv + 1);

    memtrack(pid);

    return 0;
}
