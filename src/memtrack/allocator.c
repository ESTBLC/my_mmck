#include <sys/types.h>
#include <stdio.h>

#include "allocator.h"
#include "tracee/tracee.h"
#include "preload/hook_info.h"

void match_libc(struct hook_info *info)
{
    switch (info->type)
    {
        case MALLOC:
            printf("This hook is a malloc\n");
            break;
        default:
            break;
    }
}

