#include <sys/types.h>
#include <stdio.h>

#include "allocator.h"
#include "tracee/tracee.h"
#include "preload/hook_info.h"
#include "intrlist/intrlist.h"

void match_libc(struct hook_info *info, intrlist_t *mem_table)
{
    switch (info->type)
    {
        case MALLOC:
            printf("This hook is a malloc\n");
            break;
        case FREE:
            printf("This hook is a free\n");
            break;
        default:
            break;
    }
}

