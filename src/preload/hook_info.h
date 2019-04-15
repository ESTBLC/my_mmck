#ifndef HOOK_H
#define HOOK_H

#include <stdint.h>

enum hook_type {
    MALLOC,
    CALLOC,
    FREE
};

struct hook_info {
    enum hook_type type;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    uint64_t arg4;
    uint64_t return_val;
};

#endif
