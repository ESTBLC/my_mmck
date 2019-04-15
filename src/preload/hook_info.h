#ifndef HOOK_H
#define HOOK_H

enum hook_type {
    MALLOC,
    FREE
};

struct hook_info {
    enum hook_type type;
    void *addr;
};

#endif
