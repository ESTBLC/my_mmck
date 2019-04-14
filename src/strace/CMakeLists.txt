add_library(strace
    strace.c
    syscall.c
)

target_link_libraries(strace
    tracee
)
