add_library(strace
    strace.c
)

target_link_libraries(strace
    tracee
)
