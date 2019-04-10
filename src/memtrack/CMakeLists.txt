add_library(memtrack
    memtrack.c
)

target_link_libraries(memtrack
    strace
)
