link_directories(
    strace/
    tracee/
    memtrack/
    intrlist/
    elf/
)

add_subdirectory(strace/)
add_subdirectory(tracee/)
add_subdirectory(memtrack/)
add_subdirectory(intrlist/)
add_subdirectory(elf/)

add_subdirectory(tests/)
