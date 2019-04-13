link_directories(
    strace/
    memtrack/
    intrlist/
    elf/
)

add_subdirectory(strace/)
add_subdirectory(memtrack/)
add_subdirectory(intrlist/)
add_subdirectory(elf/)

add_subdirectory(tests/)
