cmake_minimum_required(VERSION 3.0)
project(my_mmck C)

set(CMAKE_C_COMPILER "clang")
add_compile_options(-g -Wall -Wextra -std=c99)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include_directories(src/)
add_subdirectory(src/)

file(GLOB src
        src/*.c
)

add_executable(${CMAKE_PROJECT_NAME} ${src})

target_link_libraries(${CMAKE_PROJECT_NAME}
    strace
    tracee
    memtrack
    elf
)
