add_definitions(
        -D_POSIX_C_SOURCE
)

file(GLOB elf_src
        *.c
)

add_library(elf
    ${elf_src}
)
