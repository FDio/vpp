cmake_minimum_required(VERSION 3.0)

set (This MemifMainTest)

set (Sources
    memif_main_test.c)

add_executable(${This} ${Sources})

target_link_libraries(${This} PUBLIC
    unity
    memif
)

add_test(
    NAME ${This}
    COMMAND ${This}
)
