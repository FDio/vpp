cmake_minimum_required(VERSION 3.0)

set (This MemifSocketTest)

set (Sources
    memif_socket_test.c)

add_executable(${This} ${Sources})

target_link_libraries(${This} PUBLIC
    unity
    memif
)

add_test(
    NAME ${This}
    COMMAND ${This}
)
