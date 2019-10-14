include (CheckFunctionExists)

message(STATUS "Looking for picotls")


find_path (PICOTLS_INCLUDE_DIR NAMES picotls.h)
find_library (PICOTLS_CORE_LIBRARY NAMES "libpicotls-core.a")
find_library (PICOTLS_OPENSSL_LIBRARY NAMES "libpicotls-openssl.a")

list (APPEND PICOTLS_LINK_LIBRARIES
    ${PICOTLS_CORE_LIBRARY}
    ${PICOTLS_OPENSSL_LIBRARY}
)

if (PICOTLS_INCLUDE_DIR AND PICOTLS_LINK_LIBRARIES)
    include_directories (${PICOTLS_INCLUDE_DIR})
    add_vpp_plugin(tlspicotls
        SOURCES
        tls_picotls.c
        certs.c

        LINK_LIBRARIES ${PICOTLS_LINK_LIBRARIES}
    )
    message (STATUS "Found picotls in ${PICOTLS_INCLUDE_DIR} and ${PICOTLS_CORE_LIBRARY}")
else ()
    message (WARNING "-- picotls not found")
endif ()
