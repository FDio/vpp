include (CheckFunctionExists)

message(STATUS "Looking for picotls")

set(EXPECTED_QUICLY_VERSION "0.1.0-vpp")

find_path (PICOTLS_INCLUDE_DIR NAMES picotls.h)
find_library (PICOTLS_CORE_LIBRARY NAMES "libpicotls-core.a")
find_library (PICOTLS_OPENSSL_LIBRARY NAMES "libpicotls-openssl.a")

list (APPEND PICOTLS_LINK_LIBRARIES
    ${PICOTLS_CORE_LIBRARY}
    ${PICOTLS_OPENSSL_LIBRARY}
)

if (PICOTLS_INCLUDE_DIR AND PICOTLS_LINK_LIBRARIES)
    include_directories (${PICOTLS_INCLUDE_DIR})

    if (${QUICLY_VERSION_STRING} MATCHES "${EXPECTED_QUICLY_VERSION}")
        add_vpp_plugin(tlspicotls
            SOURCES
            tls_picotls.c
            pico_vpp_crypto.c
            certs.c

            LINK_LIBRARIES ${PICOTLS_LINK_LIBRARIES}
        )
        message(STATUS "Found quicly ${EXPECTED_QUICLY_VERSION} in ${QUICLY_INCLUDE_DIR}")
      else()
    message(STATUS "-- quicly ${EXPECTED_QUICLY_VERSION} not found - TLSPICOTLS plugin disabled")
      endif()
    message (STATUS "Found picotls in ${PICOTLS_INCLUDE_DIR} and ${PICOTLS_CORE_LIBRARY}")
else ()
    message (WARNING "-- picotls not found")
endif ()
