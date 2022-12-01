include (CheckFunctionExists)

# We should rely on a picotls specific version, but as
# we expect dependancies to be built with vpp-ext-deps
# it's reasonable to make this check to avoid breaking
# existing builds when upgrading the quicly/picotls
# versions
set(EXPECTED_QUICLY_VERSION "0.1.4-vpp")


vpp_find_path(QUICLY_INCLUDE_DIR NAMES quicly.h)
vpp_find_path(PICOTLS_INCLUDE_DIR NAMES picotls.h)
vpp_find_library(PICOTLS_CORE_LIBRARY NAMES "libpicotls-core.a")
vpp_find_library(PICOTLS_OPENSSL_LIBRARY NAMES "libpicotls-openssl.a")

list (APPEND PICOTLS_LINK_LIBRARIES
    ${PICOTLS_CORE_LIBRARY}
    ${PICOTLS_OPENSSL_LIBRARY}
)

if(QUICLY_INCLUDE_DIR AND PICOTLS_INCLUDE_DIR AND PICOTLS_LINK_LIBRARIES)
  if(EXISTS "${QUICLY_INCLUDE_DIR}/quicly/version.h")
    file(STRINGS "${QUICLY_INCLUDE_DIR}/quicly/version.h" quicly_version_str REGEX "^#define[\t ]+LIBQUICLY_VERSION[\t ]+\".*\"")
    string(REGEX REPLACE "^#define[\t ]+LIBQUICLY_VERSION[\t ]+\"([^\"]*)\".*" "\\1" QUICLY_VERSION_STRING "${quicly_version_str}")
    unset(quicly_version_str)
  endif()

  if (${QUICLY_VERSION_STRING} MATCHES "${EXPECTED_QUICLY_VERSION}")
    include_directories (${PICOTLS_INCLUDE_DIR})
    add_vpp_plugin(tlspicotls
        SOURCES
        tls_picotls.c
        pico_vpp_crypto.c
        certs.c

        LINK_LIBRARIES ${PICOTLS_LINK_LIBRARIES} ${OPENSSL_LIBRARIES}
    )
    message (STATUS "Found picotls in ${PICOTLS_INCLUDE_DIR} and ${PICOTLS_CORE_LIBRARY}")
  else()
    message(STATUS "-- quicly ${EXPECTED_QUICLY_VERSION} not found - tlspicotls plugin disabled")
  endif()
else ()
    message (WARNING "-- picotls not found - tlspicotls plugin disabled")
endif ()
