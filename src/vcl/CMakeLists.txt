
##############################################################################
# vppcom shared library
##############################################################################
add_library(vppcom SHARED
  vppcom.c
  vcl_bapi.c
  vcl_cfg.c
  vcl_event.c
  vcl_private.c
)
target_link_libraries(vppcom vppinfra svm vlibmemoryclient rt pthread)
install(TARGETS vppcom DESTINATION lib)

##############################################################################
# vcl headers
##############################################################################
install_hdrs(vcl
  vcl_event.h
  vppcom.h
)

##############################################################################
# vcl tests
##############################################################################
option(VPP_BUILD_VCL_TESTS "Build vcl tests." ON)
if(VPP_BUILD_VCL_TESTS)
  set(VCL_TESTS
    vcl_test_server
    vcl_test_client
    sock_test_server
    sock_test_client
    test_vcl_listener_server
    test_vcl_listener_client
  )
  foreach(test ${VCL_TESTS})
    add_executable(${test} ${test}.c)
    target_link_libraries(${test} vppcom)
  endforeach()
endif(VPP_BUILD_VCL_TESTS)

