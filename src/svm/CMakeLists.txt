
##############################################################################
# svm shared library
##############################################################################
add_library(svm SHARED
  svm.c
  ssvm.c
  svm_fifo.c
  svm_fifo_segment.c
  queue.c
  message_queue.c
)
target_link_libraries(svm vppinfra rt pthread)
install(TARGETS svm DESTINATION lib)

##############################################################################
# svmdb shared library
##############################################################################
add_library(svmdb SHARED svmdb.c)
target_link_libraries(svmdb svm vppinfra rt pthread)
install(TARGETS svmdb DESTINATION lib)

##############################################################################
# svm headers
##############################################################################
install_hdrs(svm
  ssvm.h
  svm_common.h
  svmdb.h
  svm_fifo.h
  svm_fifo_segment.h
  queue.h
  message_queue.h
  svm.h
)

##############################################################################
# svm tools
##############################################################################

add_executable (svmtool svmtool.c)
target_link_libraries (svmtool vppinfra svm)
add_executable (svmdbtool svmdbtool.c)
target_link_libraries (svmdbtool vppinfra svm svmdb)

install(
  TARGETS svmtool svmdbtool
  DESTINATION bin
)

