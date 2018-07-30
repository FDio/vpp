

set(SVM_SRCS
  svm.c
  ssvm.c
  svm_fifo.c
  svm_fifo_segment.c
  queue.c
  message_queue.c
)

add_library(svm SHARED ${SVM_SRCS})
target_link_libraries(svm vppinfra rt)
install(TARGETS svm DESTINATION lib)

