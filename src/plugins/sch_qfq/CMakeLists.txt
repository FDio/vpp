add_vpp_plugin(sch_qfq
    SOURCES
    sch_qfq.c
    sch_qfq_node.c
    ring_buffer.c

    INSTALL_HEADERS
    sch_qfq.h
    ring_buffer.h
)