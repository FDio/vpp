add_vpp_plugin(sch_fq
    SOURCES
    sch_fq.c
    sch_fq_node.c
    ring_buffer.c

    INSTALL_HEADERS
    sch_fq.h
    ring_buffer.h
)