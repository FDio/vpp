add_vpp_plugin(sch_rr
    SOURCES
    sch_rr.c
    sch_rr_node.c
    ring_buffer.c

    INSTALL_HEADERS
    sch_rr.h
    ring_buffer.h
)