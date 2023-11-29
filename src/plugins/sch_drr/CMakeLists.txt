add_vpp_plugin(sch_drr
    SOURCES
    sch_drr.c
    sch_drr_node.c
    ring_buffer.c

    INSTALL_HEADERS
    sch_drr.h
    ring_buffer.h
)