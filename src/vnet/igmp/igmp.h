#ifndef included_vnet_igmp_h
#define included_vnet_igmp_h

#define foreach_igmp_error                                             \
  _ (NONE, "valid packets")                                            \
  _ (UNKNOWN_TYPE, "unknown type")

typedef enum {
#define _(f,s) IGMP_ERROR_##f,
  foreach_igmp_error
#undef _
} igmp_error_t;

typedef struct {
  u8 packet_data[64];
} igmp_input_trace_t;

void ip4_igmp_register_type (vlib_main_t * vm, igmp_type_t type, u32 node_index);
void igmp_error_set_vnet_buffer (vlib_buffer_t *b, u8 type, u8 code, u32 data);

#endif /* included_vnet_igmp_h */
