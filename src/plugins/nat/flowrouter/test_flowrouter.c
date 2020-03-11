#include "flowrouter.h"

/* File under test */
#define UNITTEST 1

typedef struct {
  flowrouter_db_t db;
  flowrouter_config_t c;
} flowrouter_test_main_t;

flowrouter_test_main_t flowrouter_test_main;

void *
stub_vnet_feature_next_with_data (u32 * next0, vlib_buffer_t * b0,
				  u32 n_data_bytes)
{
  flowrouter_test_main_t *m = &flowrouter_test_main;
  return &m->c;
}

vlib_buffer_t b;
vlib_buffer_t *
stub_vlib_get_buffer(vlib_main_t *vm, u32 buffer_index)
{
  clib_warning("CalleD");
  return &b;
}


vlib_frame_t f;
vlib_frame_t *vlib_get_next_frame_internal (vlib_main_t * vm,
					    vlib_node_runtime_t * node,
					    u32 next_index,
					    u32 alloc_new_frame)
{
  memset(&f, 0, sizeof(f));
  clib_warning("CalleD");
  return &f;
}

#include "flowrouter.c"
vnet_feature_main_t feature_main;
static void
init (void)
{
  flowrouter_test_main_t *m = &flowrouter_test_main;

  m->db.sessions = 0;
  clib_bihash_init_16_8 (&m->db.cache,
			 "nat_slowpath_in2out",
			 1024, 128 << 20);
  m->c.db = m->db;
  m->c.punt_node = 0;
}

u32 fib_table_get_index_for_sw_if_index(fib_protocol_t proto,
					u32 sw_if_index)
{
  return 0;
}

#include <vpp/stats/stat_segment.h>
clib_error_t *
stat_segment_register_gauge (u8 *names, stat_segment_update_fn update_fn, u32 index)
{
  return 0;
}

int main (int argc, char **argv)
{
  clib_mem_init (0, 3ULL << 30);

  init();

  vlib_main_t vm;
  vlib_frame_t frame;
  memset(&vm, 0, sizeof(vm));
  memset(&frame, 0, sizeof(frame));
  frame.n_vectors = 1;
  vlib_register_node (&vm, &flowrouter_node);
  vlib_node_runtime_t * node = vlib_node_get_runtime(&vm, flowrouter_node.index);

  flowrouter (&vm, node, &frame);

  return 0;
}
