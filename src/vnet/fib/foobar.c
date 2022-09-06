
#include <vnet/vnet.h>
#include <vnet/fib/fib_table.h>


static dpo_type_t dpo_type = DPO_FIRST;
static fib_source_t src = FIB_SOURCE_INVALID;


int *refcounts = 0;

static void
foobar_dpo_lock (dpo_id_t *dpo)
{
  refcounts[dpo->dpoi_index]++;
}

static void
foobar_dpo_unlock (dpo_id_t *dpo)
{
  refcounts[dpo->dpoi_index]--;
  ASSERT (refcounts[dpo->dpoi_index] >= 0);
}

static u8 *
format_foobar_dpo (u8 *s, va_list *va)
{
  index_t index = va_arg (*va, index_t);

  return format (s, "foobar: [index: %u]", index);
}


static const dpo_vft_t foobar_dpo_vft = {
    .dv_lock = foobar_dpo_lock,
    .dv_unlock = foobar_dpo_unlock,
    .dv_format = format_foobar_dpo,
};

const static char *const *const foobar_dpo_nodes[DPO_PROTO_NUM] = {
    [DPO_PROTO_IP4] = (const char *const[]){ "ip4-drop", 0 },
};

static fib_route_path_t *
  foobar_create_route_paths(u32 fib_index, u8 weight)
  {
        fib_route_path_t *paths = 0;
        fib_route_path_t path = {
          .frp_proto = DPO_PROTO_IP4,
          .frp_flags = FIB_ROUTE_PATH_EXCLUSIVE,
          .frp_fib_index = fib_index,
          .frp_sw_if_index = ~0,
          .frp_weight = weight,
        };
        vec_add1 (paths, path);
        return paths;
  }


static fib_prefix_t pfx = {
          .fp_len = 32,
          .fp_proto = FIB_PROTOCOL_IP4,
          .fp_addr = {
              .ip4.as_u32 = 0x01010101,
          },
      };


static clib_error_t *
foobar (vlib_main_t *vm, unformat_input_t *input,
	      vlib_cli_command_t *cmd)
{
  u32 fib_index = 0;
  fib_route_path_t *paths;
  u32 idx = ~0;
  u32 weight = 1;
  int is_add = 0;
  int is_del = 0;


  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "add %u", &idx))
	is_add = 1;
      else if (unformat (input, "del %u", &idx))
	is_del = 1;
      else if (unformat (input, "weight %u", &weight))
	;
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  vec_validate (refcounts, idx);

  if (src == FIB_SOURCE_INVALID)
   src = fib_source_allocate ("foobar", FIB_SOURCE_PRIORITY_LOW,
                                       FIB_SOURCE_BH_API);
  if (dpo_type == DPO_FIRST)
    dpo_type = dpo_register_new_type (&foobar_dpo_vft, foobar_dpo_nodes);

  paths = foobar_create_route_paths(fib_index, weight);
  dpo_set (&paths->dpo, dpo_type, DPO_PROTO_IP4, idx);

  if (is_add)
    fib_table_entry_path_add2 (fib_index, &pfx, src, FIB_ENTRY_FLAG_EXCLUSIVE, paths);
  else if (is_del)
    fib_table_entry_path_remove2 (fib_index, &pfx, src, paths);

  vec_free (paths);

  return 0;
}

VLIB_CLI_COMMAND (cmd_foobar, static) = {
  .path = "foobar",
  .short_help = "foobar",
  .function = foobar,
};
