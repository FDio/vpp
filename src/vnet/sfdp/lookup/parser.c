#include <vnet/sfdp/sfdp.h>
#include <vnet/sfdp/lookup/lookup_inlines.h>
#include <vnet/sfdp/lookup/parser.h>
#include <vnet/sfdp/lookup/parser_inlines.h>
static uword
sfdp_create_parser (sfdp_parser_main_t *pm,
		    sfdp_parser_registration_mutable_t *reg)
{
  sfdp_parser_bihash_registration_t vft =
    sfdp_parser_bihash_regs[reg->key_size];
  sfdp_parser_data_t parser = { 0 };
  void **key_ptd, **kv_ptd;
  uword pi = vec_len (pm->parsers);
  parser.bihash_table =
    clib_mem_alloc_aligned (vft.table_size, CLIB_CACHE_LINE_BYTES);
  clib_memset (parser.bihash_table, 0, vft.table_size);
  vft.sfdp_parser_bihash_init_fn (parser.bihash_table, reg->name,
				  sfdp_ip4_num_buckets (),
				  sfdp_ip4_mem_size ());
  vec_validate (parser.keys_ptd, vlib_num_workers ());
  vec_validate (parser.kv_ptd, vlib_num_workers ());
  vec_foreach (key_ptd, parser.keys_ptd)
    key_ptd[0] = clib_mem_alloc_aligned (reg->key_size * VLIB_FRAME_SIZE,
					 CLIB_CACHE_LINE_BYTES);
  vec_foreach (kv_ptd, parser.kv_ptd)
    kv_ptd[0] =
      clib_mem_alloc_aligned (reg->key_size + 8, CLIB_CACHE_LINE_BYTES);

  parser.key_size = reg->key_size;
  parser.name = reg->name;
  parser.format_fn = reg->format_fn;
  parser.normalize_key_fn = reg->normalize_key_fn;
  vec_add1 (pm->parsers, parser);
  return pi;
}

static clib_error_t *
sfdp_parser_init (vlib_main_t *vm)
{
  sfdp_parser_main_t *pm = &sfdp_parser_main;
  sfdp_parser_registration_mutable_t *current_reg = pm->regs;
  vlib_call_init_function (vm, sfdp_init);
  uword pi;

  while (current_reg)
    {
      pi = sfdp_create_parser (pm, current_reg);
      current_reg->sfdp_parser_data_index = pi;
      current_reg = current_reg->next;
    }
  return 0;
}

#ifndef CLIB_MARCH_VARIANT
sfdp_parser_main_t sfdp_parser_main;
#endif

VLIB_INIT_FUNCTION (sfdp_parser_init);