/*
 * nsh.c - nsh mapping
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>
#include <vnet/nsh/nsh.h>


typedef struct {
  nsh_header_t nsh_header;
} nsh_input_trace_t;

u8 * format_nsh_header (u8 * s, va_list * args)
{
  nsh_header_t * nsh = va_arg (*args, nsh_header_t *);

  s = format (s, "nsh ver %d ", (nsh->ver_o_c>>6));
  if (nsh->ver_o_c & NSH_O_BIT)
      s = format (s, "O-set ");

  if (nsh->ver_o_c & NSH_C_BIT)
      s = format (s, "C-set ");

  s = format (s, "len %d (%d bytes) md_type %d next_protocol %d\n",
              nsh->length, nsh->length * 4, nsh->md_type, nsh->next_protocol);
  
  s = format (s, "  service path %d service index %d\n",
              (nsh->nsp_nsi>>NSH_NSP_SHIFT) & NSH_NSP_MASK,
              nsh->nsp_nsi & NSH_NSI_MASK);

  s = format (s, "  c1 %d c2 %d c3 %d c4 %d\n",
              nsh->c1, nsh->c2, nsh->c3, nsh->c4);

  return s;
}

u8 * format_nsh_map (u8 * s, va_list * args)
{
  nsh_map_t * map = va_arg (*args, nsh_map_t *);

  s = format (s, "nsh entry nsp: %d nsi: %d ",
              (map->nsp_nsi>>NSH_NSP_SHIFT) & NSH_NSP_MASK,
              map->nsp_nsi & NSH_NSI_MASK);
  s = format (s, "maps to nsp: %d nsi: %d ",
              (map->mapped_nsp_nsi>>NSH_NSP_SHIFT) & NSH_NSP_MASK,
              map->mapped_nsp_nsi & NSH_NSI_MASK);
  
  switch (map->next_node)
    {
    case NSH_INPUT_NEXT_ENCAP_GRE:
      {
	s = format (s, "encapped by GRE intf: %d", map->sw_if_index);
	break;
      }
    case NSH_INPUT_NEXT_ENCAP_VXLANGPE:
      {
	s = format (s, "encapped by VXLAN GPE intf: %d", map->sw_if_index);
	break;
      }
    default:
      s = format (s, "only GRE and VXLANGPE support in this rev");
    }

  return s;
}


#define foreach_copy_nshhdr_field               \
_(ver_o_c)					\
_(length)					\
_(md_type)					\
_(next_protocol)				\
_(nsp_nsi)					\
_(c1)						\
_(c2)						\
_(c3)						\
_(c4)						
/* alagalah TODO - temp killing tlvs as its causing me pain */


#define foreach_32bit_field			\
_(nsp_nsi)                                      \
_(c1)                                           \
_(c2)                                           \
_(c3)                                           \
_(c4)


u8 * format_nsh_input_map_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  nsh_input_trace_t * t
      = va_arg (*args, nsh_input_trace_t *);
  // alagalah TODO : this uses a NSH formatter from GRE...
  /*s = format (s, "\n  %U", format_nsh_header_with_length, &t->h, 
              (u32) sizeof (t->h) ); */

  //alagalah TODO use the format_nsh_header_with_length from GRE
  s = format (s, "NSH-INPUT: NSPNSI %d", t->nsh_header.nsp_nsi);
  return s;
}

static uword
nsh_input_map (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  nsh_main_t * nm = &nsh_main;

  from = vlib_frame_vector_args (from_frame);
  n_left_from = from_frame->n_vectors;

  next_index = 0; // alagalah todo node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
			   to_next, n_left_to_next);

      while (0 && n_left_from >= 4 && n_left_to_next >= 2)
	{

	}

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t * b0;
	  u32 next0 = NSH_INPUT_NEXT_DROP; // alagalah WRONG but not sorted yet -> NSH_INPUT_NEXT_REENCAP;
	  uword * entry0;
	  nsh_header_t * hdr0 = 0;
	  u32 nsp_nsi0;
	  u32 error0;
	  nsh_map_t * map0 = 0;

	  next_index = next0; // alagalah todo stub
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;
	  error0 = 0;

	  b0 = vlib_get_buffer (vm, bi0);
	  hdr0 = vlib_buffer_get_current (b0);
	  nsp_nsi0 = clib_net_to_host_u32(hdr0->nsp_nsi);
	  entry0 = hash_get_mem (nm->nsh_mapping_by_key, &nsp_nsi0);

	  if (PREDICT_FALSE(entry0 == 0))
	    {
	      error0 = NSH_INPUT_ERROR_NO_MAPPING;
	      goto trace00;
	    }
	  
	  /* Entry should point to a mapping ...*/
	  map0 = pool_elt_at_index (nm->nsh_mappings, entry0[0]);

	  if (PREDICT_FALSE(map0 == 0))
	    {
	      error0 = NSH_INPUT_ERROR_NO_MAPPING;
	      goto trace00;
	    }

	  entry0 = hash_get_mem (nm->nsh_entry_by_key, &map0->mapped_nsp_nsi);

	  if (PREDICT_FALSE(entry0 == 0))
	    {
	      error0 = NSH_INPUT_ERROR_NO_MAPPING;
	      goto trace00;
	    }

	  hdr0 = pool_elt_at_index (nm->nsh_entries, entry0[0]);

	  /* set up things for next node to transmit ie which node to handle it and where */
	  next0 = map0->next_node;
	  vnet_buffer(b0)->sw_if_index[VLIB_TX] = map0->sw_if_index;

        trace00:
          b0->error = error0 ? node->errors[error0] : 0;

	  if (PREDICT_FALSE(b0->flags & VLIB_BUFFER_IS_TRACED))
	    {
	      nsh_input_trace_t *tr =
		vlib_add_trace (vm, node, b0, sizeof (*tr));
              tr->nsh_header.nsp_nsi = ~0; // alagalah todo stub
            }


	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
	  				   to_next, n_left_to_next,
	  				   bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);

    }


  return from_frame->n_vectors;
}


int vnet_nsh_add_del_map (vnet_nsh_add_del_map_args_t *a)
{
  nsh_main_t * nm = &nsh_main;
  nsh_map_t *map = 0;
  u32 key, *key_copy;
  uword * entry;
  hash_pair_t *hp;

  key = a->map.nsp_nsi;
  
  entry = hash_get_mem (nm->nsh_mapping_by_key, &key);

  if (a->is_add)
    {
      /* adding an entry, must not already exist */
      if (entry)
        return VNET_API_ERROR_INVALID_VALUE;
      
      pool_get_aligned (nm->nsh_mappings, map, CLIB_CACHE_LINE_BYTES);
      memset (map, 0, sizeof (*map));

      /* copy from arg structure */
      map->nsp_nsi = a->map.nsp_nsi;
      map->mapped_nsp_nsi = a->map.mapped_nsp_nsi;
      map->sw_if_index = a->map.sw_if_index;
      map->next_node = a->map.next_node;
      

      key_copy = clib_mem_alloc (sizeof (*key_copy));
      clib_memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (nm->nsh_mapping_by_key, key_copy,
                    map - nm->nsh_mappings);
    }
  else
    {
      if (!entry)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      map = pool_elt_at_index (nm->nsh_mappings, entry[0]);
      hp = hash_get_pair (nm->nsh_mapping_by_key, &key);
      key_copy = (void *)(hp->key);
      hash_unset_mem (nm->nsh_mapping_by_key, &key);
      clib_mem_free (key_copy);

      pool_put (nm->nsh_mappings, map);
    }

  return 0;
}

static clib_error_t *
nsh_add_del_map_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  u32 nsp, nsi, mapped_nsp, mapped_nsi;
  int nsp_set = 0, nsi_set = 0, mapped_nsp_set = 0, mapped_nsi_set = 0;
  u32 next_node = ~0;
  u32 sw_if_index = ~0; // temporary requirement to get this moved over to NSHSFC
  vnet_nsh_add_del_map_args_t _a, * a = &_a;
  int rv;

  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;
  
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "nsp %d", &nsp))
      nsp_set = 1;
    else if (unformat (line_input, "nsi %d", &nsi))
      nsi_set = 1;
    else if (unformat (line_input, "mapped-nsp %d", &mapped_nsp))
      mapped_nsp_set = 1;
    else if (unformat (line_input, "mapped-nsi %d", &mapped_nsi))
      mapped_nsi_set = 1;
    else if (unformat (line_input, "encap-gre-intf %d", &sw_if_index))
      next_node = NSH_INPUT_NEXT_ENCAP_GRE;
    else if (unformat (line_input, "encap-vxlan-gpe-intf %d", &sw_if_index))
      next_node = NSH_INPUT_NEXT_ENCAP_VXLANGPE;
    else if (unformat (line_input, "encap-none"))
      next_node = NSH_INPUT_NEXT_DROP; // Once moved to NSHSFC see nsh.h:foreach_nsh_input_next to handle this case
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }

  unformat_free (line_input);

  if (nsp_set == 0 || nsi_set == 0)
    return clib_error_return (0, "nsp nsi pair required. Key: for NSH entry");

  if (mapped_nsp_set == 0 || mapped_nsi_set == 0)
    return clib_error_return (0, "mapped-nsp mapped-nsi pair required. Key: for NSH entry");

  if (next_node == ~0)
    return clib_error_return (0, "must specific action: [encap-gre-intf <nn> | encap-vxlan-gpe-intf <nn> | encap-none]");

  memset (a, 0, sizeof (*a));

  /* set args structure */
  a->is_add = is_add;
  a->map.nsp_nsi = (nsp<< NSH_NSP_SHIFT) | nsi;
  a->map.mapped_nsp_nsi = (mapped_nsp<< NSH_NSP_SHIFT) | mapped_nsi;
  a->map.sw_if_index = sw_if_index;
  a->map.next_node = next_node;


  rv = vnet_nsh_add_del_map (a);

  switch(rv)
    {
    case 0:
      break;
    case VNET_API_ERROR_INVALID_VALUE:
      return clib_error_return (0, "mapping already exists. Remove it first.");

    case VNET_API_ERROR_NO_SUCH_ENTRY:
      return clib_error_return (0, "mapping does not exist.");

    default:
      return clib_error_return 
        (0, "vnet_nsh_add_del_map returned %d", rv);
    }
  return 0;
}


VLIB_CLI_COMMAND (create_nsh_map_command, static) = {
  .path = "nsh map",
  .short_help = 
  "nsh map nsp <nn> nsi <nn> [del] map-nsp <nn> map-nsi <nn> [encap-gre-intf <nn> | encap-vxlan-gpe-intf <nn> | encap-none]\n",
  .function = nsh_add_del_map_command_fn,
};

static clib_error_t *
show_nsh_map_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  nsh_main_t * nm = &nsh_main;
  nsh_map_t * map;

  if (pool_elts (nm->nsh_mappings) == 0)
    vlib_cli_output (vm, "No nsh maps configured.");

  pool_foreach (map, nm->nsh_mappings,
		({
		  vlib_cli_output (vm, "%U", format_nsh_map, map);
		}));

  return 0;
}

VLIB_CLI_COMMAND (show_nsh_map_command, static) = {
  .path = "show nsh map",
  .function = show_nsh_map_command_fn,
};


int vnet_nsh_add_del_entry (vnet_nsh_add_del_entry_args_t *a)
{
  nsh_main_t * nm = &nsh_main;
  nsh_header_t *hdr = 0;
  u32 key, *key_copy;
  uword * entry;
  hash_pair_t *hp;

  key = a->nsh.nsp_nsi;
  
  entry = hash_get_mem (nm->nsh_entry_by_key, &key);

  if (a->is_add)
    {
      /* adding an entry, must not already exist */
      if (entry)
        return VNET_API_ERROR_INVALID_VALUE;
      
      pool_get_aligned (nm->nsh_entries, hdr, CLIB_CACHE_LINE_BYTES);
      memset (hdr, 0, sizeof (*hdr));

      /* copy from arg structure */
#define _(x) hdr->x = a->nsh.x;
      foreach_copy_nshhdr_field;
#undef _

      key_copy = clib_mem_alloc (sizeof (*key_copy));
      clib_memcpy (key_copy, &key, sizeof (*key_copy));

      hash_set_mem (nm->nsh_entry_by_key, key_copy,
                    hdr - nm->nsh_entries);
    }
  else
    {
      if (!entry)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      hdr = pool_elt_at_index (nm->nsh_entries, entry[0]);
      hp = hash_get_pair (nm->nsh_entry_by_key, &key);
      key_copy = (void *)(hp->key);
      hash_unset_mem (nm->nsh_entry_by_key, &key);
      clib_mem_free (key_copy);

      pool_put (nm->nsh_entries, hdr);
    }

  return 0;
}


static clib_error_t *
nsh_add_del_entry_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  u8 ver_o_c = 0;
  u8 length = 0;
  u8 md_type = 0;
  u8 next_protocol = 1; /* default: ip4 */
  u32 nsp;
  u8 nsp_set = 0;
  u32 nsi;
  u8 nsi_set = 0;
  u32 nsp_nsi;
  u32 c1 = 0;
  u32 c2 = 0;
  u32 c3 = 0;
  u32 c4 = 0;
  u32 *tlvs = 0;
  u32 tmp;
  int rv;
  vnet_nsh_add_del_entry_args_t _a, * a = &_a;
  
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "version %d", &tmp))
      ver_o_c |= (tmp & 3) << 6;
    else if (unformat (line_input, "o-bit %d", &tmp))
      ver_o_c |= (tmp & 1) << 5;
    else if (unformat (line_input, "c-bit %d", &tmp))
      ver_o_c |= (tmp & 1) << 4;
    else if (unformat (line_input, "md-type %d", &tmp))
      md_type = tmp;
    else if (unformat(line_input, "next-ip4"))
      next_protocol = 1;
    else if (unformat(line_input, "next-ip6"))
      next_protocol = 2;
    else if (unformat(line_input, "next-ethernet"))
      next_protocol = 3;
    else if (unformat (line_input, "c1 %d", &c1))
      ;
    else if (unformat (line_input, "c2 %d", &c2))
      ;
    else if (unformat (line_input, "c3 %d", &c3))
      ;
    else if (unformat (line_input, "c4 %d", &c4))
      ;
    else if (unformat (line_input, "nsp %d", &nsp))
      nsp_set = 1;
    else if (unformat (line_input, "nsi %d", &nsi))
      nsi_set = 1;
    else if (unformat (line_input, "tlv %x"))
        vec_add1 (tlvs, tmp);
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }

  unformat_free (line_input);

  if (nsp_set == 0)
    return clib_error_return (0, "nsp not specified");
  
  if (nsi_set == 0)
    return clib_error_return (0, "nsi not specified");

  nsp_nsi = (nsp<<8) | nsi;
  
  memset (a, 0, sizeof (*a));

  a->is_add = is_add;

#define _(x) a->nsh.x = x;
  foreach_copy_nshhdr_field;
#undef _
  
  a->nsh.tlvs[0] = 0 ; // alagalah TODO FIX ME this shouldn't be set 0

  rv = vnet_nsh_add_del_entry (a);

  switch(rv)
    {
    case 0:
      break;
    default:
      return clib_error_return 
        (0, "vnet_nsh_add_del_entry returned %d", rv);
    }

  return 0;
}

VLIB_CLI_COMMAND (create_nsh_entry_command, static) = {
  .path = "nsh entry",
  .short_help = 
  "nsh entry {nsp <nn> nsi <nn>} c1 <nn> c2 <nn> c3 <nn> c4 <nn>"
  " [md-type <nn>] [tlv <xx>] [del]\n",
  .function = nsh_add_del_entry_command_fn,
};

static clib_error_t *
show_nsh_entry_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  nsh_main_t * nm = &nsh_main;
  nsh_header_t * hdr;

  if (pool_elts (nm->nsh_entries) == 0)
    vlib_cli_output (vm, "No nsh entries configured.");

  pool_foreach (hdr, nm->nsh_entries,
		({
		  vlib_cli_output (vm, "%U", format_nsh_header, hdr);
		}));

  return 0;
}

VLIB_CLI_COMMAND (show_nsh_entry_command, static) = {
  .path = "show nsh entry",
  .function = show_nsh_entry_command_fn,
};

static char * nsh_input_error_strings[] = {
#define _(sym,string) string,
  foreach_nsh_input_error
#undef _
};

VLIB_REGISTER_NODE (nsh_input_node) = {
  .function = nsh_input_map,
  .name = "nsh-input",
  .vector_size = sizeof (u32),
  .format_trace = format_nsh_input_map_trace,
  /* alagalah todo .format_buffer = format_nsh_header_with_lenth */
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(nsh_input_error_strings),
  .error_strings = nsh_input_error_strings,

  .n_next_nodes = NSH_INPUT_N_NEXT,

  .next_nodes = {
#define _(s,n) [NSH_INPUT_NEXT_##s] = n,
    foreach_nsh_input_next
#undef _
  },
};

clib_error_t *nsh_init (vlib_main_t *vm)
{
  nsh_main_t *nm = &nsh_main;
  
  nm->vnet_main = vnet_get_main();
  nm->vlib_main = vm;
  
  nm->nsh_mapping_by_key
    = hash_create_mem (0, sizeof(u32), sizeof (uword));

  nm->nsh_mapping_by_mapped_key
    = hash_create_mem (0, sizeof(u32), sizeof (uword));

  nm->nsh_entry_by_key
    = hash_create_mem (0, sizeof(u32), sizeof (uword));

  return 0;
}

VLIB_INIT_FUNCTION(nsh_init);
