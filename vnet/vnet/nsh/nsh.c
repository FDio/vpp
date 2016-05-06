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

// alagalah NSH stuff to move
typedef struct {
  nsh_header_t nsh_header;
} nsh_input_trace_t;
// alagalan end
// alagalah move to NSH folder and node 
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
// alagalah end
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


static uword unformat_nsh_map_next (unformat_input_t * input, va_list * args)
{
  u32 * result = va_arg (*args, u32 *);
  
  if (unformat (input, "drop"))
    *result = NSH_INPUT_NEXT_DROP;
  else if (unformat (input, "decap"))
    *result = NSH_INPUT_NEXT_DROP; // alagalah wrong but working this out NSH_INPUT_NEXT_NEXTPROTO_LOOKUP;
  else if (unformat (input, "map"))
    *result = NSH_INPUT_NEXT_DROP; // alagalah wrong but working this out NSH_INPUT_NEXT_REENCAP;
  else
    return 0;
  return 1;
}

static uword
nsh_input_map (vlib_main_t * vm,
               vlib_node_runtime_t * node,
               vlib_frame_t * from_frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  u32 pkts_encapsulated = 0;

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

	  next_index = next0; // alagalah todo stub
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  (void) b0 ; //alagalah stub
          

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

  vlib_node_increment_counter (vm, node->node_index,
                               0, //alagalah wrong but not sorted yet -> NSH_INPUT_ERROR_MAPPED,
                               pkts_encapsulated);

  return from_frame->n_vectors;
}



static clib_error_t *
nsh_add_del_map_command_fn (vlib_main_t * vm,
                                   unformat_input_t * input,
                                   vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, * line_input = &_line_input;
  u8 is_add = 1;
  u32 nsh_map_next = ~0 ; //alagalah TODO fix this routine
  /* Get a line of input. */
  if (! unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT) {
    if (unformat (line_input, "del"))
      is_add = 0;
    else if (unformat (line_input, "stuff %U", unformat_nsh_map_next, 
                       &nsh_map_next))
      ;
    else 
      return clib_error_return (0, "parse error: '%U'", 
                                format_unformat_error, line_input);
  }
  (void)is_add;
  (void)nsh_map_next;
  return 0;
}


VLIB_CLI_COMMAND (create_nsh_map_command, static) = {
  .path = "nsh map",
  .short_help = 
  "nsh map nsp <nn> nsi <nn>}\n"
  "    [md-type <nn>] [tlv <xx>] [del]\n",
  .function = nsh_add_del_map_command_fn,
};

int vnet_nsh_add_del_entry (vnet_nsh_add_del_entry_args_t * args)
{
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
  "nsh entry {nsp <nn> nsi <nn>}\n"
  "    c1 <nn> c2 <nn> c3 <nn> c4 <nn> \n"
  "    [md-type <nn>] [tlv <xx>] [del]\n",
  .function = nsh_add_del_entry_command_fn,
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
  
  return 0;
}

VLIB_INIT_FUNCTION(nsh_init);
