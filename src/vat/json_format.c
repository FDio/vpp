/*
 *------------------------------------------------------------------
 * json_format.c
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------

*/
#include <inttypes.h>
#include <vat/json_format.h>
#include <vnet/ip/ip.h>
#include <vppinfra/vec.h>

#define VAT_TAB_WIDTH               2

typedef struct vat_print_ctx_s
{
  FILE *ofp;
  u32 indent;
} vat_print_ctx_t;

/* Format an IP4 address. */
static u8 *
vat_json_format_ip4_address (u8 * s, va_list * args)
{
  u8 *a = va_arg (*args, u8 *);
  return format (s, "%d.%d.%d.%d", a[0], a[1], a[2], a[3]);
}

/* Format an IP6 address. */
static u8 *
vat_json_format_ip6_address (u8 * s, va_list * args)
{
  ip6_address_t *a = va_arg (*args, ip6_address_t *);
  u32 i, i_max_n_zero, max_n_zeros, i_first_zero, n_zeros, last_double_colon;

  i_max_n_zero = ARRAY_LEN (a->as_u16);
  max_n_zeros = 0;
  i_first_zero = i_max_n_zero;
  n_zeros = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      u32 is_zero = a->as_u16[i] == 0;
      if (is_zero && i_first_zero >= ARRAY_LEN (a->as_u16))
	{
	  i_first_zero = i;
	  n_zeros = 0;
	}
      n_zeros += is_zero;
      if ((!is_zero && n_zeros > max_n_zeros)
	  || (i + 1 >= ARRAY_LEN (a->as_u16) && n_zeros > max_n_zeros))
	{
	  i_max_n_zero = i_first_zero;
	  max_n_zeros = n_zeros;
	  i_first_zero = ARRAY_LEN (a->as_u16);
	  n_zeros = 0;
	}
    }

  last_double_colon = 0;
  for (i = 0; i < ARRAY_LEN (a->as_u16); i++)
    {
      if (i == i_max_n_zero && max_n_zeros > 1)
	{
	  s = format (s, "::");
	  i += max_n_zeros - 1;
	  last_double_colon = 1;
	}
      else
	{
	  s = format (s, "%s%x",
		      (last_double_colon || i == 0) ? "" : ":",
		      clib_net_to_host_u16 (a->as_u16[i]));
	  last_double_colon = 0;
	}
    }

  return s;
}

static void
vat_json_indent_print (vat_print_ctx_t * ctx)
{
  int i;
  for (i = 0; i < ctx->indent * VAT_TAB_WIDTH; i++)
    {
      fformat (ctx->ofp, " ");
    }
}

static void
vat_json_indent_line (vat_print_ctx_t * ctx, char *fmt, ...)
{
  va_list va;

  vat_json_indent_print (ctx);
  va_start (va, fmt);
  va_fformat (ctx->ofp, fmt, &va);
  va_end (va);
}

static u8
is_num_only (vat_json_node_t * p)
{
  vat_json_node_t *elem;
  vec_foreach (elem, p)
  {
    if (VAT_JSON_INT != elem->type && VAT_JSON_UINT != elem->type)
      {
	return 0;
      }
  }
  return 1;
}

static void
vat_json_print_internal (vat_print_ctx_t * ctx, vat_json_node_t * node)
{
#define P(fmt,...) fformat(ctx->ofp, fmt, ##__VA_ARGS__)
#define PL(fmt,...) fformat(ctx->ofp, fmt"\n", ##__VA_ARGS__)
#define PPL(fmt,...) vat_json_indent_line(ctx, fmt"\n", ##__VA_ARGS__)
#define PP(fmt,...) vat_json_indent_line(ctx, fmt, ##__VA_ARGS__)
#define INCR (ctx->indent++)
#define DECR (ctx->indent--)

  vat_json_pair_t *pair;
  u32 i, count;
  vat_json_node_t *elem;
  u8 num_only = 0;

  if (!node)
    {
      return;
    }

  switch (node->type)
    {
    case VAT_JSON_OBJECT:
      count = vec_len (node->pairs);
      if (count >= 1)
	{
	  PL ("{");
	  INCR;
	  for (i = 0; i < count; i++)
	    {
	      pair = &node->pairs[i];
	      PP ("\"%s\": ", pair->name);
	      vat_json_print_internal (ctx, &pair->value);
	      if (i < count - 1)
		{
		  P (",");
		}
	      PL ();
	    }
	  DECR;
	  PP ("}");
	}
      else
	{
	  P ("{}");
	}
      break;
    case VAT_JSON_ARRAY:
      num_only = is_num_only (node->array);
      count = vec_len (node->array);
      if (count >= 1)
	{
	  if (num_only)
	    P ("[");
	  else
	    PL ("[ ");
	  INCR;
	  for (i = 0; i < count; i++)
	    {
	      elem = &node->array[i];
	      if (!num_only)
		{
		  vat_json_indent_print (ctx);
		}
	      vat_json_print_internal (ctx, elem);
	      if (i < count - 1)
		{
		  if (num_only)
		    {
		      P (", ");
		    }
		  else
		    {
		      P (",");
		    }
		}
	      if (!num_only)
		PL ();
	    }
	  DECR;
	  if (!num_only)
	    PP ("]");
	  else
	    P ("]");
	}
      else
	{
	  P ("[]");
	}
      break;
    case VAT_JSON_INT:
      P ("%d", node->sint);
      break;
    case VAT_JSON_UINT:
      P ("%" PRIu64, node->uint);
      break;
    case VAT_JSON_REAL:
      P ("%f", node->real);
      break;
    case VAT_JSON_STRING:
      P ("\"%s\"", node->string);
      break;
    case VAT_JSON_IPV4:
      P ("\"%U\"", vat_json_format_ip4_address, &node->ip4);
      break;
    case VAT_JSON_IPV6:
      P ("\"%U\"", vat_json_format_ip6_address, &node->ip6);
      break;
    default:
      break;
    }
#undef PPL
#undef PP
#undef PL
#undef P
}

void
vat_json_print (FILE * ofp, vat_json_node_t * node)
{
  vat_print_ctx_t ctx;
  clib_memset (&ctx, 0, sizeof ctx);
  ctx.indent = 0;
  ctx.ofp = ofp;
  fformat (ofp, "\n");
  vat_json_print_internal (&ctx, node);
  fformat (ofp, "\n");
}

void
vat_json_free (vat_json_node_t * node)
{
  int i = 0;

  if (NULL == node)
    {
      return;
    }
  switch (node->type)
    {
    case VAT_JSON_OBJECT:
      for (i = 0; i < vec_len (node->pairs); i++)
	{
	  vat_json_free (&node->pairs[i].value);
	}
      if (NULL != node->pairs)
	{
	  vec_free (node->pairs);
	}
      break;
    case VAT_JSON_ARRAY:
      for (i = 0; i < vec_len (node->array); i++)
	{
	  vat_json_free (&node->array[i]);
	}
      if (NULL != node->array)
	{
	  vec_free (node->array);
	}
      break;
    case VAT_JSON_STRING:
      if (NULL != node->string)
	{
	  vec_free (node->string);
	}
      break;
    default:
      break;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
