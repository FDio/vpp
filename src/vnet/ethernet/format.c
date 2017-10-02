/*
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
 */
/*
 * ethernet_format.c: ethernet formatting/parsing.
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vnet/ethernet/ethernet.h>

u8 *
format_ethernet_address (u8 * s, va_list * args)
{
  ethernet_main_t *em = &ethernet_main;
  u8 *a = va_arg (*args, u8 *);

  if (em->format_ethernet_address_16bit)
    return format (s, "%02x%02x.%02x%02x.%02x%02x",
		   a[0], a[1], a[2], a[3], a[4], a[5]);
  else
    return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
		   a[0], a[1], a[2], a[3], a[4], a[5]);
}

u8 *
format_ethernet_type (u8 * s, va_list * args)
{
  ethernet_type_t type = va_arg (*args, u32);
  ethernet_main_t *em = &ethernet_main;
  ethernet_type_info_t *t = ethernet_get_type_info (em, type);

  if (t)
    s = format (s, "%s", t->name);
  else
    s = format (s, "0x%04x", type);

  return s;
}

u8 *
format_ethernet_vlan_tci (u8 * s, va_list * va)
{
  u32 vlan_tci = va_arg (*va, u32);

  u32 vid = (vlan_tci & 0xfff);
  u32 cfi = (vlan_tci >> 12) & 1;
  u32 pri = (vlan_tci >> 13);

  s = format (s, "%d", vid);
  if (pri != 0)
    s = format (s, " priority %d", pri);
  if (cfi != 0)
    s = format (s, " cfi");

  return s;
}

u8 *
format_ethernet_header_with_length (u8 * s, va_list * args)
{
  ethernet_pbb_header_packed_t *ph =
    va_arg (*args, ethernet_pbb_header_packed_t *);
  ethernet_max_header_t *m = (ethernet_max_header_t *) ph;
  u32 max_header_bytes = va_arg (*args, u32);
  ethernet_main_t *em = &ethernet_main;
  ethernet_header_t *e = &m->ethernet;
  ethernet_vlan_header_t *v;
  ethernet_type_t type = clib_net_to_host_u16 (e->type);
  ethernet_type_t vlan_type[ARRAY_LEN (m->vlan)];
  u32 n_vlan = 0, i, header_bytes;
  u32 indent;

  while ((type == ETHERNET_TYPE_VLAN || type == ETHERNET_TYPE_DOT1AD
	  || type == ETHERNET_TYPE_DOT1AH) && n_vlan < ARRAY_LEN (m->vlan))
    {
      vlan_type[n_vlan] = type;
      if (type != ETHERNET_TYPE_DOT1AH)
	{
	  v = m->vlan + n_vlan;
	  type = clib_net_to_host_u16 (v->type);
	}
      n_vlan++;
    }

  header_bytes = sizeof (e[0]) + n_vlan * sizeof (v[0]);
  if (max_header_bytes != 0 && header_bytes > max_header_bytes)
    return format (s, "ethernet header truncated");

  indent = format_get_indent (s);

  s = format (s, "%U: %U -> %U",
	      format_ethernet_type, type,
	      format_ethernet_address, e->src_address,
	      format_ethernet_address, e->dst_address);

  if (type != ETHERNET_TYPE_DOT1AH)
    {
      for (i = 0; i < n_vlan; i++)
	{
	  u32 v = clib_net_to_host_u16 (m->vlan[i].priority_cfi_and_id);
	  if (*vlan_type == ETHERNET_TYPE_VLAN)
	    s = format (s, " 802.1q vlan %U", format_ethernet_vlan_tci, v);
	  else
	    s = format (s, " 802.1ad vlan %U", format_ethernet_vlan_tci, v);
	}

      if (max_header_bytes != 0 && header_bytes < max_header_bytes)
	{
	  ethernet_type_info_t *ti;
	  vlib_node_t *node = 0;

	  ti = ethernet_get_type_info (em, type);
	  if (ti && ti->node_index != ~0)
	    node = vlib_get_node (em->vlib_main, ti->node_index);
	  if (node && node->format_buffer)
	    s = format (s, "\n%U%U",
			format_white_space, indent,
			node->format_buffer, (void *) m + header_bytes,
			max_header_bytes - header_bytes);
	}
    }
  else
    {
      s =
	format (s, " %s b-tag %04X",
		(clib_net_to_host_u16 (ph->b_type) ==
		 ETHERNET_TYPE_DOT1AD) ? "802.1ad" : "",
		clib_net_to_host_u16 (ph->priority_dei_id));
      s =
	format (s, " %s i-tag %08X",
		(clib_net_to_host_u16 (ph->i_type) ==
		 ETHERNET_TYPE_DOT1AH) ? "802.1ah" : "",
		clib_net_to_host_u32 (ph->priority_dei_uca_res_sid));
    }

  return s;
}

u8 *
format_ethernet_header (u8 * s, va_list * args)
{
  ethernet_max_header_t *m = va_arg (*args, ethernet_max_header_t *);
  return format (s, "%U", format_ethernet_header_with_length, m, 0);
}

/* Parse X:X:X:X:X:X unix style ethernet address. */
static uword
unformat_ethernet_address_unix (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  u32 i, a[6];

  if (!unformat (input, "%_%x:%x:%x:%x:%x:%x%_",
		 &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]))
    return 0;

  /* Check range. */
  for (i = 0; i < ARRAY_LEN (a); i++)
    if (a[i] >= (1 << 8))
      return 0;

  for (i = 0; i < ARRAY_LEN (a); i++)
    result[i] = a[i];

  return 1;
}

/* Parse X.X.X cisco style ethernet address. */
static uword
unformat_ethernet_address_cisco (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  u32 i, a[3];

  if (!unformat (input, "%_%x.%x.%x%_", &a[0], &a[1], &a[2]))
    return 0;

  /* Check range. */
  for (i = 0; i < ARRAY_LEN (a); i++)
    if (a[i] >= (1 << 16))
      return 0;

  result[0] = (a[0] >> 8) & 0xff;
  result[1] = (a[0] >> 0) & 0xff;
  result[2] = (a[1] >> 8) & 0xff;
  result[3] = (a[1] >> 0) & 0xff;
  result[4] = (a[2] >> 8) & 0xff;
  result[5] = (a[2] >> 0) & 0xff;

  return 1;
}

/* Parse ethernet address; accept either unix or style addresses. */
uword
unformat_ethernet_address (unformat_input_t * input, va_list * args)
{
  u8 *result = va_arg (*args, u8 *);
  return (unformat_user (input, unformat_ethernet_address_unix, result)
	  || unformat_user (input, unformat_ethernet_address_cisco, result));
}

/* Returns ethernet type as an int in host byte order. */
uword
unformat_ethernet_type_host_byte_order (unformat_input_t * input,
					va_list * args)
{
  u16 *result = va_arg (*args, u16 *);
  ethernet_main_t *em = &ethernet_main;
  int type, i;

  /* Numeric type. */
  if (unformat (input, "0x%x", &type) || unformat (input, "%d", &type))
    {
      if (type >= (1 << 16))
	return 0;
      *result = type;
      return 1;
    }

  /* Named type. */
  if (unformat_user (input, unformat_vlib_number_by_name,
		     em->type_info_by_name, &i))
    {
      ethernet_type_info_t *ti = vec_elt_at_index (em->type_infos, i);
      *result = ti->type;
      return 1;
    }

  return 0;
}

uword
unformat_ethernet_type_net_byte_order (unformat_input_t * input,
				       va_list * args)
{
  u16 *result = va_arg (*args, u16 *);
  if (!unformat_user (input, unformat_ethernet_type_host_byte_order, result))
    return 0;

  *result = clib_host_to_net_u16 ((u16) * result);
  return 1;
}

uword
unformat_ethernet_header (unformat_input_t * input, va_list * args)
{
  u8 **result = va_arg (*args, u8 **);
  ethernet_max_header_t _m, *m = &_m;
  ethernet_header_t *e = &m->ethernet;
  u16 type;
  u32 n_vlan;

  if (!unformat (input, "%U: %U -> %U",
		 unformat_ethernet_type_host_byte_order, &type,
		 unformat_ethernet_address, &e->src_address,
		 unformat_ethernet_address, &e->dst_address))
    return 0;

  n_vlan = 0;
  while (unformat (input, "vlan"))
    {
      u32 id, priority;

      if (!unformat_user (input, unformat_vlib_number, &id)
	  || id >= ETHERNET_N_VLAN)
	return 0;

      if (unformat (input, "priority %d", &priority))
	{
	  if (priority >= 8)
	    return 0;
	  id |= priority << 13;
	}

      if (unformat (input, "cfi"))
	id |= 1 << 12;

      /* Too many vlans given. */
      if (n_vlan >= ARRAY_LEN (m->vlan))
	return 0;

      m->vlan[n_vlan].priority_cfi_and_id = clib_host_to_net_u16 (id);
      n_vlan++;
    }

  if (n_vlan == 0)
    e->type = clib_host_to_net_u16 (type);
  else
    {
      int i;

      e->type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      for (i = 0; i < n_vlan - 1; i++)
	m->vlan[i].type = clib_host_to_net_u16 (ETHERNET_TYPE_VLAN);
      m->vlan[n_vlan - 1].type = clib_host_to_net_u16 (type);
    }

  /* Add header to result. */
  {
    void *p;
    u32 n_bytes = sizeof (e[0]) + n_vlan * sizeof (m->vlan[0]);

    vec_add2 (*result, p, n_bytes);
    clib_memcpy (p, m, n_bytes);
  }

  return 1;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
