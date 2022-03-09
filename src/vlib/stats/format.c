/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vlib/stats/stats.h>

u8 *
format_vlib_stats_symlink_name (u8 *s, va_list *args)
{
  u8 *input = va_arg (*args, u8 *);

  for (int i = 0; i < vec_len (input); i++)
    {
      if (input[i] == 0)
	return s;
      vec_add1 (s, input[i] == '/' ? '_' : input[i]);
    }
  return s;
}

u8 *
format_vlib_stats_data (u8 *s, va_list *args)
{
  void *data = va_arg (*args, void *);
  vlib_stats_data_type_t dt = va_arg (*args, vlib_stats_data_type_t);
  vlib_stats_data_type_info_t *i = vlib_stats_data_types + dt;
  if (i->format_fn)
    return format (s, "%U", i->format_fn, data);
  else
    return format (s, "%U", format_hexdump, data, i->size);
  return s;
}

u8 *
format_vlib_stats_entry_value (u8 *s, va_list *args)
{
  vlib_stats_entry_t *e = va_arg (*args, vlib_stats_entry_t *);
  vlib_stats_data_type_info_t *dti = vlib_stats_data_types + e->data_type;
  u32 i, j, indent = format_get_indent (s);

  if (e->n_dimensions == 0)
    {
      void *data = dti->size <= sizeof (e->value) ? &e->value : e->data;
      return format (s, "%U", format_vlib_stats_data, data, e->data_type);
    }
  else if (e->n_dimensions == 1)
    {
      void *data = e->data;
      int first = 1;
      vec_foreach_index (i, data)
	{
	  void *elt = (u8 *) data + i * dti->size;
	  if (!first)
	    s = format (s, "\n%U", format_white_space, indent);
	  else
	    first = 0;

	  s = format (s, "[%u] ", i);
	  s = format (s, "%U", format_vlib_stats_data, elt, e->data_type);
	}
    }
  else if (e->n_dimensions == 2)
    {
      void **data = e->data;
      int first = 1;
      vec_foreach_index (i, data)
	vec_foreach_index (j, data[i])
	  {
	    void *elt = (u8 *) data[i] + j * dti->size;
	    if (!first)
	      s = format (s, "\n%U", format_white_space, indent);
	    else
	      first = 0;

	    s = format (s, "[%u,%u] ", i, j);
	    s = format (s, "%U", format_vlib_stats_data, elt, e->data_type);
	  }
    }
  else
    s = format (s, "%u-dimensional arrays not supported", e->n_dimensions);

  return s;
}
u8 *
format_vlib_stats_entry_dim (u8 *s, va_list *args)
{
  vlib_stats_entry_t *e = va_arg (*args, vlib_stats_entry_t *);

  if (e->n_dimensions == 0)
    s = format (s, "scalar");
  else if (e->n_dimensions == 1)
    s = format (s, "1-dimensional (%u)", vec_len (e->data));
  else if (e->n_dimensions == 2)
    {
      u8 **data = e->data;
      s = format (s, "2-dimensional (%u x %u)", vec_len (data),
		  vec_len (data[0]));
    }
  else if (e->n_dimensions == 3)
    {
      u8 ***data = e->data;
      s = format (s, "3-dimensional (%u x %u x %u)", vec_len (data),
		  vec_len (data[0]), vec_len (data[0][0]));
    }
  else
    ASSERT (0);

  return s;
}

uword
unformat_vlib_stats_entry_name (unformat_input_t *input, va_list *args)
{
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  u32 *entry_index = va_arg (*args, u32 *);
  u8 *name = 0;

  if (unformat (input, "%s", &name))
    {
      vec_add1 (name, 0);
      hash_pair_t *hp = hash_get_pair (sm->directory_vector_by_name, name);
      vec_free (name);
      if (hp)
	{
	  *entry_index = hp->value[0];
	  return 1;
	}
    }
  return 0;
}
