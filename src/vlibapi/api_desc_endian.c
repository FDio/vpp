/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

/* Byte order conversion of API messages by interpreting API descriptors. It
 * does what the generated vl_api_<msg>_t_endian functions do: the integers
 * and floats of 2, 4 and 8 bytes are swapped, enums by their underlying
 * type, nested types and the elements of arrays one by one, and a union
 * which has a tag only by the arm the tag selects. Arrays of bytes, strings,
 * bools and aliases which are arrays are not touched, and client_index is
 * not converted. */

#include <vlibapi/api_desc.h>
#include <vlibapi/api_common.h>
#include <vppinfra/byte_order.h>

static void desc_endian_type (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t, u8 *base,
			      int to_net);

static u32
desc_size_of_kind (u32 kind)
{
  switch (kind)
    {
    case VL_API_DK_U16:
    case VL_API_DK_I16:
      return 2;
    case VL_API_DK_U32:
    case VL_API_DK_I32:
      return 4;
    case VL_API_DK_U64:
    case VL_API_DK_I64:
    case VL_API_DK_F64:
      return 8;
    default:
      return 1;
    }
}

static void
desc_swap (u8 *p, u32 size)
{
  switch (size)
    {
    case 2:
      {
	u16 v;

	clib_memcpy_fast (&v, p, sizeof (v));
	v = clib_byte_swap_u16 (v);
	clib_memcpy_fast (p, &v, sizeof (v));
      }
      break;
    case 4:
      {
	u32 v;

	clib_memcpy_fast (&v, p, sizeof (v));
	v = clib_byte_swap_u32 (v);
	clib_memcpy_fast (p, &v, sizeof (v));
      }
      break;
    case 8:
      {
	u64 v;

	clib_memcpy_fast (&v, p, sizeof (v));
	v = clib_byte_swap_u64 (v);
	clib_memcpy_fast (p, &v, sizeof (v));
      }
      break;
    }
}

/* one value of a field or one element of an array */
static void
desc_endian_element (const vl_api_desc_file_t *df, const vl_api_desc_field_t *f, u8 *p, int to_net)
{
  switch (f->kind)
    {
    case VL_API_DK_U16 ... VL_API_DK_F64:
      desc_swap (p, desc_size_of_kind (f->kind));
      break;
    case VL_API_DK_ENUM:
    case VL_API_DK_ENUMFLAG:
      desc_swap (p, desc_size_of_kind (vl_api_desc_ref (df, f)->base));
      break;
    case VL_API_DK_STRUCT:
      desc_endian_type (df, vl_api_desc_ref (df, f), p, to_net);
      break;
    default:
      /* bytes, strings, bools, aliases of arrays and untagged unions */
      break;
    }
}

/* the value of a field which is an integer or an enum, host byte order */
static u64
desc_read_host (const vl_api_desc_file_t *df, const vl_api_desc_field_t *f, const u8 *p, int in_net)
{
  u32 size = f->kind == VL_API_DK_ENUM || f->kind == VL_API_DK_ENUMFLAG ?
	       desc_size_of_kind (vl_api_desc_ref (df, f)->base) :
	       desc_size_of_kind (f->kind);
  u64 v = 0;
  u8 tmp[8];

  clib_memcpy_fast (tmp, p, size);
  if (in_net)
    desc_swap (tmp, size);
  clib_memcpy_fast (&v, tmp, size);
  return v;
}

/* the arm of a tagged union which the tag, in host byte order, selects */
static void
desc_endian_tagged (const vl_api_desc_file_t *df, const vl_api_desc_field_t *f, u8 *base, u64 tag,
		    int to_net)
{
  const vl_api_desc_type_t *u = vl_api_desc_ref (df, f);

  for (u32 i = 0; i < u->n_fields; i++)
    {
      const vl_api_desc_field_t *arm = &vl_api_desc_fields (df, u)[i];

      if ((arm->flags & VL_API_DF_CASE) && (u64) arm->case_value == tag)
	{
	  desc_endian_element (df, arm, base + f->offset + arm->offset, to_net);
	  return;
	}
    }
}

#define DESC_MAX_TAGS 4

static void
desc_endian_type (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t, u8 *base, int to_net)
{
  u64 tags[DESC_MAX_TAGS];
  u32 n_tags = 0;

  /* the tags are read before anything is converted, as the type was handed
   * over, in host byte order when it is on its way to the network */
  for (u32 i = 0; i < t->n_fields; i++)
    if ((vl_api_desc_fields (df, t)[i].flags & VL_API_DF_TAGGED) && n_tags < DESC_MAX_TAGS)
      {
	const vl_api_desc_field_t *tag =
	  &vl_api_desc_fields (df, t)[vl_api_desc_fields (df, t)[i].related];

	tags[n_tags++] = desc_read_host (df, tag, base + tag->offset, !to_net);
      }

  n_tags = 0;

  for (u32 i = 0; i < t->n_fields; i++)
    {
      const vl_api_desc_field_t *f = &vl_api_desc_fields (df, t)[i];
      u8 *p = base + f->offset;

      if (f->flags & VL_API_DF_NO_ENDIAN)
	continue;

      if (f->flags & VL_API_DF_TAGGED)
	{
	  if (n_tags < DESC_MAX_TAGS)
	    desc_endian_tagged (df, f, base, tags[n_tags++], to_net);
	  continue;
	}

      if (f->flags & VL_API_DF_ARRAY)
	{
	  u32 n = f->length;

	  /* arrays of things which are not converted */
	  if (f->kind <= VL_API_DK_I8 || f->kind == VL_API_DK_BOOL || f->kind == VL_API_DK_STRING ||
	      f->kind == VL_API_DK_FSTRING || f->kind == VL_API_DK_NAMED ||
	      f->kind == VL_API_DK_UNION)
	    continue;

	  if (f->flags & VL_API_DF_VLA)
	    {
	      /* the length is converted already, it is a host value when it is
	       * on its way to the network */
	      const vl_api_desc_field_t *lf = &vl_api_desc_fields (df, t)[f->related];

	      n = desc_read_host (df, lf, base + lf->offset, to_net);
	    }

	  for (u32 k = 0; k < n; k++)
	    desc_endian_element (df, f, p + k * f->size, to_net);

	  continue;
	}

      desc_endian_element (df, f, p, to_net);
    }
}

void
vl_api_desc_msg_endian (const vl_api_desc_msg_t *m, void *msg, int to_net)
{
  if (!clib_arch_is_little_endian)
    return;

  desc_endian_type (m->file, m->type, msg, to_net);
}

/* A plan is the descriptor of a message flattened into what has to be done,
 * built once: the swaps of the fixed part, merged when they are next to each
 * other, and what is left to interpret. */
typedef struct desc_op
{
  u32 offset;
  u16 size;  /* of an element to swap, 0 if the op is interpreted */
  u16 count; /* of elements, or of the structures */
  /* interpreted: the type of the structures, or the type which has the VLA */
  const vl_api_desc_type_t *type;
  const vl_api_desc_field_t *vla;
  /* what to do with each of the structures or the elements of the VLA */
  struct desc_op *sub;
} desc_op_t;

static int
desc_type_has_tag (const vl_api_desc_file_t *df, const vl_api_desc_type_t *t)
{
  for (u32 i = 0; i < t->n_fields; i++)
    if (vl_api_desc_fields (df, t)[i].flags & VL_API_DF_TAGGED)
      return 1;
  return 0;
}

static void desc_run_plan (const vl_api_desc_file_t *df, const desc_op_t *ops, u8 *msg, int to_net);

static void
desc_plan_swap (desc_op_t **ops, u32 offset, u32 size, u32 count)
{
  desc_op_t *last = vec_len (*ops) ? vec_end (*ops) - 1 : 0;

  if (last && last->size == size && last->offset + (u32) last->size * last->count == offset &&
      (u32) last->count + count < 65536)
    {
      last->count += count;
      return;
    }

  desc_op_t op = { .offset = offset, .size = size, .count = count };
  vec_add1 (*ops, op);
}

static void desc_plan_type (const vl_api_desc_file_t *df, desc_op_t **ops,
			    const vl_api_desc_type_t *t, u32 base);

/* the plan of a structure, which is not empty even if there is nothing to do */
static void
desc_plan_sub (const vl_api_desc_file_t *df, desc_op_t **ops, const vl_api_desc_type_t *t)
{
  desc_plan_type (df, ops, t, 0);
  if (!vec_len (*ops))
    {
      desc_op_t none = { .size = 1 };
      vec_add1 (*ops, none);
    }
}

static void
desc_plan_type (const vl_api_desc_file_t *df, desc_op_t **ops, const vl_api_desc_type_t *t,
		u32 base)
{
  if (desc_type_has_tag (df, t))
    {
      desc_op_t op = { .offset = base, .count = 1, .type = t };
      vec_add1 (*ops, op);
      return;
    }

  for (u32 i = 0; i < t->n_fields; i++)
    {
      const vl_api_desc_field_t *f = &vl_api_desc_fields (df, t)[i];
      u32 off = base + f->offset, n = 1, size = 0;

      if (f->flags & VL_API_DF_NO_ENDIAN)
	continue;

      if (f->flags & VL_API_DF_ARRAY)
	{
	  if (f->kind <= VL_API_DK_I8 || f->kind == VL_API_DK_BOOL || f->kind == VL_API_DK_STRING ||
	      f->kind == VL_API_DK_FSTRING || f->kind == VL_API_DK_NAMED ||
	      f->kind == VL_API_DK_UNION)
	    continue;

	  if (f->flags & VL_API_DF_VLA)
	    {
	      desc_op_t op = { .offset = base, .type = t, .vla = f };
	      if (f->kind == VL_API_DK_STRUCT)
		desc_plan_sub (df, &op.sub, vl_api_desc_ref (df, f));
	      vec_add1 (*ops, op);
	      continue;
	    }
	  n = f->length;
	}

      switch (f->kind)
	{
	case VL_API_DK_U16 ... VL_API_DK_F64:
	  size = desc_size_of_kind (f->kind);
	  break;
	case VL_API_DK_ENUM:
	case VL_API_DK_ENUMFLAG:
	  size = desc_size_of_kind (vl_api_desc_ref (df, f)->base);
	  break;
	case VL_API_DK_STRUCT:
	  if (n * vl_api_desc_ref (df, f)->n_fields <= 64)
	    {
	      for (u32 k = 0; k < n; k++)
		desc_plan_type (df, ops, vl_api_desc_ref (df, f), off + k * f->size);
	    }
	  else
	    {
	      desc_op_t op = { .offset = off, .count = n, .type = vl_api_desc_ref (df, f) };
	      desc_plan_sub (df, &op.sub, vl_api_desc_ref (df, f));
	      vec_add1 (*ops, op);
	    }
	  break;
	default:
	  break;
	}

      if (size > 1)
	desc_plan_swap (ops, off, size, n);
    }
}

static void
desc_run_vla (const vl_api_desc_file_t *df, const desc_op_t *op, u8 *base, int to_net)
{
  const vl_api_desc_type_t *t = op->type;
  const vl_api_desc_field_t *f = op->vla;
  const vl_api_desc_field_t *lf = &vl_api_desc_fields (df, t)[f->related];
  u32 n = desc_read_host (df, lf, base + lf->offset, to_net);

  if (op->sub)
    {
      for (u32 k = 0; k < n; k++)
	desc_run_plan (df, op->sub, base + f->offset + k * f->size, to_net);
      return;
    }

  for (u32 k = 0; k < n; k++)
    desc_endian_element (df, f, base + f->offset + k * f->size, to_net);
}

static void
desc_run_plan (const vl_api_desc_file_t *df, const desc_op_t *ops, u8 *msg, int to_net)
{
  for (const desc_op_t *op = ops; op < vec_end (ops); op++)
    {
      u8 *p = msg + op->offset;

      switch (op->size)
	{
	case 2:
	  for (u32 k = 0; k < op->count; k++, p += 2)
	    {
	      u16 v;

	      clib_memcpy_fast (&v, p, 2);
	      v = clib_byte_swap_u16 (v);
	      clib_memcpy_fast (p, &v, 2);
	    }
	  break;
	case 4:
	  for (u32 k = 0; k < op->count; k++, p += 4)
	    {
	      u32 v;

	      clib_memcpy_fast (&v, p, 4);
	      v = clib_byte_swap_u32 (v);
	      clib_memcpy_fast (p, &v, 4);
	    }
	  break;
	case 8:
	  for (u32 k = 0; k < op->count; k++, p += 8)
	    {
	      u64 v;

	      clib_memcpy_fast (&v, p, 8);
	      v = clib_byte_swap_u64 (v);
	      clib_memcpy_fast (p, &v, 8);
	    }
	  break;
	default:
	  if (op->vla)
	    desc_run_vla (df, op, msg + op->offset, to_net);
	  else if (op->sub)
	    for (u32 k = 0; k < op->count; k++)
	      desc_run_plan (df, op->sub, p + k * op->type->size, to_net);
	  else
	    for (u32 k = 0; k < op->count; k++)
	      desc_endian_type (df, op->type, p + k * op->type->size, to_net);
	  break;
	}
    }
}

void
vl_api_msg_endian (api_main_t *am, u32 msg_id, void *msg, int to_net)
{
  const vl_api_desc_msg_t *m = vl_api_desc_find_msg (am, msg_id);
  desc_op_t *plan;

  if (m)
    {
      if (!clib_arch_is_little_endian)
	return;

      if (PREDICT_FALSE (msg_id >= vec_len (am->desc_endian_plans) ||
			 !am->desc_endian_plans[msg_id]))
	{
	  plan = 0;
	  desc_plan_type (m->file, &plan, m->type, 0);
	  /* a message which needs nothing has a plan which is not empty */
	  desc_op_t none = { .size = 1 };
	  vec_add1 (plan, none);
	  vec_validate_init_empty (am->desc_endian_plans, msg_id, 0);
	  am->desc_endian_plans[msg_id] = plan;
	}

      desc_run_plan (m->file, am->desc_endian_plans[msg_id], msg, to_net);
    }
  else if (msg_id < vec_len (am->msg_data) && am->msg_data[msg_id].endian_handler)
    am->msg_data[msg_id].endian_handler (msg, to_net);
}

int
vl_api_msg_has_endian (api_main_t *am, u32 msg_id)
{
  return vl_api_desc_find_msg (am, msg_id) ||
	 (msg_id < vec_len (am->msg_data) && am->msg_data[msg_id].endian_handler);
}
