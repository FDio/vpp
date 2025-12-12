/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* pg_edit.h: packet generator edits */

#ifndef included_packet_generator_pg_edit_h
#define included_packet_generator_pg_edit_h

#include <vppinfra/format.h>
#include <vppinfra/vec.h>

typedef enum
{
  /* Invalid type used to poison edits. */
  PG_EDIT_INVALID_TYPE,

  /* Value is fixed: does not change for all packets in sequence. */
  PG_EDIT_FIXED,

  /* Value v increments between low and high values v_low <= v <= v_high. */
  PG_EDIT_INCREMENT,

  /* Random value between low and high values v_low <= v <= v_high. */
  PG_EDIT_RANDOM,

  /* Unspecified value; will be specified by some edit function. */
  PG_EDIT_UNSPECIFIED,
} pg_edit_type_t;

typedef struct
{
  pg_edit_type_t type;

  /* Bit offset within packet where value is to be written.
     Bits are written in network byte order: high bits first.
     This is the bit offset of the least significant bit: i.e. the
     highest numbered byte * 8 plus bit offset within that byte.
     Negative offsets encode special edits. */
  i32 lsb_bit_offset;

  /* Special offset indicating this edit is for packet length. */
#define PG_EDIT_PACKET_LENGTH (-1)

  /* Number of bits in edit. */
  u32 n_bits;

  /* Low and high values for this edit.  Network byte order. */
  u8 *values[2];
#define PG_EDIT_LO 0
#define PG_EDIT_HI 1

  /* Last value used for increment edit type. */
  u64 last_increment_value;
} pg_edit_t;

always_inline void
pg_edit_free (pg_edit_t * e)
{
  int i;
  for (i = 0; i < ARRAY_LEN (e->values); i++)
    vec_free (e->values[i]);
}

#define pg_edit_init_bitfield(e,type,field,field_offset,field_n_bits)	\
do {									\
  u32 _bo;								\
									\
  ASSERT ((field_offset) < STRUCT_BITS_OF (type, field));		\
									\
  /* Start byte offset. */						\
  _bo = STRUCT_OFFSET_OF (type, field);					\
									\
  /* Adjust for big endian byte order. */				\
  _bo += ((STRUCT_BITS_OF (type, field)					\
	   - (field_offset) - 1) / BITS (u8));				\
									\
  (e)->lsb_bit_offset = _bo * BITS (u8) + ((field_offset) % BITS (u8));	\
  (e)->n_bits = (field_n_bits);						\
} while (0)

/* Initialize edit for byte aligned fields. */
#define pg_edit_init(e,type,field) \
   pg_edit_init_bitfield(e,type,field,0,STRUCT_BITS_OF(type,field))

static inline uword
pg_edit_n_alloc_bytes (pg_edit_t * e)
{
  int i0, i1, n_bytes, n_bits_left;

  i0 = e->lsb_bit_offset;
  i1 = i0 % BITS (u8);

  n_bytes = 0;
  n_bits_left = e->n_bits;

  if (n_bits_left > 0 && i1 != 0)
    {
      n_bytes++;
      n_bits_left -= i1;
      if (n_bits_left < 0)
	n_bits_left = 0;
    }

  n_bytes += (n_bits_left / BITS (u8));
  n_bytes += (n_bits_left % BITS (u8)) != 0;

  return n_bytes;
}

static inline void
pg_edit_alloc_value (pg_edit_t * e, int i)
{
  vec_validate (e->values[i], e->lsb_bit_offset / BITS (u8));
}

extern void pg_edit_set_value (pg_edit_t * e, int hi_or_lo, u64 value);

static inline void
pg_edit_set_fixed (pg_edit_t * e, u64 value)
{
  e->type = PG_EDIT_FIXED;
  pg_edit_set_value (e, PG_EDIT_LO, value);
}

static inline void
pg_edit_copy_type_and_values (pg_edit_t * dst, pg_edit_t * src)
{
  int i;
  dst->type = src->type;
  src->type = PG_EDIT_INVALID_TYPE;
  for (i = 0; i < ARRAY_LEN (dst->values); i++)
    {
      dst->values[i] = src->values[i];
      src->values[i] = 0;
    }
}

static inline u64
pg_edit_get_value (pg_edit_t * e, int hi_or_lo)
{
  u64 r = 0;
  int i, n;
  u8 *v = e->values[hi_or_lo];

  n = round_pow2 (e->n_bits, BITS (u8)) / BITS (u8);

  ASSERT (n <= vec_len (v));
  ASSERT (n <= sizeof (r));

  for (i = 0; i < n; i++)
    r = (r << BITS (v[i])) + v[i];

  return r;
}

static inline uword
pg_edit_is_fixed_with_value (pg_edit_t * e, u64 value)
{
  return (e->type == PG_EDIT_FIXED
	  && value == pg_edit_get_value (e, PG_EDIT_LO));
}

uword unformat_pg_edit (unformat_input_t * input, va_list * args);
uword unformat_pg_payload (unformat_input_t * input, va_list * args);
uword unformat_pg_number (unformat_input_t * input, va_list * args);
uword unformat_pg_interface (unformat_input_t * input, va_list * args);

#endif /* included_packet_generator_pg_edit_h */
