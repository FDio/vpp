/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2005 Eliot Dresselhaus
 */

#ifndef included_clib_random_buffer_h
#define included_clib_random_buffer_h

#include <vppinfra/clib.h>
#include <vppinfra/random_isaac.h>
#include <vppinfra/warnings.h>

WARN_OFF(array-bounds)

typedef struct
{
  /* Two parallel ISAAC contexts for speed. */
  isaac_t ctx[2];

  /* Random buffer. */
  uword *buffer;

  /* An actual length to be applied before using the buffer. */
  uword next_read_len;

  /* Cache up to 1 word worth of bytes for random data
     less than one word at a time. */
  uword n_cached_bytes;

  union
  {
    u8 cached_bytes[sizeof (uword)];
    uword cached_word;
  };
}
clib_random_buffer_t;

always_inline void
clib_random_buffer_free (clib_random_buffer_t * b)
{
  vec_free (b->buffer);
}

/* Fill random buffer. */
void clib_random_buffer_fill (clib_random_buffer_t * b, uword n_words);

/* Initialize random buffer. */
void clib_random_buffer_init (clib_random_buffer_t * b, uword seed);

/* Returns word aligned random data, possibly filling buffer. */
always_inline void *
clib_random_buffer_get_data (clib_random_buffer_t * b, uword n_bytes)
{
  uword n_words, i, l;

  if (b->buffer)
    vec_set_len (b->buffer, b->next_read_len);
  else
    ASSERT (b->next_read_len == 0);

  l = b->n_cached_bytes;
  if (n_bytes <= l)
    {
      b->n_cached_bytes = l - n_bytes;
      return &b->cached_bytes[l - n_bytes];
    }

  n_words = n_bytes / sizeof (uword);
  if (n_bytes % sizeof (uword))
    n_words++;

  /* Enough random words left? */
  if (PREDICT_FALSE (n_words > vec_len (b->buffer)))
    clib_random_buffer_fill (b, n_words);

  i = vec_len (b->buffer) - n_words;
  b->next_read_len = i;

  if (n_bytes < sizeof (uword))
    {
      b->cached_word = b->buffer[i];
      b->n_cached_bytes = sizeof (uword) - n_bytes;
      return &b->cached_bytes[sizeof (uword) - n_bytes];
    }
  else
    return b->buffer + i;
}

WARN_ON(array-bounds)

#endif /* included_clib_random_buffer_h */
