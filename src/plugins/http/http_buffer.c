/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco and/or its affiliates.
 */

#include <http/http_buffer.h>
#include <http/http.h>

static http_buffer_vft_t buf_vfts[HTTP_BUFFER_N_TYPES];

#define HTTP_BUFFER_REGISTER_VFT(type, vft)                                   \
  static void __attribute__ ((constructor)) http_buf_init_##type (void)       \
  {                                                                           \
    buf_vfts[type] = vft;                                                     \
  }

typedef struct http_buffer_fifo_
{
  svm_fifo_t *src;
  svm_fifo_seg_t *segs;
  u64 len;
  u64 offset;
} http_buffer_fifo_t;

STATIC_ASSERT (sizeof (http_buffer_fifo_t) <= HTTP_BUFFER_DATA_SZ, "buf data");

static void
buf_fifo_init (http_buffer_t *hb, void *data, u64 len)
{
  svm_fifo_t *f = (svm_fifo_t *) data;
  http_buffer_fifo_t *bf;

  bf = (http_buffer_fifo_t *) &hb->data;

  bf->len = len;
  bf->offset = 0;
  bf->src = f;
  bf->segs = 0;
}

static void
buf_fifo_free (http_buffer_t *hb)
{
  http_buffer_fifo_t *bf = (http_buffer_fifo_t *) &hb->data;

  bf->src = 0;
  vec_free (bf->segs);
}

static u32
buf_fifo_get_segs (http_buffer_t *hb, u32 max_len, svm_fifo_seg_t **fs,
		   u32 *n_segs)
{
  http_buffer_fifo_t *bf = (http_buffer_fifo_t *) &hb->data;

  u32 _n_segs = 5;
  int len;

  max_len = clib_min (bf->len - bf->offset, (u64) max_len);

  vec_validate (bf->segs, _n_segs - 1);

  len = svm_fifo_segments (bf->src, 0, bf->segs, &_n_segs, max_len);
  if (len < 0)
    return 0;

  *n_segs = _n_segs;

  HTTP_DBG (1, "available to send %u n_segs %u", len, *n_segs);

  *fs = bf->segs;
  return len;
}

static u32
buf_fifo_drain (http_buffer_t *hb, u32 len)
{
  http_buffer_fifo_t *bf = (http_buffer_fifo_t *) &hb->data;

  bf->offset += len;
  svm_fifo_dequeue_drop (bf->src, len);
  HTTP_DBG (1, "drained %u len %u offset %u", len, bf->len, bf->offset);

  return len;
}

static u64
buf_fifo_bytes_left (http_buffer_t *hb)
{
  http_buffer_fifo_t *bf = (http_buffer_fifo_t *) &hb->data;

  ASSERT (bf->offset <= bf->len);
  return (bf->len - bf->offset);
}

const static http_buffer_vft_t buf_fifo_vft = {
  .init = buf_fifo_init,
  .free = buf_fifo_free,
  .get_segs = buf_fifo_get_segs,
  .drain = buf_fifo_drain,
  .bytes_left = buf_fifo_bytes_left,
};

HTTP_BUFFER_REGISTER_VFT (HTTP_BUFFER_FIFO, buf_fifo_vft);

typedef struct http_buffer_ptr_
{
  svm_fifo_seg_t *segs;
  svm_fifo_t *f;
  u64 len;
} http_buffer_ptr_t;

STATIC_ASSERT (sizeof (http_buffer_ptr_t) <= HTTP_BUFFER_DATA_SZ, "buf data");

static void
buf_ptr_init (http_buffer_t *hb, void *data, u64 len)
{
  svm_fifo_t *f = (svm_fifo_t *) data;
  http_buffer_ptr_t *bf;
  uword ptr;
  int rv;

  bf = (http_buffer_ptr_t *) &hb->data;

  /* Peek the pointer, do not drain the fifo until done with transfer */
  rv = svm_fifo_peek (f, 0, sizeof (ptr), (u8 *) &ptr);
  ASSERT (rv == sizeof (ptr));

  bf->f = f;
  bf->segs = 0;
  vec_validate (bf->segs, 0);

  bf->segs[0].data = uword_to_pointer (ptr, u8 *);

  bf->len = len;
}

static void
buf_ptr_free (http_buffer_t *hb)
{
  http_buffer_ptr_t *bf = (http_buffer_ptr_t *) &hb->data;

  bf->f = 0;
  vec_free (bf->segs);
}

static u32
buf_ptr_get_segs (http_buffer_t *hb, u32 max_len, svm_fifo_seg_t **fs,
		  u32 *n_segs)
{
  http_buffer_ptr_t *bf = (http_buffer_ptr_t *) &hb->data;

  *n_segs = 1;
  bf->segs[0].len = clib_min (bf->len, (u64) max_len);

  *fs = bf->segs;
  return bf->segs[0].len;
}

static u32
buf_ptr_drain (http_buffer_t *hb, u32 len)
{
  http_buffer_ptr_t *bf = (http_buffer_ptr_t *) &hb->data;

  ASSERT (bf->len >= len);

  bf->segs[0].data += len;
  bf->len -= len;

  HTTP_DBG (1, "drained %u left %u", len, bf->len);

  if (!bf->len)
    {
      svm_fifo_dequeue_drop (bf->f, sizeof (uword));
      return sizeof (uword);
    }

  return 0;
}

static u64
buf_ptr_bytes_left (http_buffer_t *hb)
{
  http_buffer_ptr_t *bf = (http_buffer_ptr_t *) &hb->data;

  return bf->len;
}

const static http_buffer_vft_t buf_ptr_vft = {
  .init = buf_ptr_init,
  .free = buf_ptr_free,
  .get_segs = buf_ptr_get_segs,
  .drain = buf_ptr_drain,
  .bytes_left = buf_ptr_bytes_left,
};

HTTP_BUFFER_REGISTER_VFT (HTTP_BUFFER_PTR, buf_ptr_vft);

typedef struct http_buffer_streaming_
{
  svm_fifo_t *src;
  svm_fifo_seg_t *segs;
  u64 total_len; /* total expected length (can be ~0 for unknown) */
  u64 sent;	 /* bytes sent so far */
} http_buffer_streaming_t;

STATIC_ASSERT (sizeof (http_buffer_streaming_t) <= HTTP_BUFFER_DATA_SZ,
	       "buf data");

static void
buf_streaming_init (http_buffer_t *hb, void *data, u64 len)
{
  svm_fifo_t *f = (svm_fifo_t *) data;
  http_buffer_streaming_t *bs;

  bs = (http_buffer_streaming_t *) &hb->data;

  bs->total_len = len;
  bs->sent = 0;
  bs->src = f;
  bs->segs = 0;
}

static void
buf_streaming_free (http_buffer_t *hb)
{
  http_buffer_streaming_t *bs = (http_buffer_streaming_t *) &hb->data;

  bs->src = 0;
  vec_free (bs->segs);
}

static u32
buf_streaming_get_segs (http_buffer_t *hb, u32 max_len, svm_fifo_seg_t **fs,
			u32 *n_segs)
{
  http_buffer_streaming_t *bs = (http_buffer_streaming_t *) &hb->data;

  u32 _n_segs = 5;
  int len;

  /* For streaming, we send whatever is available */
  u32 available = svm_fifo_max_dequeue (bs->src);
  if (available == 0)
    return 0;

  max_len = clib_min (available, max_len);

  vec_validate (bs->segs, _n_segs - 1);

  len = svm_fifo_segments (bs->src, 0, bs->segs, &_n_segs, max_len);
  if (len < 0)
    return 0;

  *n_segs = _n_segs;

  HTTP_DBG (1, "streaming: available to send %u n_segs %u", len, *n_segs);

  *fs = bs->segs;
  return len;
}

static u32
buf_streaming_drain (http_buffer_t *hb, u32 len)
{
  http_buffer_streaming_t *bs = (http_buffer_streaming_t *) &hb->data;

  bs->sent += len;
  svm_fifo_dequeue_drop (bs->src, len);
  HTTP_DBG (1, "streaming: drained %u total sent %lu", len, bs->sent);

  return len;
}

static u64
buf_streaming_bytes_left (http_buffer_t *hb)
{
  http_buffer_streaming_t *bs = (http_buffer_streaming_t *) &hb->data;
  if (bs->total_len == ~0)
    {
      return ~0;
    }

  return (bs->total_len > bs->sent ? (bs->total_len - bs->sent) : 0);
}

const static http_buffer_vft_t buf_streaming_vft = {
  .init = buf_streaming_init,
  .free = buf_streaming_free,
  .get_segs = buf_streaming_get_segs,
  .drain = buf_streaming_drain,
  .bytes_left = buf_streaming_bytes_left,
};

HTTP_BUFFER_REGISTER_VFT (HTTP_BUFFER_STREAMING, buf_streaming_vft);

void
http_buffer_init (http_buffer_t *hb, http_buffer_type_t type, svm_fifo_t *f,
		  u64 data_len)
{
  hb->vft = &buf_vfts[type];
  hb->type = type;
  hb->vft->init (hb, f, data_len);
}
