/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <http/http_buffer.h>
#include <http/http.h>

static http_buffer_vft_t buf_vfts[HTTP_BUFFER_PTR + 1];

#define HTTP_BUFFER_REGISTER_VFT(type, vft)                                   \
  static void __attribute__ ((constructor)) http_buf_init_##type (void)       \
  {                                                                           \
    buf_vfts[type] = vft;                                                     \
  }

typedef struct http_buffer_fifo_
{
  svm_fifo_t *src;
  svm_fifo_seg_t *segs;
  u32 len;
  u32 offset;
} http_buffer_fifo_t;

STATIC_ASSERT (sizeof (http_buffer_fifo_t) <= HTTP_BUFFER_DATA_SZ, "buf data");

static void
buf_fifo_init (http_buffer_t *hb, void *data, u32 len)
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

static svm_fifo_seg_t *
buf_fifo_get_segs (http_buffer_t *hb, u32 max_len, u32 *n_segs)
{
  http_buffer_fifo_t *bf = (http_buffer_fifo_t *) &hb->data;

  u32 _n_segs = 5;
  int len;

  max_len = clib_max (bf->len - bf->offset, max_len);

  vec_validate (bf->segs, _n_segs);

  len = svm_fifo_segments (bf->src, 0, bf->segs, &_n_segs, max_len);
  if (len < 0)
    return 0;

  *n_segs = _n_segs;

  HTTP_DBG (1, "available to send %u n_segs %u", len, *n_segs);

  return bf->segs;
}

static void
buf_fifo_drain (http_buffer_t *hb, u32 len)
{
  http_buffer_fifo_t *bf = (http_buffer_fifo_t *) &hb->data;

  bf->offset += len;
  svm_fifo_dequeue_drop (bf->src, len);
  HTTP_DBG (1, "drained %u len %u offset %u", len, hb->len, hb->offset);
}

static u8
buf_fifo_is_drained (http_buffer_t *hb)
{
  http_buffer_fifo_t *bf = (http_buffer_fifo_t *) &hb->data;

  ASSERT (bf->offset <= bf->len);
  return (bf->offset == bf->len);
}

const static http_buffer_vft_t buf_fifo_vft = {
  .init = buf_fifo_init,
  .free = buf_fifo_free,
  .get_segs = buf_fifo_get_segs,
  .drain = buf_fifo_drain,
  .is_drained = buf_fifo_is_drained,
};

HTTP_BUFFER_REGISTER_VFT (HTTP_BUFFER_FIFO, buf_fifo_vft);

typedef struct http_buffer_ptr_
{
  svm_fifo_seg_t *segs;
  svm_fifo_t *f;
} http_buffer_ptr_t;

STATIC_ASSERT (sizeof (http_buffer_ptr_t) <= HTTP_BUFFER_DATA_SZ, "buf data");

static void
buf_ptr_init (http_buffer_t *hb, void *data, u32 len)
{
  svm_fifo_t *f = (svm_fifo_t *) data;
  http_buffer_ptr_t *bf;

  bf = (http_buffer_ptr_t *) &hb->data;

  bf->f = f;
  bf->segs = 0;
  vec_validate (bf->segs, 1);

  bf->segs[0].data = 0;
  bf->segs[0].len = len;

  bf->segs[1] = bf->segs[0];
}

static void
buf_ptr_free (http_buffer_t *hb)
{
  http_buffer_ptr_t *bf = (http_buffer_ptr_t *) &hb->data;

  bf->f = 0;
  vec_free (bf->segs);
}

static svm_fifo_seg_t *
buf_ptr_get_segs (http_buffer_t *hb, u32 max_len, u32 *n_segs)
{
  http_buffer_ptr_t *bf = (http_buffer_ptr_t *) &hb->data;

  *n_segs = 1;

  return &bf->segs[1];
}

static void
buf_ptr_drain (http_buffer_t *hb, u32 len)
{
  http_buffer_ptr_t *bf = (http_buffer_ptr_t *) &hb->data;

  bf->segs[1].data += len;
  bf->segs[1].len -= len;

  if (!bf->segs[1].len)
    svm_fifo_dequeue_drop (bf->f, sizeof (uword));

  HTTP_DBG (1, "drained %u left %u", len, bf->segs[1].len);
}

static u8
buf_ptr_is_drained (http_buffer_t *hb)
{
  http_buffer_ptr_t *bf = (http_buffer_ptr_t *) &hb->data;

  ASSERT (bf->segs[1].len <= bf->segs[0].len);
  return (bf->segs[1].len == 0);
}

const static http_buffer_vft_t buf_ptr_vft = {
  .init = buf_ptr_init,
  .free = buf_ptr_free,
  .get_segs = buf_ptr_get_segs,
  .drain = buf_ptr_drain,
  .is_drained = buf_ptr_is_drained,
};

HTTP_BUFFER_REGISTER_VFT (HTTP_BUFFER_PTR, buf_ptr_vft);

void
http_buffer_init (http_buffer_t *hb, http_buffer_type_t type, svm_fifo_t *f,
		  u32 data_len)
{
  hb->type = type;
  hb->vft = &buf_vfts[type];
  hb->vft->init (hb, f, data_len);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
