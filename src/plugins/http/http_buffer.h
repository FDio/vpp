/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP_BUFFER_H_
#define SRC_PLUGINS_HTTP_HTTP_BUFFER_H_

#include <svm/svm_fifo.h>

#define HTTP_BUFFER_DATA_SZ 32

typedef enum http_buffer_type_
{
  HTTP_BUFFER_FIFO,
  HTTP_BUFFER_PTR,
  HTTP_BUFFER_STREAMING,
  /* the value below is used to size the structures indexed by
     http_buffer_type_t */
  HTTP_BUFFER_N_TYPES,
} http_buffer_type_t;

typedef struct http_buffer_vft_ http_buffer_vft_t;

typedef struct http_buffer_
{
  http_buffer_vft_t *vft;
  http_buffer_type_t type;
  u8 data[HTTP_BUFFER_DATA_SZ];
} http_buffer_t;

struct http_buffer_vft_
{
  void (*init) (http_buffer_t *, void *data, u64 len);
  void (*free) (http_buffer_t *);
  u32 (*get_segs) (http_buffer_t *, u32 max_len, svm_fifo_seg_t **fs,
		   u32 *n_segs);
  u32 (*drain) (http_buffer_t *, u32 len);
  u64 (*bytes_left) (http_buffer_t *);
};

void http_buffer_init (http_buffer_t *hb, http_buffer_type_t type,
		       svm_fifo_t *f, u64 data_len);

static inline void
http_buffer_free (http_buffer_t *hb)
{
  if (hb->vft)
    hb->vft->free (hb);
}

static inline u32
http_buffer_get_segs (http_buffer_t *hb, u32 max_len, svm_fifo_seg_t **fs,
		      u32 *n_segs)
{
  return hb->vft->get_segs (hb, max_len, fs, n_segs);
}

static inline u32
http_buffer_drain (http_buffer_t *hb, u32 len)
{
  return hb->vft->drain (hb, len);
}

static inline u64
http_buffer_bytes_left (http_buffer_t *hb)
{
  return hb->vft->bytes_left (hb);
}

#endif /* SRC_PLUGINS_HTTP_HTTP_BUFFER_H_ */
