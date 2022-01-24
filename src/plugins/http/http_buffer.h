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

#ifndef SRC_PLUGINS_HTTP_HTTP_BUFFER_H_
#define SRC_PLUGINS_HTTP_HTTP_BUFFER_H_

#include <svm/svm_fifo.h>

#define HTTP_BUFFER_DATA_SZ 24

typedef enum http_buffer_type_
{
  HTTP_BUFFER_FIFO,
  HTTP_BUFFER_PTR,
} http_buffer_type_t;

typedef struct http_buffer_vft_ http_buffer_vft_t;

typedef struct http_buffer_
{
  http_buffer_vft_t *vft;
  u8 data[HTTP_BUFFER_DATA_SZ];
} http_buffer_t;

struct http_buffer_vft_
{
  void (*init) (http_buffer_t *, void *data, u32 len);
  void (*free) (http_buffer_t *);
  svm_fifo_seg_t *(*get_segs) (http_buffer_t *, u32 max_len, u32 *n_segs);
  void (*drain) (http_buffer_t *, u32 len);
  u8 (*is_drained) (http_buffer_t *);
};

void http_buffer_init (http_buffer_t *hb, http_buffer_type_t type,
		       svm_fifo_t *f, u32 data_len);

static inline void
http_buffer_free (http_buffer_t *hb)
{
  hb->vft->free (hb);
}

static inline svm_fifo_seg_t *
http_buffer_get_segs (http_buffer_t *hb, u32 max_len, u32 *n_segs)
{
  return hb->vft->get_segs (hb, max_len, n_segs);
}

static inline void
http_buffer_drain (http_buffer_t *hb, u32 len)
{
  hb->vft->drain (hb, len);
}

static inline u8
http_buffer_is_drained (http_buffer_t *hb)
{
  return hb->vft->is_drained (hb);
}

#endif /* SRC_PLUGINS_HTTP_HTTP_BUFFER_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
