/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#ifndef __FILTER_LIST_H__
#define __FILTER_LIST_H__

#include <filter/filter_types.h>

/**
 * A sorted list of index_t an call back is invoked if the ifrst or list element
 * of the list is changed
 */

struct filter_list_t_;

typedef void (*filter_list_update_t) (index_t owner,
				      index_t front, void *ctx);
typedef void (*filter_list_update_prev_t) (index_t owner,
					   index_t prev,
					   index_t next, void *ctx);
typedef int (*filter_list_sort_t) (index_t * i1, index_t * i2);

typedef struct filter_list_vft_t_
{
  filter_list_update_t flv_front;
  filter_list_update_t flv_back;
  filter_list_update_prev_t flv_prev;
  filter_list_update_prev_t flv_this;
  filter_list_sort_t flv_sort;
  format_function_t *flv_format;
} filter_list_vft_t;

extern struct filter_list_t_ *filter_list_create (index_t owner,
						  const filter_list_vft_t *
						  vft);

extern void filter_list_insert (struct filter_list_t_ *fl, index_t elem,
				void *ctx);
extern void filter_list_remove (struct filter_list_t_ *fl, index_t elem,
				void *ctx);
extern u32 filter_list_get_length (struct filter_list_t_ *fl);
extern index_t filter_list_get_front (struct filter_list_t_ *fl);
extern index_t filter_list_get_back (struct filter_list_t_ *fl);
extern u8 *filter_list_format (u8 * s, u32 indent, struct filter_list_t_ *fl);

extern void filter_list_destroy (struct filter_list_t_ **fl);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

#endif
