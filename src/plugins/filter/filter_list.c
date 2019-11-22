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

#include <filter/filter_list.h>

/**
 * A sorted list of index_t and a set of call backs is invoked when elements are added.
 */
typedef struct filter_list_t_
{
  index_t fl_owner;
  index_t *fl_list;
  filter_list_vft_t fl_vft;
} filter_list_t;


filter_list_t *
filter_list_create (index_t owner, const filter_list_vft_t * vft)
{
  filter_list_t *fl;

  fl = clib_mem_alloc (sizeof (*fl));

  fl->fl_list = NULL;
  fl->fl_owner = owner;
  fl->fl_vft = *vft;

  return (fl);
}

#define vec_back(_v) (vec_len(_v) ? _v[vec_len(_v)-1] : INDEX_INVALID)
#define vec_front(_v) (vec_len(_v) ? _v[0] : INDEX_INVALID)

void
filter_list_insert (filter_list_t * fl, index_t elem, void *ctx)
{
  index_t front, back;
  u32 pos;

  front = vec_front (fl->fl_list);
  back = vec_back (fl->fl_list);

  vec_add1 (fl->fl_list, elem);

  if (fl->fl_vft.flv_sort)
    {
      vec_sort_with_function (fl->fl_list, fl->fl_vft.flv_sort);

      vec_foreach_index (pos, fl->fl_list)
      {
	if (fl->fl_list[pos] == elem)
	  break;
      }
    }
  else
    pos = vec_len (fl->fl_list) - 1;

  if (fl->fl_vft.flv_this)
    {
      if (pos < vec_len (fl->fl_list) - 1)
	fl->fl_vft.flv_this (fl->fl_owner, fl->fl_list[pos],
			     fl->fl_list[pos + 1], ctx);
      else
	fl->fl_vft.flv_this (fl->fl_owner, fl->fl_list[pos],
			     INDEX_INVALID, ctx);
    }
  if (fl->fl_vft.flv_prev && pos >= 1)
    fl->fl_vft.flv_prev (fl->fl_owner, fl->fl_list[pos - 1],
			 fl->fl_list[pos], ctx);
  if (fl->fl_vft.flv_front && front != vec_front (fl->fl_list))
    fl->fl_vft.flv_front (fl->fl_owner, vec_front (fl->fl_list), ctx);
  if (fl->fl_vft.flv_back && back != vec_back (fl->fl_list))
    fl->fl_vft.flv_back (fl->fl_owner, vec_back (fl->fl_list), ctx);
}

void
filter_list_remove (filter_list_t * fl, index_t elem, void *ctx)
{
  index_t front, back;
  u32 pos;

  front = vec_front (fl->fl_list);
  back = vec_back (fl->fl_list);

  vec_foreach_index (pos, fl->fl_list)
  {
    if (fl->fl_list[pos] == elem)
      break;
  }
  if (pos < vec_len (fl->fl_list))
    {
      vec_delete (fl->fl_list, 1, pos);

      if (fl->fl_vft.flv_prev && pos >= 1)
	{
	  if (vec_len (fl->fl_list) > pos)
	    fl->fl_vft.flv_prev (fl->fl_owner, fl->fl_list[pos - 1],
				 fl->fl_list[pos], ctx);
	  else
	    fl->fl_vft.flv_prev (fl->fl_owner, fl->fl_list[pos - 1],
				 INDEX_INVALID, ctx);
	}
      if (fl->fl_vft.flv_front && front != vec_front (fl->fl_list))
	fl->fl_vft.flv_front (fl->fl_owner, vec_front (fl->fl_list), ctx);
      if (fl->fl_vft.flv_back && back != vec_back (fl->fl_list))
	fl->fl_vft.flv_back (fl->fl_owner, vec_back (fl->fl_list), ctx);
    }
}

void
filter_list_destroy (filter_list_t ** flp)
{
  ASSERT (0 == vec_len ((*flp)->fl_list));

  clib_mem_free (*flp);
  *flp = NULL;
}

u32
filter_list_get_length (filter_list_t * fl)
{
  return (vec_len (fl->fl_list));
}

index_t
filter_list_get_front (filter_list_t * fl)
{
  if (vec_len (fl->fl_list))
    return (fl->fl_list)[0];
  return (INDEX_INVALID);
}

u8 *
filter_list_format (u8 * s, u32 indent, filter_list_t * fl)
{
  index_t *elem;

  vec_foreach (elem, fl->fl_list)
    s = format (s, "\n%U", fl->fl_vft.flv_format, *elem, indent);

  return (s);
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
