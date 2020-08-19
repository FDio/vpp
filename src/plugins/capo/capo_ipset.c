/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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


#include <capo/capo.h>
#include <capo/capo_ipset.h>

capo_ipset_t *capo_ipsets;

static capo_ipset_t *
capo_ipsets_get_if_exists (u32 index)
{
  if (pool_is_free_index (capo_ipsets, index))
    return (NULL);
  return pool_elt_at_index (capo_ipsets, index);
}

u32
capo_ipset_create (capo_ipset_type_t type)
{
  capo_ipset_t *ipset;
  pool_get (capo_ipsets, ipset);
  ipset->type = type;
  ipset->members = NULL;
  return ipset - capo_ipsets;
}

int
capo_ipset_delete (u32 id)
{
  capo_ipset_t *ipset;
  ipset = capo_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  pool_free (ipset->members);
  pool_put (capo_ipsets, ipset);
  return 0;
}

int
capo_ipset_get_type (u32 id, capo_ipset_type_t * type)
{
  capo_ipset_t *ipset;
  ipset = capo_ipsets_get_if_exists (id);
  if (NULL == ipset)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  *type = ipset->type;
  return 0;
}

int
capo_ipset_add_member (u32 ipset_id, capo_ipset_member_t * member)
{
  capo_ipset_member_t *m;
  capo_ipset_t *ipset = &capo_ipsets[ipset_id];

  if (pool_is_free (capo_ipsets, ipset))
    return 1;

  pool_get (ipset->members, m);
  memcpy (m, member, sizeof (*m));
  return 0;
}

int
capo_ipset_del_member (u32 ipset_id, capo_ipset_member_t * member)
{
  capo_ipset_member_t *m;
  capo_ipset_t *ipset = &capo_ipsets[ipset_id];

  if (pool_is_free (capo_ipsets, ipset))
    return 1;

    /* *INDENT-OFF* */
    pool_foreach(m, ipset->members, ({
      if (!memcmp(m, member, sizeof(*m)))
        {
          pool_put(ipset->members, m);
          return 0;
        }
    }));
    /* *INDENT-ON* */

  clib_warning ("could not find ipset member to delete");
  return 2;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
