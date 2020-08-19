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


/**
 * Create an empty ipset
 */
u32
capo_ipset_create (capo_ipset_type_t type)
{
  capo_ipset_t *ipset;
  pool_get (capo_main.ipsets, ipset);
  ipset->type = type;
  ipset->members = NULL;
  return ipset - capo_main.ipsets;
}

int
capo_ipset_delete (u32 ipset_id)
{
  capo_ipset_t *ipset = &capo_main.ipsets[ipset_id];

  if (pool_is_free (capo_main.ipsets, ipset))
    return 1;

  pool_free (ipset->members);
  pool_put (capo_main.ipsets, ipset);
  return 0;
}

int
capo_ipset_member_from_api (u32 ipset_id, vl_api_capo_ipset_member_t * m,
			    capo_ipset_member_t * dest)
{
  capo_ipset_t *ipset = &capo_main.ipsets[ipset_id];

  if (pool_is_free (capo_main.ipsets, ipset))
    return 1;

  switch (ipset->type)
    {
    case IPSET_TYPE_IP:
      ip_address_decode2 (&m->val.address, &dest->address);
      break;
    case IPSET_TYPE_IPPORT:
      ip_address_decode2 (&m->val.tuple.address, &dest->ipport.addr);
      dest->ipport.l4proto = m->val.tuple.l4_proto;
      dest->ipport.port = clib_net_to_host_u16 (m->val.tuple.port);
      break;
    case IPSET_TYPE_NET:
      return ip_prefix_decode2 (&m->val.prefix, &dest->prefix);
    }
  return 0;
}

int
capo_ipset_add_member (u32 ipset_id, capo_ipset_member_t * new_member)
{
  capo_ipset_member_t *m;
  capo_ipset_t *ipset = &capo_main.ipsets[ipset_id];

  if (pool_is_free (capo_main.ipsets, ipset))
    return 1;

  pool_get (ipset->members, m);
  memcpy (m, new_member, sizeof (*m));
  return 0;
}

int
capo_ipset_del_member (u32 ipset_id, capo_ipset_member_t * to_delete)
{
  capo_ipset_member_t *m;
  capo_ipset_t *ipset = &capo_main.ipsets[ipset_id];

  if (pool_is_free (capo_main.ipsets, ipset))
    return 1;

    /* *INDENT-OFF* */
    pool_foreach(m, ipset->members, ({
      if (!memcmp(m, to_delete, sizeof(*m)))
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
