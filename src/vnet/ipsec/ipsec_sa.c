/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vnet/ipsec/ipsec.h>

static clib_error_t *
ipsec_call_add_del_callbacks (ipsec_main_t * im, ipsec_sa_t * sa,
			      u32 sa_index, int is_add)
{
  ipsec_ah_backend_t *ab;
  ipsec_esp_backend_t *eb;
  switch (sa->protocol)
    {
    case IPSEC_PROTOCOL_AH:
      ab = pool_elt_at_index (im->ah_backends, im->ah_current_backend);
      if (ab->add_del_sa_sess_cb)
	return ab->add_del_sa_sess_cb (sa_index, is_add);
      break;
    case IPSEC_PROTOCOL_ESP:
      eb = pool_elt_at_index (im->esp_backends, im->esp_current_backend);
      if (eb->add_del_sa_sess_cb)
	return eb->add_del_sa_sess_cb (sa_index, is_add);
      break;
    }
  return 0;
}

int
ipsec_add_del_sa (vlib_main_t * vm, ipsec_sa_t * new_sa, int is_add)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_sa_t *sa = 0;
  uword *p;
  u32 sa_index;
  clib_error_t *err;

  clib_warning ("id %u spi %u", new_sa->id, new_sa->spi);

  p = hash_get (im->sa_index_by_sa_id, new_sa->id);
  if (p && is_add)
    return VNET_API_ERROR_ENTRY_ALREADY_EXISTS;
  if (!p && !is_add)
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  if (!is_add)			/* delete */
    {
      sa_index = p[0];
      sa = pool_elt_at_index (im->sad, sa_index);
      if (ipsec_is_sa_used (sa_index))
	{
	  clib_warning ("sa_id %u used in policy", sa->id);
	  return VNET_API_ERROR_SYSCALL_ERROR_1;	/* sa used in policy */
	}
      hash_unset (im->sa_index_by_sa_id, sa->id);
      err = ipsec_call_add_del_callbacks (im, sa, sa_index, 0);
      if (err)
	return VNET_API_ERROR_SYSCALL_ERROR_1;
      pool_put (im->sad, sa);
    }
  else				/* create new SA */
    {
      pool_get (im->sad, sa);
      clib_memcpy (sa, new_sa, sizeof (*sa));
      sa_index = sa - im->sad;
      hash_set (im->sa_index_by_sa_id, sa->id, sa_index);
      err = ipsec_call_add_del_callbacks (im, sa, sa_index, 1);
      if (err)
	return VNET_API_ERROR_SYSCALL_ERROR_1;
    }
  return 0;
}

u8
ipsec_is_sa_used (u32 sa_index)
{
  ipsec_main_t *im = &ipsec_main;
  ipsec_spd_t *spd;
  ipsec_policy_t *p;
  ipsec_tunnel_if_t *t;

  /* *INDENT-OFF* */
  pool_foreach(spd, im->spds, ({
    pool_foreach(p, spd->policies, ({
      if (p->policy == IPSEC_POLICY_ACTION_PROTECT)
        {
          if (p->sa_index == sa_index)
            return 1;
        }
    }));
  }));

  pool_foreach(t, im->tunnel_interfaces, ({
    if (t->input_sa_index == sa_index)
      return 1;
    if (t->output_sa_index == sa_index)
      return 1;
  }));
  /* *INDENT-ON* */

  return 0;
}

int
ipsec_set_sa_key (vlib_main_t * vm, ipsec_sa_t * sa_update)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p;
  u32 sa_index;
  ipsec_sa_t *sa = 0;
  clib_error_t *err;

  p = hash_get (im->sa_index_by_sa_id, sa_update->id);
  if (!p)
    return VNET_API_ERROR_SYSCALL_ERROR_1;	/* no such sa-id */

  sa_index = p[0];
  sa = pool_elt_at_index (im->sad, sa_index);

  /* new crypto key */
  if (0 < sa_update->crypto_key_len)
    {
      clib_memcpy (sa->crypto_key, sa_update->crypto_key,
		   sa_update->crypto_key_len);
      sa->crypto_key_len = sa_update->crypto_key_len;
    }

  /* new integ key */
  if (0 < sa_update->integ_key_len)
    {
      clib_memcpy (sa->integ_key, sa_update->integ_key,
		   sa_update->integ_key_len);
      sa->integ_key_len = sa_update->integ_key_len;
    }

  if (0 < sa_update->crypto_key_len || 0 < sa_update->integ_key_len)
    {
      err = ipsec_call_add_del_callbacks (im, sa, sa_index, 0);
      if (err)
	return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  return 0;
}

u32
ipsec_get_sa_index_by_sa_id (u32 sa_id)
{
  ipsec_main_t *im = &ipsec_main;
  uword *p = hash_get (im->sa_index_by_sa_id, sa_id);
  if (!p)
    return ~0;

  return p[0];
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
