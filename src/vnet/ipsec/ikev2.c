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

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <vppinfra/random.h>
#include <vnet/udp/udp.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ikev2.h>
#include <vnet/ipsec/ikev2_priv.h>
#include <openssl/sha.h>

ikev2_main_t ikev2_main;

static int ikev2_delete_tunnel_interface (vnet_main_t * vnm,
					  ikev2_sa_t * sa,
					  ikev2_child_sa_t * child);

#define ikev2_set_state(sa, v) do { \
    (sa)->state = v; \
    clib_warning("sa state changed to " #v); \
  } while(0);

typedef struct
{
  u32 next_index;
  u32 sw_if_index;
} ikev2_trace_t;

static u8 *
format_ikev2_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ikev2_trace_t *t = va_arg (*args, ikev2_trace_t *);

  s = format (s, "ikev2: sw_if_index %d, next index %d",
	      t->sw_if_index, t->next_index);
  return s;
}

static vlib_node_registration_t ikev2_node;

#define foreach_ikev2_error \
_(PROCESSED, "IKEv2 packets processed") \
_(IKE_SA_INIT_RETRANSMIT, "IKE_SA_INIT retransmit ") \
_(IKE_SA_INIT_IGNORE, "IKE_SA_INIT ignore (IKE SA already auth)") \
_(IKE_REQ_RETRANSMIT, "IKE request retransmit") \
_(IKE_REQ_IGNORE, "IKE request ignore (old msgid)") \
_(NOT_IKEV2, "Non IKEv2 packets received")

typedef enum
{
#define _(sym,str) IKEV2_ERROR_##sym,
  foreach_ikev2_error
#undef _
    IKEV2_N_ERROR,
} ikev2_error_t;

static char *ikev2_error_strings[] = {
#define _(sym,string) string,
  foreach_ikev2_error
#undef _
};

typedef enum
{
  IKEV2_NEXT_IP4_LOOKUP,
  IKEV2_NEXT_ERROR_DROP,
  IKEV2_N_NEXT,
} ikev2_next_t;

static ikev2_sa_transform_t *
ikev2_find_transform_data (ikev2_sa_transform_t * t)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_sa_transform_t *td;

  vec_foreach (td, km->supported_transforms)
  {
    if (td->type != t->type)
      continue;

    if (td->transform_id != t->transform_id)
      continue;

    if (td->type == IKEV2_TRANSFORM_TYPE_ENCR)
      {
	if (vec_len (t->attrs) != 4 || t->attrs[0] != 0x80
	    || t->attrs[1] != 14)
	  continue;

	if (((t->attrs[2] << 8 | t->attrs[3]) / 8) != td->key_len)
	  continue;
      }
    return td;
  }
  return 0;
}

static ikev2_sa_proposal_t *
ikev2_select_proposal (ikev2_sa_proposal_t * proposals,
		       ikev2_protocol_id_t prot_id)
{
  ikev2_sa_proposal_t *rv = 0;
  ikev2_sa_proposal_t *proposal;
  ikev2_sa_transform_t *transform, *new_t;
  u8 mandatory_bitmap, optional_bitmap;

  if (prot_id == IKEV2_PROTOCOL_IKE)
    {
      mandatory_bitmap = (1 << IKEV2_TRANSFORM_TYPE_ENCR) |
	(1 << IKEV2_TRANSFORM_TYPE_PRF) |
	(1 << IKEV2_TRANSFORM_TYPE_INTEG) | (1 << IKEV2_TRANSFORM_TYPE_DH);
      optional_bitmap = mandatory_bitmap;
    }
  else if (prot_id == IKEV2_PROTOCOL_ESP)
    {
      mandatory_bitmap = (1 << IKEV2_TRANSFORM_TYPE_ENCR) |
	(1 << IKEV2_TRANSFORM_TYPE_ESN);
      optional_bitmap = mandatory_bitmap |
	(1 << IKEV2_TRANSFORM_TYPE_INTEG) | (1 << IKEV2_TRANSFORM_TYPE_DH);
    }
  else if (prot_id == IKEV2_PROTOCOL_AH)
    {
      mandatory_bitmap = (1 << IKEV2_TRANSFORM_TYPE_INTEG) |
	(1 << IKEV2_TRANSFORM_TYPE_ESN);
      optional_bitmap = mandatory_bitmap | (1 << IKEV2_TRANSFORM_TYPE_DH);
    }
  else
    return 0;

  vec_add2 (rv, proposal, 1);

  vec_foreach (proposal, proposals)
  {
    u8 bitmap = 0;
    if (proposal->protocol_id != prot_id)
      continue;

    vec_foreach (transform, proposal->transforms)
    {
      if ((1 << transform->type) & bitmap)
	continue;

      if (ikev2_find_transform_data (transform))
	{
	  bitmap |= 1 << transform->type;
	  vec_add2 (rv->transforms, new_t, 1);
	  clib_memcpy (new_t, transform, sizeof (*new_t));
	  new_t->attrs = vec_dup (transform->attrs);
	}
    }

    clib_warning ("bitmap is %x mandatory is %x optional is %x",
		  bitmap, mandatory_bitmap, optional_bitmap);

    if ((bitmap & mandatory_bitmap) == mandatory_bitmap &&
	(bitmap & ~optional_bitmap) == 0)
      {
	rv->proposal_num = proposal->proposal_num;
	rv->protocol_id = proposal->protocol_id;
	RAND_bytes ((u8 *) & rv->spi, sizeof (rv->spi));
	goto done;
      }
    else
      {
	vec_free (rv->transforms);
      }
  }

  vec_free (rv);
done:
  return rv;
}

ikev2_sa_transform_t *
ikev2_sa_get_td_for_type (ikev2_sa_proposal_t * p,
			  ikev2_transform_type_t type)
{
  ikev2_sa_transform_t *t;

  if (!p)
    return 0;

  vec_foreach (t, p->transforms)
  {
    if (t->type == type)
      return ikev2_find_transform_data (t);
  }
  return 0;
}

ikev2_child_sa_t *
ikev2_sa_get_child (ikev2_sa_t * sa, u32 spi, ikev2_protocol_id_t prot_id,
		    int by_initiator)
{
  ikev2_child_sa_t *c;
  vec_foreach (c, sa->childs)
  {
    ikev2_sa_proposal_t *proposal =
      by_initiator ? &c->i_proposals[0] : &c->r_proposals[0];
    if (proposal && proposal->spi == spi && proposal->protocol_id == prot_id)
      return c;
  }

  return 0;
}

void
ikev2_sa_free_proposal_vector (ikev2_sa_proposal_t ** v)
{
  ikev2_sa_proposal_t *p;
  ikev2_sa_transform_t *t;

  if (!*v)
    return;

  vec_foreach (p, *v)
  {
    vec_foreach (t, p->transforms)
    {
      vec_free (t->attrs);
    }
    vec_free (p->transforms);
  }
  vec_free (*v);
};

static void
ikev2_sa_free_all_child_sa (ikev2_child_sa_t ** childs)
{
  ikev2_child_sa_t *c;
  vec_foreach (c, *childs)
  {
    ikev2_sa_free_proposal_vector (&c->r_proposals);
    ikev2_sa_free_proposal_vector (&c->i_proposals);
    vec_free (c->sk_ai);
    vec_free (c->sk_ar);
    vec_free (c->sk_ei);
    vec_free (c->sk_er);
  }

  vec_free (*childs);
}

static void
ikev2_sa_del_child_sa (ikev2_sa_t * sa, ikev2_child_sa_t * child)
{
  ikev2_sa_free_proposal_vector (&child->r_proposals);
  ikev2_sa_free_proposal_vector (&child->i_proposals);
  vec_free (child->sk_ai);
  vec_free (child->sk_ar);
  vec_free (child->sk_ei);
  vec_free (child->sk_er);

  vec_del1 (sa->childs, child - sa->childs);
}

static void
ikev2_sa_free_all_vec (ikev2_sa_t * sa)
{
  vec_free (sa->i_nonce);
  vec_free (sa->i_dh_data);
  vec_free (sa->dh_shared_key);
  vec_free (sa->dh_private_key);

  ikev2_sa_free_proposal_vector (&sa->r_proposals);
  ikev2_sa_free_proposal_vector (&sa->i_proposals);

  vec_free (sa->sk_d);
  vec_free (sa->sk_ai);
  vec_free (sa->sk_ar);
  vec_free (sa->sk_ei);
  vec_free (sa->sk_er);
  vec_free (sa->sk_pi);
  vec_free (sa->sk_pr);

  vec_free (sa->i_id.data);
  vec_free (sa->i_auth.data);
  vec_free (sa->r_id.data);
  vec_free (sa->r_auth.data);
  if (sa->r_auth.key)
    EVP_PKEY_free (sa->r_auth.key);

  vec_free (sa->del);

  ikev2_sa_free_all_child_sa (&sa->childs);
}

static void
ikev2_delete_sa (ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  u32 thread_index = vlib_get_thread_index ();
  uword *p;

  ikev2_sa_free_all_vec (sa);

  p = hash_get (km->per_thread_data[thread_index].sa_by_rspi, sa->rspi);
  if (p)
    {
      hash_unset (km->per_thread_data[thread_index].sa_by_rspi, sa->rspi);
      pool_put (km->per_thread_data[thread_index].sas, sa);
    }
}

static void
ikev2_generate_sa_init_data (ikev2_sa_t * sa)
{
  ikev2_sa_transform_t *t = 0, *t2;
  ikev2_main_t *km = &ikev2_main;

  if (sa->dh_group == IKEV2_TRANSFORM_DH_TYPE_NONE)
    {
      return;
    }

  /* check if received DH group is on our list of supported groups */
  vec_foreach (t2, km->supported_transforms)
  {
    if (t2->type == IKEV2_TRANSFORM_TYPE_DH && sa->dh_group == t2->dh_type)
      {
	t = t2;
	break;
      }
  }

  if (!t)
    {
      clib_warning ("unknown dh data group %u (data len %u)", sa->dh_group,
		    vec_len (sa->i_dh_data));
      sa->dh_group = IKEV2_TRANSFORM_DH_TYPE_NONE;
      return;
    }

  if (sa->is_initiator)
    {
      /* generate rspi */
      RAND_bytes ((u8 *) & sa->ispi, 8);

      /* generate nonce */
      sa->i_nonce = vec_new (u8, IKEV2_NONCE_SIZE);
      RAND_bytes ((u8 *) sa->i_nonce, IKEV2_NONCE_SIZE);
    }
  else
    {
      /* generate rspi */
      RAND_bytes ((u8 *) & sa->rspi, 8);

      /* generate nonce */
      sa->r_nonce = vec_new (u8, IKEV2_NONCE_SIZE);
      RAND_bytes ((u8 *) sa->r_nonce, IKEV2_NONCE_SIZE);
    }

  /* generate dh keys */
  ikev2_generate_dh (sa, t);

}

static void
ikev2_complete_sa_data (ikev2_sa_t * sa, ikev2_sa_t * sai)
{
  ikev2_sa_transform_t *t = 0, *t2;
  ikev2_main_t *km = &ikev2_main;


  /*move some data to the new SA */
#define _(A) ({void* __tmp__ = (A); (A) = 0; __tmp__;})
  sa->i_nonce = _(sai->i_nonce);
  sa->i_dh_data = _(sai->i_dh_data);
  sa->dh_private_key = _(sai->dh_private_key);
  sa->iaddr.as_u32 = sai->iaddr.as_u32;
  sa->raddr.as_u32 = sai->raddr.as_u32;
  sa->is_initiator = sai->is_initiator;
  sa->profile = sai->profile;
  sa->i_id.type = sai->i_id.type;
  sa->i_id.data = _(sai->i_id.data);
  sa->i_auth.method = sai->i_auth.method;
  sa->i_auth.hex = sai->i_auth.hex;
  sa->i_auth.data = _(sai->i_auth.data);
  sa->i_auth.key = _(sai->i_auth.key);
  sa->last_sa_init_req_packet_data = _(sai->last_sa_init_req_packet_data);
  sa->childs = _(sai->childs);
#undef _


  if (sa->dh_group == IKEV2_TRANSFORM_DH_TYPE_NONE)
    {
      return;
    }

  /* check if received DH group is on our list of supported groups */
  vec_foreach (t2, km->supported_transforms)
  {
    if (t2->type == IKEV2_TRANSFORM_TYPE_DH && sa->dh_group == t2->dh_type)
      {
	t = t2;
	break;
      }
  }

  if (!t)
    {
      clib_warning ("unknown dh data group %u (data len %u)", sa->dh_group,
		    vec_len (sa->i_dh_data));
      sa->dh_group = IKEV2_TRANSFORM_DH_TYPE_NONE;
      return;
    }


  /* generate dh keys */
  ikev2_complete_dh (sa, t);

}

static void
ikev2_calc_keys (ikev2_sa_t * sa)
{
  u8 *tmp;
  /* calculate SKEYSEED = prf(Ni | Nr, g^ir) */
  u8 *skeyseed = 0;
  u8 *s = 0;
  ikev2_sa_transform_t *tr_encr, *tr_prf, *tr_integ;
  tr_encr =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  tr_prf =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);
  tr_integ =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);

  vec_append (s, sa->i_nonce);
  vec_append (s, sa->r_nonce);
  skeyseed = ikev2_calc_prf (tr_prf, s, sa->dh_shared_key);

  /* Calculate S = Ni | Nr | SPIi | SPIr */
  u64 *spi;
  vec_add2 (s, tmp, 2 * sizeof (*spi));
  spi = (u64 *) tmp;
  spi[0] = clib_host_to_net_u64 (sa->ispi);
  spi[1] = clib_host_to_net_u64 (sa->rspi);

  /* calculate PRFplus */
  u8 *keymat;
  int len = tr_prf->key_trunc +	/* SK_d */
    tr_integ->key_len * 2 +	/* SK_ai, SK_ar */
    tr_encr->key_len * 2 +	/* SK_ei, SK_er */
    tr_prf->key_len * 2;	/* SK_pi, SK_pr */

  keymat = ikev2_calc_prfplus (tr_prf, skeyseed, s, len);
  vec_free (skeyseed);
  vec_free (s);

  int pos = 0;

  /* SK_d */
  sa->sk_d = vec_new (u8, tr_prf->key_trunc);
  clib_memcpy (sa->sk_d, keymat + pos, tr_prf->key_trunc);
  pos += tr_prf->key_trunc;

  /* SK_ai */
  sa->sk_ai = vec_new (u8, tr_integ->key_len);
  clib_memcpy (sa->sk_ai, keymat + pos, tr_integ->key_len);
  pos += tr_integ->key_len;

  /* SK_ar */
  sa->sk_ar = vec_new (u8, tr_integ->key_len);
  clib_memcpy (sa->sk_ar, keymat + pos, tr_integ->key_len);
  pos += tr_integ->key_len;

  /* SK_ei */
  sa->sk_ei = vec_new (u8, tr_encr->key_len);
  clib_memcpy (sa->sk_ei, keymat + pos, tr_encr->key_len);
  pos += tr_encr->key_len;

  /* SK_er */
  sa->sk_er = vec_new (u8, tr_encr->key_len);
  clib_memcpy (sa->sk_er, keymat + pos, tr_encr->key_len);
  pos += tr_encr->key_len;

  /* SK_pi */
  sa->sk_pi = vec_new (u8, tr_prf->key_len);
  clib_memcpy (sa->sk_pi, keymat + pos, tr_prf->key_len);
  pos += tr_prf->key_len;

  /* SK_pr */
  sa->sk_pr = vec_new (u8, tr_prf->key_len);
  clib_memcpy (sa->sk_pr, keymat + pos, tr_prf->key_len);
  pos += tr_prf->key_len;

  vec_free (keymat);
}

static void
ikev2_calc_child_keys (ikev2_sa_t * sa, ikev2_child_sa_t * child)
{
  u8 *s = 0;
  ikev2_sa_transform_t *tr_prf, *ctr_encr, *ctr_integ;
  tr_prf =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);
  ctr_encr =
    ikev2_sa_get_td_for_type (child->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  ctr_integ =
    ikev2_sa_get_td_for_type (child->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);

  vec_append (s, sa->i_nonce);
  vec_append (s, sa->r_nonce);
  /* calculate PRFplus */
  u8 *keymat;
  int len = ctr_encr->key_len * 2 + ctr_integ->key_len * 2;

  keymat = ikev2_calc_prfplus (tr_prf, sa->sk_d, s, len);

  int pos = 0;

  /* SK_ei */
  child->sk_ei = vec_new (u8, ctr_encr->key_len);
  clib_memcpy (child->sk_ei, keymat + pos, ctr_encr->key_len);
  pos += ctr_encr->key_len;

  /* SK_ai */
  child->sk_ai = vec_new (u8, ctr_integ->key_len);
  clib_memcpy (child->sk_ai, keymat + pos, ctr_integ->key_len);
  pos += ctr_integ->key_len;

  /* SK_er */
  child->sk_er = vec_new (u8, ctr_encr->key_len);
  clib_memcpy (child->sk_er, keymat + pos, ctr_encr->key_len);
  pos += ctr_encr->key_len;

  /* SK_ar */
  child->sk_ar = vec_new (u8, ctr_integ->key_len);
  clib_memcpy (child->sk_ar, keymat + pos, ctr_integ->key_len);
  pos += ctr_integ->key_len;

  ASSERT (pos == len);

  vec_free (keymat);
}

static void
ikev2_process_sa_init_req (vlib_main_t * vm, ikev2_sa_t * sa,
			   ike_header_t * ike)
{
  int p = 0;
  u32 len = clib_net_to_host_u32 (ike->length);
  u8 payload = ike->nextpayload;

  clib_warning ("ispi %lx rspi %lx nextpayload %x version %x "
		"exchange %x flags %x msgid %x length %u",
		clib_net_to_host_u64 (ike->ispi),
		clib_net_to_host_u64 (ike->rspi),
		payload, ike->version,
		ike->exchange, ike->flags,
		clib_net_to_host_u32 (ike->msgid), len);

  sa->ispi = clib_net_to_host_u64 (ike->ispi);

  /* store whole IKE payload - needed for PSK auth */
  vec_free (sa->last_sa_init_req_packet_data);
  vec_add (sa->last_sa_init_req_packet_data, ike, len);

  while (p < len && payload != IKEV2_PAYLOAD_NONE)
    {
      ike_payload_header_t *ikep = (ike_payload_header_t *) & ike->payload[p];
      u32 plen = clib_net_to_host_u16 (ikep->length);

      if (plen < sizeof (ike_payload_header_t))
	return;

      if (payload == IKEV2_PAYLOAD_SA)
	{
	  ikev2_sa_free_proposal_vector (&sa->i_proposals);
	  sa->i_proposals = ikev2_parse_sa_payload (ikep);
	}
      else if (payload == IKEV2_PAYLOAD_KE)
	{
	  ike_ke_payload_header_t *ke = (ike_ke_payload_header_t *) ikep;
	  sa->dh_group = clib_net_to_host_u16 (ke->dh_group);
	  vec_free (sa->i_dh_data);
	  vec_add (sa->i_dh_data, ke->payload, plen - sizeof (*ke));
	}
      else if (payload == IKEV2_PAYLOAD_NONCE)
	{
	  vec_free (sa->i_nonce);
	  vec_add (sa->i_nonce, ikep->payload, plen - sizeof (*ikep));
	}
      else if (payload == IKEV2_PAYLOAD_NOTIFY)
	{
	  ikev2_notify_t *n = ikev2_parse_notify_payload (ikep);
	  vec_free (n);
	}
      else if (payload == IKEV2_PAYLOAD_VENDOR)
	{
	  ikev2_parse_vendor_payload (ikep);
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u", payload,
			ikep->flags, plen);
	  if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
	    {
	      ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
	      sa->unsupported_cp = payload;
	      return;
	    }
	}

      payload = ikep->nextpayload;
      p += plen;
    }

  ikev2_set_state (sa, IKEV2_STATE_SA_INIT);
}

static void
ikev2_process_sa_init_resp (vlib_main_t * vm, ikev2_sa_t * sa,
			    ike_header_t * ike)
{
  int p = 0;
  u32 len = clib_net_to_host_u32 (ike->length);
  u8 payload = ike->nextpayload;

  clib_warning ("ispi %lx rspi %lx nextpayload %x version %x "
		"exchange %x flags %x msgid %x length %u",
		clib_net_to_host_u64 (ike->ispi),
		clib_net_to_host_u64 (ike->rspi),
		payload, ike->version,
		ike->exchange, ike->flags,
		clib_net_to_host_u32 (ike->msgid), len);

  sa->ispi = clib_net_to_host_u64 (ike->ispi);
  sa->rspi = clib_net_to_host_u64 (ike->rspi);

  /* store whole IKE payload - needed for PSK auth */
  vec_free (sa->last_sa_init_res_packet_data);
  vec_add (sa->last_sa_init_res_packet_data, ike, len);

  while (p < len && payload != IKEV2_PAYLOAD_NONE)
    {
      ike_payload_header_t *ikep = (ike_payload_header_t *) & ike->payload[p];
      u32 plen = clib_net_to_host_u16 (ikep->length);

      if (plen < sizeof (ike_payload_header_t))
	return;

      if (payload == IKEV2_PAYLOAD_SA)
	{
	  ikev2_sa_free_proposal_vector (&sa->r_proposals);
	  sa->r_proposals = ikev2_parse_sa_payload (ikep);
	  if (sa->r_proposals)
	    {
	      ikev2_set_state (sa, IKEV2_STATE_SA_INIT);
	      ike->msgid =
		clib_host_to_net_u32 (clib_net_to_host_u32 (ike->msgid) + 1);
	    }
	}
      else if (payload == IKEV2_PAYLOAD_KE)
	{
	  ike_ke_payload_header_t *ke = (ike_ke_payload_header_t *) ikep;
	  sa->dh_group = clib_net_to_host_u16 (ke->dh_group);
	  vec_free (sa->r_dh_data);
	  vec_add (sa->r_dh_data, ke->payload, plen - sizeof (*ke));
	}
      else if (payload == IKEV2_PAYLOAD_NONCE)
	{
	  vec_free (sa->r_nonce);
	  vec_add (sa->r_nonce, ikep->payload, plen - sizeof (*ikep));
	}
      else if (payload == IKEV2_PAYLOAD_NOTIFY)
	{
	  ikev2_notify_t *n = ikev2_parse_notify_payload (ikep);
	  vec_free (n);
	}
      else if (payload == IKEV2_PAYLOAD_VENDOR)
	{
	  ikev2_parse_vendor_payload (ikep);
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u", payload,
			ikep->flags, plen);
	  if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
	    {
	      ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
	      sa->unsupported_cp = payload;
	      return;
	    }
	}

      payload = ikep->nextpayload;
      p += plen;
    }
}

static u8 *
ikev2_decrypt_sk_payload (ikev2_sa_t * sa, ike_header_t * ike, u8 * payload)
{
  int p = 0;
  u8 last_payload = 0;
  u8 *hmac = 0;
  u32 len = clib_net_to_host_u32 (ike->length);
  ike_payload_header_t *ikep = 0;
  u32 plen = 0;
  ikev2_sa_transform_t *tr_integ;
  tr_integ =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);

  while (p < len &&
	 *payload != IKEV2_PAYLOAD_NONE && last_payload != IKEV2_PAYLOAD_SK)
    {
      ikep = (ike_payload_header_t *) & ike->payload[p];
      plen = clib_net_to_host_u16 (ikep->length);

      if (plen < sizeof (*ikep))
	return 0;

      if (*payload == IKEV2_PAYLOAD_SK)
	{
	  clib_warning ("received IKEv2 payload SK, len %u", plen - 4);
	  last_payload = *payload;
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u", payload,
			ikep->flags, plen);
	  if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
	    {
	      sa->unsupported_cp = *payload;
	      return 0;
	    }
	}

      *payload = ikep->nextpayload;
      p += plen;
    }

  if (last_payload != IKEV2_PAYLOAD_SK)
    {
      clib_warning ("Last payload must be SK");
      return 0;
    }

  hmac =
    ikev2_calc_integr (tr_integ, sa->is_initiator ? sa->sk_ar : sa->sk_ai,
		       (u8 *) ike, len - tr_integ->key_trunc);

  plen = plen - sizeof (*ikep) - tr_integ->key_trunc;

  if (memcmp (hmac, &ikep->payload[plen], tr_integ->key_trunc))
    {
      clib_warning ("message integrity check failed");
      vec_free (hmac);
      return 0;
    }
  vec_free (hmac);

  return ikev2_decrypt_data (sa, ikep->payload, plen);
}

static void
ikev2_initial_contact_cleanup (ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_sa_t *tmp;
  u32 i, *delete = 0;
  ikev2_child_sa_t *c;
  u32 thread_index = vlib_get_thread_index ();

  if (!sa->initial_contact)
    return;

  /* find old IKE SAs with the same authenticated identity */
  /* *INDENT-OFF* */
  pool_foreach (tmp, km->per_thread_data[thread_index].sas, ({
        if (tmp->i_id.type != sa->i_id.type ||
            vec_len(tmp->i_id.data) != vec_len(sa->i_id.data) ||
            memcmp(sa->i_id.data, tmp->i_id.data, vec_len(sa->i_id.data)))
          continue;

        if (sa->rspi != tmp->rspi)
          vec_add1(delete, tmp - km->per_thread_data[thread_index].sas);
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (delete); i++)
    {
      tmp =
	pool_elt_at_index (km->per_thread_data[thread_index].sas, delete[i]);
      vec_foreach (c,
		   tmp->childs) ikev2_delete_tunnel_interface (km->vnet_main,
							       tmp, c);
      ikev2_delete_sa (tmp);
    }

  vec_free (delete);
  sa->initial_contact = 0;
}

static void
ikev2_process_auth_req (vlib_main_t * vm, ikev2_sa_t * sa, ike_header_t * ike)
{
  ikev2_child_sa_t *first_child_sa;
  int p = 0;
  u32 len = clib_net_to_host_u32 (ike->length);
  u8 payload = ike->nextpayload;
  u8 *plaintext = 0;

  ike_payload_header_t *ikep;
  u32 plen;

  clib_warning ("ispi %lx rspi %lx nextpayload %x version %x "
		"exchange %x flags %x msgid %x length %u",
		clib_net_to_host_u64 (ike->ispi),
		clib_net_to_host_u64 (ike->rspi),
		payload, ike->version,
		ike->exchange, ike->flags,
		clib_net_to_host_u32 (ike->msgid), len);

  ikev2_calc_keys (sa);

  plaintext = ikev2_decrypt_sk_payload (sa, ike, &payload);

  if (!plaintext)
    {
      if (sa->unsupported_cp)
	ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
      goto cleanup_and_exit;
    }

  /* select or create 1st child SA */
  if (sa->is_initiator)
    {
      first_child_sa = &sa->childs[0];
    }
  else
    {
      ikev2_sa_free_all_child_sa (&sa->childs);
      vec_add2 (sa->childs, first_child_sa, 1);
    }


  /* process encrypted payload */
  p = 0;
  while (p < vec_len (plaintext) && payload != IKEV2_PAYLOAD_NONE)
    {
      ikep = (ike_payload_header_t *) & plaintext[p];
      plen = clib_net_to_host_u16 (ikep->length);

      if (plen < sizeof (ike_payload_header_t))
	goto cleanup_and_exit;

      if (payload == IKEV2_PAYLOAD_SA)	/* 33 */
	{
	  clib_warning ("received payload SA, len %u", plen - sizeof (*ikep));
	  if (sa->is_initiator)
	    {
	      ikev2_sa_free_proposal_vector (&first_child_sa->r_proposals);
	      first_child_sa->r_proposals = ikev2_parse_sa_payload (ikep);
	    }
	  else
	    {
	      ikev2_sa_free_proposal_vector (&first_child_sa->i_proposals);
	      first_child_sa->i_proposals = ikev2_parse_sa_payload (ikep);
	    }
	}
      else if (payload == IKEV2_PAYLOAD_IDI)	/* 35 */
	{
	  ike_id_payload_header_t *id = (ike_id_payload_header_t *) ikep;

	  sa->i_id.type = id->id_type;
	  vec_free (sa->i_id.data);
	  vec_add (sa->i_id.data, id->payload, plen - sizeof (*id));

	  clib_warning ("received payload IDi, len %u id_type %u",
			plen - sizeof (*id), id->id_type);
	}
      else if (payload == IKEV2_PAYLOAD_IDR)	/* 36 */
	{
	  ike_id_payload_header_t *id = (ike_id_payload_header_t *) ikep;

	  sa->r_id.type = id->id_type;
	  vec_free (sa->r_id.data);
	  vec_add (sa->r_id.data, id->payload, plen - sizeof (*id));

	  clib_warning ("received payload IDr len %u id_type %u",
			plen - sizeof (*id), id->id_type);
	}
      else if (payload == IKEV2_PAYLOAD_AUTH)	/* 39 */
	{
	  ike_auth_payload_header_t *a = (ike_auth_payload_header_t *) ikep;

	  if (sa->is_initiator)
	    {
	      sa->r_auth.method = a->auth_method;
	      vec_free (sa->r_auth.data);
	      vec_add (sa->r_auth.data, a->payload, plen - sizeof (*a));
	    }
	  else
	    {
	      sa->i_auth.method = a->auth_method;
	      vec_free (sa->i_auth.data);
	      vec_add (sa->i_auth.data, a->payload, plen - sizeof (*a));
	    }

	  clib_warning ("received payload AUTH, len %u auth_type %u",
			plen - sizeof (*a), a->auth_method);
	}
      else if (payload == IKEV2_PAYLOAD_NOTIFY)	/* 41 */
	{
	  ikev2_notify_t *n = ikev2_parse_notify_payload (ikep);
	  if (n->msg_type == IKEV2_NOTIFY_MSG_INITIAL_CONTACT)
	    {
	      sa->initial_contact = 1;
	    }
	  vec_free (n);
	}
      else if (payload == IKEV2_PAYLOAD_VENDOR)	/* 43 */
	{
	  ikev2_parse_vendor_payload (ikep);
	}
      else if (payload == IKEV2_PAYLOAD_TSI)	/* 44 */
	{
	  clib_warning ("received payload TSi, len %u",
			plen - sizeof (*ikep));

	  vec_free (first_child_sa->tsi);
	  first_child_sa->tsi = ikev2_parse_ts_payload (ikep);
	}
      else if (payload == IKEV2_PAYLOAD_TSR)	/* 45 */
	{
	  clib_warning ("received payload TSr, len %u",
			plen - sizeof (*ikep));

	  vec_free (first_child_sa->tsr);
	  first_child_sa->tsr = ikev2_parse_ts_payload (ikep);
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u data %u",
			payload, ikep->flags, plen - 4,
			format_hex_bytes, ikep->payload, plen - 4);

	  if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
	    {
	      ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
	      sa->unsupported_cp = payload;
	      return;
	    }
	}

      payload = ikep->nextpayload;
      p += plen;
    }

cleanup_and_exit:
  vec_free (plaintext);
}

static void
ikev2_process_informational_req (vlib_main_t * vm, ikev2_sa_t * sa,
				 ike_header_t * ike)
{
  int p = 0;
  u32 len = clib_net_to_host_u32 (ike->length);
  u8 payload = ike->nextpayload;
  u8 *plaintext = 0;

  ike_payload_header_t *ikep;
  u32 plen;

  clib_warning ("ispi %lx rspi %lx nextpayload %x version %x "
		"exchange %x flags %x msgid %x length %u",
		clib_net_to_host_u64 (ike->ispi),
		clib_net_to_host_u64 (ike->rspi),
		payload, ike->version,
		ike->exchange, ike->flags,
		clib_net_to_host_u32 (ike->msgid), len);

  plaintext = ikev2_decrypt_sk_payload (sa, ike, &payload);

  if (!plaintext)
    goto cleanup_and_exit;

  /* process encrypted payload */
  p = 0;
  while (p < vec_len (plaintext) && payload != IKEV2_PAYLOAD_NONE)
    {
      ikep = (ike_payload_header_t *) & plaintext[p];
      plen = clib_net_to_host_u16 (ikep->length);

      if (plen < sizeof (ike_payload_header_t))
	goto cleanup_and_exit;

      if (payload == IKEV2_PAYLOAD_NOTIFY)	/* 41 */
	{
	  ikev2_notify_t *n = ikev2_parse_notify_payload (ikep);
	  if (n->msg_type == IKEV2_NOTIFY_MSG_AUTHENTICATION_FAILED)
	    ikev2_set_state (sa, IKEV2_STATE_AUTH_FAILED);
	  vec_free (n);
	}
      else if (payload == IKEV2_PAYLOAD_DELETE)	/* 42 */
	{
	  sa->del = ikev2_parse_delete_payload (ikep);
	}
      else if (payload == IKEV2_PAYLOAD_VENDOR)	/* 43 */
	{
	  ikev2_parse_vendor_payload (ikep);
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u data %u",
			payload, ikep->flags, plen - 4,
			format_hex_bytes, ikep->payload, plen - 4);

	  if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
	    {
	      sa->unsupported_cp = payload;
	      return;
	    }
	}

      payload = ikep->nextpayload;
      p += plen;
    }

cleanup_and_exit:
  vec_free (plaintext);
}

static void
ikev2_process_create_child_sa_req (vlib_main_t * vm, ikev2_sa_t * sa,
				   ike_header_t * ike)
{
  int p = 0;
  u32 len = clib_net_to_host_u32 (ike->length);
  u8 payload = ike->nextpayload;
  u8 *plaintext = 0;
  u8 rekeying = 0;
  u8 nonce[IKEV2_NONCE_SIZE];

  ike_payload_header_t *ikep;
  u32 plen;
  ikev2_notify_t *n = 0;
  ikev2_ts_t *tsi = 0;
  ikev2_ts_t *tsr = 0;
  ikev2_sa_proposal_t *proposal = 0;
  ikev2_child_sa_t *child_sa;

  clib_warning ("ispi %lx rspi %lx nextpayload %x version %x "
		"exchange %x flags %x msgid %x length %u",
		clib_net_to_host_u64 (ike->ispi),
		clib_net_to_host_u64 (ike->rspi),
		payload, ike->version,
		ike->exchange, ike->flags,
		clib_net_to_host_u32 (ike->msgid), len);

  plaintext = ikev2_decrypt_sk_payload (sa, ike, &payload);

  if (!plaintext)
    goto cleanup_and_exit;

  /* process encrypted payload */
  p = 0;
  while (p < vec_len (plaintext) && payload != IKEV2_PAYLOAD_NONE)
    {
      ikep = (ike_payload_header_t *) & plaintext[p];
      plen = clib_net_to_host_u16 (ikep->length);

      if (plen < sizeof (ike_payload_header_t))
	goto cleanup_and_exit;

      else if (payload == IKEV2_PAYLOAD_SA)
	{
	  proposal = ikev2_parse_sa_payload (ikep);
	}
      else if (payload == IKEV2_PAYLOAD_NOTIFY)
	{
	  n = ikev2_parse_notify_payload (ikep);
	  if (n->msg_type == IKEV2_NOTIFY_MSG_REKEY_SA)
	    {
	      rekeying = 1;
	    }
	}
      else if (payload == IKEV2_PAYLOAD_DELETE)
	{
	  sa->del = ikev2_parse_delete_payload (ikep);
	}
      else if (payload == IKEV2_PAYLOAD_VENDOR)
	{
	  ikev2_parse_vendor_payload (ikep);
	}
      else if (payload == IKEV2_PAYLOAD_NONCE)
	{
	  clib_memcpy (nonce, ikep->payload, plen - sizeof (*ikep));
	}
      else if (payload == IKEV2_PAYLOAD_TSI)
	{
	  tsi = ikev2_parse_ts_payload (ikep);
	}
      else if (payload == IKEV2_PAYLOAD_TSR)
	{
	  tsr = ikev2_parse_ts_payload (ikep);
	}
      else
	{
	  clib_warning ("unknown payload %u flags %x length %u data %u",
			payload, ikep->flags, plen - 4,
			format_hex_bytes, ikep->payload, plen - 4);

	  if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
	    {
	      sa->unsupported_cp = payload;
	      return;
	    }
	}

      payload = ikep->nextpayload;
      p += plen;
    }

  if (sa->is_initiator && proposal->protocol_id == IKEV2_PROTOCOL_ESP)
    {
      ikev2_rekey_t *rekey = &sa->rekey[0];
      rekey->protocol_id = proposal->protocol_id;
      rekey->i_proposal =
	ikev2_select_proposal (proposal, IKEV2_PROTOCOL_ESP);
      rekey->i_proposal->spi = rekey->spi;
      rekey->r_proposal = proposal;
      rekey->tsi = tsi;
      rekey->tsr = tsr;
      /* update Nr */
      vec_free (sa->r_nonce);
      vec_add (sa->r_nonce, nonce, IKEV2_NONCE_SIZE);
      child_sa = ikev2_sa_get_child (sa, rekey->ispi, IKEV2_PROTOCOL_ESP, 1);
      if (child_sa)
	{
	  child_sa->rekey_retries = 0;
	}
    }
  else if (rekeying)
    {
      ikev2_rekey_t *rekey;
      child_sa = ikev2_sa_get_child (sa, n->spi, n->protocol_id, 1);
      if (!child_sa)
	{
	  clib_warning ("child SA spi %lx not found", n->spi);
	  goto cleanup_and_exit;
	}
      vec_add2 (sa->rekey, rekey, 1);
      rekey->protocol_id = n->protocol_id;
      rekey->spi = n->spi;
      rekey->i_proposal = proposal;
      rekey->r_proposal =
	ikev2_select_proposal (proposal, IKEV2_PROTOCOL_ESP);
      rekey->tsi = tsi;
      rekey->tsr = tsr;
      /* update Ni */
      vec_free (sa->i_nonce);
      vec_add (sa->i_nonce, nonce, IKEV2_NONCE_SIZE);
      /* generate new Nr */
      vec_free (sa->r_nonce);
      sa->r_nonce = vec_new (u8, IKEV2_NONCE_SIZE);
      RAND_bytes ((u8 *) sa->r_nonce, IKEV2_NONCE_SIZE);
    }

cleanup_and_exit:
  vec_free (plaintext);
  vec_free (n);
}

static u8 *
ikev2_sa_generate_authmsg (ikev2_sa_t * sa, int is_responder)
{
  u8 *authmsg = 0;
  u8 *data;
  u8 *nonce;
  ikev2_id_t *id;
  u8 *key;
  u8 *packet_data;
  ikev2_sa_transform_t *tr_prf;

  tr_prf =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);

  if (is_responder)
    {
      id = &sa->r_id;
      key = sa->sk_pr;
      nonce = sa->i_nonce;
      packet_data = sa->last_sa_init_res_packet_data;
    }
  else
    {
      id = &sa->i_id;
      key = sa->sk_pi;
      nonce = sa->r_nonce;
      packet_data = sa->last_sa_init_req_packet_data;
    }

  data = vec_new (u8, 4);
  data[0] = id->type;
  vec_append (data, id->data);

  u8 *id_hash = ikev2_calc_prf (tr_prf, key, data);
  vec_append (authmsg, packet_data);
  vec_append (authmsg, nonce);
  vec_append (authmsg, id_hash);
  vec_free (id_hash);
  vec_free (data);

  return authmsg;
}

static int
ikev2_ts_cmp (ikev2_ts_t * ts1, ikev2_ts_t * ts2)
{
  if (ts1->ts_type == ts2->ts_type && ts1->protocol_id == ts2->protocol_id &&
      ts1->start_port == ts2->start_port && ts1->end_port == ts2->end_port &&
      ts1->start_addr.as_u32 == ts2->start_addr.as_u32 &&
      ts1->end_addr.as_u32 == ts2->end_addr.as_u32)
    return 1;

  return 0;
}

static void
ikev2_sa_match_ts (ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_profile_t *p;
  ikev2_ts_t *ts, *p_tsi, *p_tsr, *tsi = 0, *tsr = 0;
  ikev2_id_t *id;

  /* *INDENT-OFF* */
  pool_foreach (p, km->profiles, ({

    if (sa->is_initiator)
      {
        p_tsi = &p->loc_ts;
        p_tsr = &p->rem_ts;
        id = &sa->r_id;
      }
    else
      {
        p_tsi = &p->rem_ts;
        p_tsr = &p->loc_ts;
        id = &sa->i_id;
      }

    /* check id */
    if (p->rem_id.type != id->type ||
        vec_len(p->rem_id.data) != vec_len(id->data) ||
        memcmp(p->rem_id.data, id->data, vec_len(p->rem_id.data)))
      continue;

    vec_foreach(ts, sa->childs[0].tsi)
      {
        if (ikev2_ts_cmp(p_tsi, ts))
          {
            tsi = vec_dup(ts);
            break;
          }
      }

    vec_foreach(ts, sa->childs[0].tsr)
      {
        if (ikev2_ts_cmp(p_tsr, ts))
          {
            tsr = vec_dup(ts);
            break;
          }
      }

    break;
  }));
  /* *INDENT-ON* */

  if (tsi && tsr)
    {
      vec_free (sa->childs[0].tsi);
      vec_free (sa->childs[0].tsr);
      sa->childs[0].tsi = tsi;
      sa->childs[0].tsr = tsr;
    }
  else
    {
      vec_free (tsi);
      vec_free (tsr);
      ikev2_set_state (sa, IKEV2_STATE_TS_UNACCEPTABLE);
    }
}

static void
ikev2_sa_auth (ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_profile_t *p, *sel_p = 0;
  u8 *authmsg, *key_pad, *psk = 0, *auth = 0;
  ikev2_sa_transform_t *tr_prf;

  tr_prf =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);

  /* only shared key and rsa signature */
  if (!(sa->i_auth.method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC ||
	sa->i_auth.method == IKEV2_AUTH_METHOD_RSA_SIG))
    {
      clib_warning ("unsupported authentication method %u",
		    sa->i_auth.method);
      ikev2_set_state (sa, IKEV2_STATE_AUTH_FAILED);
      return;
    }

  key_pad = format (0, "%s", IKEV2_KEY_PAD);
  authmsg = ikev2_sa_generate_authmsg (sa, sa->is_initiator);

  ikev2_id_t *sa_id;
  ikev2_auth_t *sa_auth;

  if (sa->is_initiator)
    {
      sa_id = &sa->r_id;
      sa_auth = &sa->r_auth;
    }
  else
    {
      sa_id = &sa->i_id;
      sa_auth = &sa->i_auth;
    }

  /* *INDENT-OFF* */
  pool_foreach (p, km->profiles, ({

    /* check id */
    if (p->rem_id.type != sa_id->type ||
        vec_len(p->rem_id.data) != vec_len(sa_id->data) ||
        memcmp(p->rem_id.data, sa_id->data, vec_len(p->rem_id.data)))
      continue;

    if (sa_auth->method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
      {
        if (!p->auth.data ||
             p->auth.method != IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
          continue;

        psk = ikev2_calc_prf(tr_prf, p->auth.data, key_pad);
        auth = ikev2_calc_prf(tr_prf, psk, authmsg);

        if (!memcmp(auth, sa_auth->data, vec_len(sa_auth->data)))
          {
            ikev2_set_state(sa, IKEV2_STATE_AUTHENTICATED);
            vec_free(auth);
            sel_p = p;
            break;
          }

      }
    else if (sa_auth->method == IKEV2_AUTH_METHOD_RSA_SIG)
      {
        if (p->auth.method != IKEV2_AUTH_METHOD_RSA_SIG)
          continue;

        if (ikev2_verify_sign(p->auth.key, sa_auth->data, authmsg) == 1)
          {
            ikev2_set_state(sa, IKEV2_STATE_AUTHENTICATED);
            sel_p = p;
            break;
          }
      }

    vec_free(auth);
    vec_free(psk);
  }));
  /* *INDENT-ON* */

  vec_free (authmsg);

  if (sa->state == IKEV2_STATE_AUTHENTICATED)
    {
      if (!sa->is_initiator)
	{
	  vec_free (sa->r_id.data);
	  sa->r_id.data = vec_dup (sel_p->loc_id.data);
	  sa->r_id.type = sel_p->loc_id.type;

	  /* generate our auth data */
	  authmsg = ikev2_sa_generate_authmsg (sa, 1);
	  if (sel_p->auth.method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
	    {
	      sa->r_auth.data = ikev2_calc_prf (tr_prf, psk, authmsg);
	      sa->r_auth.method = IKEV2_AUTH_METHOD_SHARED_KEY_MIC;
	    }
	  else if (sel_p->auth.method == IKEV2_AUTH_METHOD_RSA_SIG)
	    {
	      sa->r_auth.data = ikev2_calc_sign (km->pkey, authmsg);
	      sa->r_auth.method = IKEV2_AUTH_METHOD_RSA_SIG;
	    }
	  vec_free (authmsg);

	  /* select transforms for 1st child sa */
	  ikev2_sa_free_proposal_vector (&sa->childs[0].r_proposals);
	  sa->childs[0].r_proposals =
	    ikev2_select_proposal (sa->childs[0].i_proposals,
				   IKEV2_PROTOCOL_ESP);
	}
    }
  else
    {
      ikev2_set_state (sa, IKEV2_STATE_AUTH_FAILED);
    }
  vec_free (psk);
  vec_free (key_pad);
}


static void
ikev2_sa_auth_init (ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  u8 *authmsg, *key_pad, *psk = 0, *auth = 0;
  ikev2_sa_transform_t *tr_prf;

  tr_prf =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);

  /* only shared key and rsa signature */
  if (!(sa->i_auth.method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC ||
	sa->i_auth.method == IKEV2_AUTH_METHOD_RSA_SIG))
    {
      clib_warning ("unsupported authentication method %u",
		    sa->i_auth.method);
      ikev2_set_state (sa, IKEV2_STATE_AUTH_FAILED);
      return;
    }

  key_pad = format (0, "%s", IKEV2_KEY_PAD);
  authmsg = ikev2_sa_generate_authmsg (sa, 0);
  psk = ikev2_calc_prf (tr_prf, sa->i_auth.data, key_pad);
  auth = ikev2_calc_prf (tr_prf, psk, authmsg);


  if (sa->i_auth.method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
    {
      sa->i_auth.data = ikev2_calc_prf (tr_prf, psk, authmsg);
      sa->i_auth.method = IKEV2_AUTH_METHOD_SHARED_KEY_MIC;
    }
  else if (sa->i_auth.method == IKEV2_AUTH_METHOD_RSA_SIG)
    {
      sa->i_auth.data = ikev2_calc_sign (km->pkey, authmsg);
      sa->i_auth.method = IKEV2_AUTH_METHOD_RSA_SIG;
    }

  vec_free (psk);
  vec_free (key_pad);
  vec_free (auth);
  vec_free (authmsg);
}


static int
ikev2_create_tunnel_interface (vnet_main_t * vnm, ikev2_sa_t * sa,
			       ikev2_child_sa_t * child)
{
  ipsec_add_del_tunnel_args_t a;
  ikev2_sa_transform_t *tr;
  ikev2_sa_proposal_t *proposals;
  u8 encr_type = 0;

  if (!child->r_proposals)
    {
      ikev2_set_state (sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
      return 1;
    }

  memset (&a, 0, sizeof (a));
  a.is_add = 1;
  if (sa->is_initiator)
    {
      a.local_ip.as_u32 = sa->iaddr.as_u32;
      a.remote_ip.as_u32 = sa->raddr.as_u32;
      proposals = child->i_proposals;
      a.local_spi = child->r_proposals[0].spi;
      a.remote_spi = child->i_proposals[0].spi;
    }
  else
    {
      a.local_ip.as_u32 = sa->raddr.as_u32;
      a.remote_ip.as_u32 = sa->iaddr.as_u32;
      proposals = child->r_proposals;
      a.local_spi = child->i_proposals[0].spi;
      a.remote_spi = child->r_proposals[0].spi;
    }
  a.anti_replay = 1;

  tr = ikev2_sa_get_td_for_type (proposals, IKEV2_TRANSFORM_TYPE_ESN);
  if (tr)
    a.esn = tr->esn_type;
  else
    a.esn = 0;

  tr = ikev2_sa_get_td_for_type (proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  if (tr)
    {
      if (tr->encr_type == IKEV2_TRANSFORM_ENCR_TYPE_AES_CBC && tr->key_len)
	{
	  switch (tr->key_len)
	    {
	    case 16:
	      encr_type = IPSEC_CRYPTO_ALG_AES_CBC_128;
	      break;
	    case 24:
	      encr_type = IPSEC_CRYPTO_ALG_AES_CBC_192;
	      break;
	    case 32:
	      encr_type = IPSEC_CRYPTO_ALG_AES_CBC_256;
	      break;
	    default:
	      ikev2_set_state (sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
	      return 1;
	      break;
	    }
	}
      else
	{
	  ikev2_set_state (sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
	  return 1;
	}
    }
  else
    {
      ikev2_set_state (sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
      return 1;
    }

  tr = ikev2_sa_get_td_for_type (proposals, IKEV2_TRANSFORM_TYPE_INTEG);
  if (tr)
    {
      if (tr->integ_type != IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_96)
	{
	  ikev2_set_state (sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
	  return 1;
	}
    }
  else
    {
      ikev2_set_state (sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
      return 1;
    }

  ikev2_calc_child_keys (sa, child);

  u8 *loc_ckey, *rem_ckey, *loc_ikey, *rem_ikey;
  if (sa->is_initiator)
    {
      loc_ikey = child->sk_ai;
      rem_ikey = child->sk_ar;
      loc_ckey = child->sk_ei;
      rem_ckey = child->sk_er;
    }
  else
    {
      loc_ikey = child->sk_ar;
      rem_ikey = child->sk_ai;
      loc_ckey = child->sk_er;
      rem_ckey = child->sk_ei;
    }

  a.integ_alg = IPSEC_INTEG_ALG_SHA1_96;
  a.local_integ_key_len = vec_len (loc_ikey);
  clib_memcpy (a.local_integ_key, loc_ikey, a.local_integ_key_len);
  a.remote_integ_key_len = vec_len (rem_ikey);
  clib_memcpy (a.remote_integ_key, rem_ikey, a.remote_integ_key_len);

  a.crypto_alg = encr_type;
  a.local_crypto_key_len = vec_len (loc_ckey);
  clib_memcpy (a.local_crypto_key, loc_ckey, a.local_crypto_key_len);
  a.remote_crypto_key_len = vec_len (rem_ckey);
  clib_memcpy (a.remote_crypto_key, rem_ckey, a.remote_crypto_key_len);

  if (sa->profile && sa->profile->lifetime)
    {
      child->time_to_expiration = vlib_time_now (vnm->vlib_main)
	+ sa->profile->lifetime;
      if (sa->profile->lifetime_jitter)
	{
	  // This is not much better than rand(3), which Coverity warns
	  // is unsuitable for security applications; random_u32 is
	  // however fast. If this perturbance to the expiration time
	  // needs to use a better RNG then we may need to use something
	  // like /dev/urandom which has significant overhead.
	  u32 rnd = (u32) (vlib_time_now (vnm->vlib_main) * 1e6);
	  rnd = random_u32 (&rnd);

	  child->time_to_expiration +=
	    1 + (rnd % sa->profile->lifetime_jitter);
	}
    }

  ipsec_add_del_tunnel_if (&a);

  return 0;
}

static int
ikev2_delete_tunnel_interface (vnet_main_t * vnm, ikev2_sa_t * sa,
			       ikev2_child_sa_t * child)
{
  ipsec_add_del_tunnel_args_t a;

  if (sa->is_initiator)
    {
      if (!vec_len (child->i_proposals))
	return 0;

      a.is_add = 0;
      a.local_ip.as_u32 = sa->iaddr.as_u32;
      a.remote_ip.as_u32 = sa->raddr.as_u32;
      a.local_spi = child->r_proposals[0].spi;
      a.remote_spi = child->i_proposals[0].spi;
    }
  else
    {
      if (!vec_len (child->r_proposals))
	return 0;

      a.is_add = 0;
      a.local_ip.as_u32 = sa->raddr.as_u32;
      a.remote_ip.as_u32 = sa->iaddr.as_u32;
      a.local_spi = child->i_proposals[0].spi;
      a.remote_spi = child->r_proposals[0].spi;
    }

  ipsec_add_del_tunnel_if (&a);
  return 0;
}

static u32
ikev2_generate_message (ikev2_sa_t * sa, ike_header_t * ike, void *user)
{
  v8 *integ = 0;
  ike_payload_header_t *ph;
  u16 plen;
  u32 tlen = 0;

  ikev2_sa_transform_t *tr_encr, *tr_integ;
  tr_encr =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  tr_integ =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);

  ikev2_payload_chain_t *chain = 0;
  ikev2_payload_new_chain (chain);

  if (ike->exchange == IKEV2_EXCHANGE_SA_INIT)
    {
      if (sa->r_proposals == 0)
	{
	  ikev2_payload_add_notify (chain,
				    IKEV2_NOTIFY_MSG_NO_PROPOSAL_CHOSEN, 0);
	  ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
	}
      else if (sa->dh_group == IKEV2_TRANSFORM_DH_TYPE_NONE)
	{
	  u8 *data = vec_new (u8, 2);
	  ikev2_sa_transform_t *tr_dh;
	  tr_dh =
	    ikev2_sa_get_td_for_type (sa->r_proposals,
				      IKEV2_TRANSFORM_TYPE_DH);
	  ASSERT (tr_dh && tr_dh->dh_type);

	  data[0] = (tr_dh->dh_type >> 8) & 0xff;
	  data[1] = (tr_dh->dh_type) & 0xff;

	  ikev2_payload_add_notify (chain,
				    IKEV2_NOTIFY_MSG_INVALID_KE_PAYLOAD,
				    data);
	  vec_free (data);
	  ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
	}
      else if (sa->state == IKEV2_STATE_NOTIFY_AND_DELETE)
	{
	  u8 *data = vec_new (u8, 1);

	  data[0] = sa->unsupported_cp;
	  ikev2_payload_add_notify (chain,
				    IKEV2_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
				    data);
	  vec_free (data);
	}
      else
	{
	  ike->rspi = clib_host_to_net_u64 (sa->rspi);
	  ikev2_payload_add_sa (chain, sa->r_proposals);
	  ikev2_payload_add_ke (chain, sa->dh_group, sa->r_dh_data);
	  ikev2_payload_add_nonce (chain, sa->r_nonce);
	}
    }
  else if (ike->exchange == IKEV2_EXCHANGE_IKE_AUTH)
    {
      if (sa->state == IKEV2_STATE_AUTHENTICATED)
	{
	  ikev2_payload_add_id (chain, &sa->r_id, IKEV2_PAYLOAD_IDR);
	  ikev2_payload_add_auth (chain, &sa->r_auth);
	  ikev2_payload_add_sa (chain, sa->childs[0].r_proposals);
	  ikev2_payload_add_ts (chain, sa->childs[0].tsi, IKEV2_PAYLOAD_TSI);
	  ikev2_payload_add_ts (chain, sa->childs[0].tsr, IKEV2_PAYLOAD_TSR);
	}
      else if (sa->state == IKEV2_STATE_AUTH_FAILED)
	{
	  ikev2_payload_add_notify (chain,
				    IKEV2_NOTIFY_MSG_AUTHENTICATION_FAILED,
				    0);
	  ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
	}
      else if (sa->state == IKEV2_STATE_TS_UNACCEPTABLE)
	{
	  ikev2_payload_add_notify (chain, IKEV2_NOTIFY_MSG_TS_UNACCEPTABLE,
				    0);
	  ikev2_payload_add_id (chain, &sa->r_id, IKEV2_PAYLOAD_IDR);
	  ikev2_payload_add_auth (chain, &sa->r_auth);
	}
      else if (sa->state == IKEV2_STATE_NO_PROPOSAL_CHOSEN)
	{
	  ikev2_payload_add_notify (chain,
				    IKEV2_NOTIFY_MSG_NO_PROPOSAL_CHOSEN, 0);
	  ikev2_payload_add_id (chain, &sa->r_id, IKEV2_PAYLOAD_IDR);
	  ikev2_payload_add_auth (chain, &sa->r_auth);
	  ikev2_payload_add_ts (chain, sa->childs[0].tsi, IKEV2_PAYLOAD_TSI);
	  ikev2_payload_add_ts (chain, sa->childs[0].tsr, IKEV2_PAYLOAD_TSR);
	}
      else if (sa->state == IKEV2_STATE_NOTIFY_AND_DELETE)
	{
	  u8 *data = vec_new (u8, 1);

	  data[0] = sa->unsupported_cp;
	  ikev2_payload_add_notify (chain,
				    IKEV2_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
				    data);
	  vec_free (data);
	}
      else if (sa->state == IKEV2_STATE_SA_INIT)
	{
	  ikev2_payload_add_id (chain, &sa->i_id, IKEV2_PAYLOAD_IDI);
	  ikev2_payload_add_auth (chain, &sa->i_auth);
	  ikev2_payload_add_sa (chain, sa->childs[0].i_proposals);
	  ikev2_payload_add_ts (chain, sa->childs[0].tsi, IKEV2_PAYLOAD_TSI);
	  ikev2_payload_add_ts (chain, sa->childs[0].tsr, IKEV2_PAYLOAD_TSR);
	}
      else
	{
	  ikev2_set_state (sa, IKEV2_STATE_DELETED);
	  goto done;
	}
    }
  else if (ike->exchange == IKEV2_EXCHANGE_INFORMATIONAL)
    {
      /* if pending delete */
      if (sa->del)
	{
	  if (sa->del[0].protocol_id == IKEV2_PROTOCOL_IKE)
	    {
	      if (sa->is_initiator)
		ikev2_payload_add_delete (chain, sa->del);

	      /* The response to a request that deletes the IKE SA is an empty
	         INFORMATIONAL response. */
	      ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
	    }
	  /* The response to a request that deletes ESP or AH SAs will contain
	     delete payloads for the paired SAs going in the other direction. */
	  else
	    {
	      ikev2_payload_add_delete (chain, sa->del);
	    }
	  vec_free (sa->del);
	  sa->del = 0;
	}
      /* received N(AUTHENTICATION_FAILED) */
      else if (sa->state == IKEV2_STATE_AUTH_FAILED)
	{
	  ikev2_set_state (sa, IKEV2_STATE_DELETED);
	  goto done;
	}
      /* received unsupported critical payload */
      else if (sa->unsupported_cp)
	{
	  u8 *data = vec_new (u8, 1);

	  data[0] = sa->unsupported_cp;
	  ikev2_payload_add_notify (chain,
				    IKEV2_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
				    data);
	  vec_free (data);
	  sa->unsupported_cp = 0;
	}
      /* else send empty response */
    }
  else if (ike->exchange == IKEV2_EXCHANGE_CREATE_CHILD_SA)
    {
      if (sa->is_initiator)
	{

	  ikev2_sa_proposal_t *proposals = (ikev2_sa_proposal_t *) user;
	  ikev2_notify_t notify;
	  u8 *data = vec_new (u8, 4);
	  memset (&notify, 0, sizeof (notify));
	  notify.protocol_id = IKEV2_PROTOCOL_ESP;
	  notify.spi = sa->childs[0].i_proposals->spi;
	  *(u32 *) data = clib_host_to_net_u32 (notify.spi);

	  ikev2_payload_add_sa (chain, proposals);
	  ikev2_payload_add_nonce (chain, sa->i_nonce);
	  ikev2_payload_add_ts (chain, sa->childs[0].tsi, IKEV2_PAYLOAD_TSI);
	  ikev2_payload_add_ts (chain, sa->childs[0].tsr, IKEV2_PAYLOAD_TSR);
	  ikev2_payload_add_notify_2 (chain, IKEV2_NOTIFY_MSG_REKEY_SA, data,
				      &notify);

	  vec_free (data);
	}
      else
	{
	  if (sa->rekey)
	    {
	      ikev2_payload_add_sa (chain, sa->rekey[0].r_proposal);
	      ikev2_payload_add_nonce (chain, sa->r_nonce);
	      ikev2_payload_add_ts (chain, sa->rekey[0].tsi,
				    IKEV2_PAYLOAD_TSI);
	      ikev2_payload_add_ts (chain, sa->rekey[0].tsr,
				    IKEV2_PAYLOAD_TSR);
	      vec_del1 (sa->rekey, 0);
	    }
	  else if (sa->unsupported_cp)
	    {
	      u8 *data = vec_new (u8, 1);

	      data[0] = sa->unsupported_cp;
	      ikev2_payload_add_notify (chain,
					IKEV2_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
					data);
	      vec_free (data);
	      sa->unsupported_cp = 0;
	    }
	  else
	    {
	      ikev2_payload_add_notify (chain,
					IKEV2_NOTIFY_MSG_NO_ADDITIONAL_SAS,
					0);
	    }
	}
    }

  /* IKEv2 header */
  ike->version = IKE_VERSION_2;
  ike->nextpayload = IKEV2_PAYLOAD_SK;
  tlen = sizeof (*ike);
  if (sa->is_initiator)
    {
      ike->flags = IKEV2_HDR_FLAG_INITIATOR;
      sa->last_init_msg_id = clib_net_to_host_u32 (ike->msgid);
    }
  else
    {
      ike->flags = IKEV2_HDR_FLAG_RESPONSE;
    }


  if (ike->exchange == IKEV2_EXCHANGE_SA_INIT)
    {
      tlen += vec_len (chain->data);
      ike->nextpayload = chain->first_payload_type;
      ike->length = clib_host_to_net_u32 (tlen);
      clib_memcpy (ike->payload, chain->data, vec_len (chain->data));

      /* store whole IKE payload - needed for PSK auth */
      vec_free (sa->last_sa_init_res_packet_data);
      vec_add (sa->last_sa_init_res_packet_data, ike, tlen);
    }
  else
    {

      ikev2_payload_chain_add_padding (chain, tr_encr->block_size);

      /* SK payload */
      plen = sizeof (*ph);
      ph = (ike_payload_header_t *) & ike->payload[0];
      ph->nextpayload = chain->first_payload_type;
      ph->flags = 0;
      int enc_len = ikev2_encrypt_data (sa, chain->data, ph->payload);
      plen += enc_len;

      /* add space for hmac */
      plen += tr_integ->key_trunc;
      tlen += plen;

      /* payload and total length */
      ph->length = clib_host_to_net_u16 (plen);
      ike->length = clib_host_to_net_u32 (tlen);

      /* calc integrity data for whole packet except hash itself */
      integ =
	ikev2_calc_integr (tr_integ, sa->is_initiator ? sa->sk_ai : sa->sk_ar,
			   (u8 *) ike, tlen - tr_integ->key_trunc);

      clib_memcpy (ike->payload + tlen - tr_integ->key_trunc - sizeof (*ike),
		   integ, tr_integ->key_trunc);

      /* store whole IKE payload - needed for retransmit */
      vec_free (sa->last_res_packet_data);
      vec_add (sa->last_res_packet_data, ike, tlen);
    }

done:
  ikev2_payload_destroy_chain (chain);
  vec_free (integ);
  return tlen;
}

static int
ikev2_retransmit_sa_init (ike_header_t * ike,
			  ip4_address_t iaddr, ip4_address_t raddr)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_sa_t *sa;
  u32 thread_index = vlib_get_thread_index ();

  /* *INDENT-OFF* */
  pool_foreach (sa, km->per_thread_data[thread_index].sas, ({
    if (sa->ispi == clib_net_to_host_u64(ike->ispi) &&
        sa->iaddr.as_u32 == iaddr.as_u32 &&
        sa->raddr.as_u32 == raddr.as_u32)
      {
        int p = 0;
        u32 len = clib_net_to_host_u32(ike->length);
        u8 payload = ike->nextpayload;

        while (p < len && payload!= IKEV2_PAYLOAD_NONE) {
          ike_payload_header_t * ikep = (ike_payload_header_t *) &ike->payload[p];
          u32 plen = clib_net_to_host_u16(ikep->length);

          if (plen < sizeof(ike_payload_header_t))
            return -1;

          if (payload == IKEV2_PAYLOAD_NONCE)
            {
              if (!memcmp(sa->i_nonce, ikep->payload, plen - sizeof(*ikep)))
                {
                  /* req is retransmit */
                  if (sa->state == IKEV2_STATE_SA_INIT)
                    {
                      ike_header_t * tmp;
                      tmp = (ike_header_t*)sa->last_sa_init_res_packet_data;
                      ike->ispi = tmp->ispi;
                      ike->rspi = tmp->rspi;
                      ike->nextpayload = tmp->nextpayload;
                      ike->version = tmp->version;
                      ike->exchange = tmp->exchange;
                      ike->flags = tmp->flags;
                      ike->msgid = tmp->msgid;
                      ike->length = tmp->length;
                      clib_memcpy(ike->payload, tmp->payload,
                             clib_net_to_host_u32(tmp->length) - sizeof(*ike));
                      clib_warning("IKE_SA_INIT retransmit from %U to %U",
                                   format_ip4_address, &raddr,
                                   format_ip4_address, &iaddr);
                      return 1;
                    }
                  /* else ignore req */
                  else
                    {
                      clib_warning("IKE_SA_INIT ignore from %U to %U",
                                   format_ip4_address, &raddr,
                                   format_ip4_address, &iaddr);
                      return -1;
                    }
                }
            }
          payload = ikep->nextpayload;
          p+=plen;
        }
      }
  }));
  /* *INDENT-ON* */

  /* req is not retransmit */
  return 0;
}

static int
ikev2_retransmit_resp (ikev2_sa_t * sa, ike_header_t * ike)
{
  u32 msg_id = clib_net_to_host_u32 (ike->msgid);

  /* new req */
  if (msg_id > sa->last_msg_id)
    {
      sa->last_msg_id = msg_id;
      return 0;
    }
  /* retransmitted req */
  else if (msg_id == sa->last_msg_id)
    {
      ike_header_t *tmp;
      tmp = (ike_header_t *) sa->last_res_packet_data;
      ike->ispi = tmp->ispi;
      ike->rspi = tmp->rspi;
      ike->nextpayload = tmp->nextpayload;
      ike->version = tmp->version;
      ike->exchange = tmp->exchange;
      ike->flags = tmp->flags;
      ike->msgid = tmp->msgid;
      ike->length = tmp->length;
      clib_memcpy (ike->payload, tmp->payload,
		   clib_net_to_host_u32 (tmp->length) - sizeof (*ike));
      clib_warning ("IKE msgid %u retransmit from %U to %U",
		    msg_id,
		    format_ip4_address, &sa->raddr,
		    format_ip4_address, &sa->iaddr);
      return 1;
    }
  /* old req ignore */
  else
    {
      clib_warning ("IKE msgid %u req ignore from %U to %U",
		    msg_id,
		    format_ip4_address, &sa->raddr,
		    format_ip4_address, &sa->iaddr);
      return -1;
    }
}

static uword
ikev2_node_fn (vlib_main_t * vm,
	       vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, *to_next;
  ikev2_next_t next_index;
  ikev2_main_t *km = &ikev2_main;
  u32 thread_index = vlib_get_thread_index ();

  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
	{
	  u32 bi0;
	  vlib_buffer_t *b0;
	  u32 next0 = IKEV2_NEXT_ERROR_DROP;
	  u32 sw_if_index0;
	  ip4_header_t *ip40;
	  udp_header_t *udp0;
	  ike_header_t *ike0;
	  ikev2_sa_t *sa0 = 0;
	  ikev2_sa_t sa;	/* temporary store for SA */
	  int len = 0;
	  int r;

	  /* speculatively enqueue b0 to the current next frame */
	  bi0 = from[0];
	  to_next[0] = bi0;
	  from += 1;
	  to_next += 1;
	  n_left_from -= 1;
	  n_left_to_next -= 1;

	  b0 = vlib_get_buffer (vm, bi0);
	  ike0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*udp0));
	  udp0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*ip40));
	  ip40 = vlib_buffer_get_current (b0);

	  if (ike0->version != IKE_VERSION_2)
	    {
	      vlib_node_increment_counter (vm, ikev2_node.index,
					   IKEV2_ERROR_NOT_IKEV2, 1);
	      goto dispatch0;
	    }

	  if (ike0->exchange == IKEV2_EXCHANGE_SA_INIT)
	    {
	      sa0 = &sa;
	      memset (sa0, 0, sizeof (*sa0));

	      if (ike0->flags & IKEV2_HDR_FLAG_INITIATOR)
		{
		  if (ike0->rspi == 0)
		    {
		      sa0->raddr.as_u32 = ip40->dst_address.as_u32;
		      sa0->iaddr.as_u32 = ip40->src_address.as_u32;

		      r = ikev2_retransmit_sa_init (ike0, sa0->iaddr,
						    sa0->raddr);
		      if (r == 1)
			{
			  vlib_node_increment_counter (vm, ikev2_node.index,
						       IKEV2_ERROR_IKE_SA_INIT_RETRANSMIT,
						       1);
			  len = clib_net_to_host_u32 (ike0->length);
			  goto dispatch0;
			}
		      else if (r == -1)
			{
			  vlib_node_increment_counter (vm, ikev2_node.index,
						       IKEV2_ERROR_IKE_SA_INIT_IGNORE,
						       1);
			  goto dispatch0;
			}

		      ikev2_process_sa_init_req (vm, sa0, ike0);

		      if (sa0->state == IKEV2_STATE_SA_INIT)
			{
			  ikev2_sa_free_proposal_vector (&sa0->r_proposals);
			  sa0->r_proposals =
			    ikev2_select_proposal (sa0->i_proposals,
						   IKEV2_PROTOCOL_IKE);
			  ikev2_generate_sa_init_data (sa0);
			}

		      if (sa0->state == IKEV2_STATE_SA_INIT
			  || sa0->state == IKEV2_STATE_NOTIFY_AND_DELETE)
			{
			  len = ikev2_generate_message (sa0, ike0, 0);
			}

		      if (sa0->state == IKEV2_STATE_SA_INIT)
			{
			  /* add SA to the pool */
			  pool_get (km->per_thread_data[thread_index].sas,
				    sa0);
			  clib_memcpy (sa0, &sa, sizeof (*sa0));
			  hash_set (km->
				    per_thread_data[thread_index].sa_by_rspi,
				    sa0->rspi,
				    sa0 -
				    km->per_thread_data[thread_index].sas);
			}
		      else
			{
			  ikev2_sa_free_all_vec (sa0);
			}
		    }
		}
	      else
		{
		  ikev2_process_sa_init_resp (vm, sa0, ike0);

		  if (sa0->state == IKEV2_STATE_SA_INIT)
		    {
		      ike0->exchange = IKEV2_EXCHANGE_IKE_AUTH;
		      uword *p = hash_get (km->sa_by_ispi, ike0->ispi);
		      if (p)
			{
			  ikev2_sa_t *sai =
			    pool_elt_at_index (km->sais, p[0]);

			  ikev2_complete_sa_data (sa0, sai);
			  ikev2_calc_keys (sa0);
			  ikev2_sa_auth_init (sa0);
			  len = ikev2_generate_message (sa0, ike0, 0);
			}
		    }

		  if (sa0->state == IKEV2_STATE_SA_INIT)
		    {
		      /* add SA to the pool */
		      pool_get (km->per_thread_data[thread_index].sas, sa0);
		      clib_memcpy (sa0, &sa, sizeof (*sa0));
		      hash_set (km->per_thread_data[thread_index].sa_by_rspi,
				sa0->rspi,
				sa0 - km->per_thread_data[thread_index].sas);
		    }
		  else
		    {
		      ikev2_sa_free_all_vec (sa0);
		    }
		}
	    }
	  else if (ike0->exchange == IKEV2_EXCHANGE_IKE_AUTH)
	    {
	      uword *p;
	      p = hash_get (km->per_thread_data[thread_index].sa_by_rspi,
			    clib_net_to_host_u64 (ike0->rspi));
	      if (p)
		{
		  sa0 =
		    pool_elt_at_index (km->per_thread_data[thread_index].sas,
				       p[0]);

		  r = ikev2_retransmit_resp (sa0, ike0);
		  if (r == 1)
		    {
		      vlib_node_increment_counter (vm, ikev2_node.index,
						   IKEV2_ERROR_IKE_REQ_RETRANSMIT,
						   1);
		      len = clib_net_to_host_u32 (ike0->length);
		      goto dispatch0;
		    }
		  else if (r == -1)
		    {
		      vlib_node_increment_counter (vm, ikev2_node.index,
						   IKEV2_ERROR_IKE_REQ_IGNORE,
						   1);
		      goto dispatch0;
		    }

		  ikev2_process_auth_req (vm, sa0, ike0);
		  ikev2_sa_auth (sa0);
		  if (sa0->state == IKEV2_STATE_AUTHENTICATED)
		    {
		      ikev2_initial_contact_cleanup (sa0);
		      ikev2_sa_match_ts (sa0);
		      if (sa0->state != IKEV2_STATE_TS_UNACCEPTABLE)
			ikev2_create_tunnel_interface (km->vnet_main, sa0,
						       &sa0->childs[0]);
		    }

		  if (sa0->is_initiator)
		    {
		      uword *p = hash_get (km->sa_by_ispi, ike0->ispi);
		      if (p)
			{
			  ikev2_sa_t *sai =
			    pool_elt_at_index (km->sais, p[0]);
			  hash_unset (km->sa_by_ispi, sai->ispi);
			  ikev2_sa_free_all_vec (sai);
			  pool_put (km->sais, sai);
			}
		    }
		  else
		    {
		      len = ikev2_generate_message (sa0, ike0, 0);
		    }
		}
	    }
	  else if (ike0->exchange == IKEV2_EXCHANGE_INFORMATIONAL)
	    {
	      uword *p;
	      p = hash_get (km->per_thread_data[thread_index].sa_by_rspi,
			    clib_net_to_host_u64 (ike0->rspi));
	      if (p)
		{
		  sa0 =
		    pool_elt_at_index (km->per_thread_data[thread_index].sas,
				       p[0]);

		  r = ikev2_retransmit_resp (sa0, ike0);
		  if (r == 1)
		    {
		      vlib_node_increment_counter (vm, ikev2_node.index,
						   IKEV2_ERROR_IKE_REQ_RETRANSMIT,
						   1);
		      len = clib_net_to_host_u32 (ike0->length);
		      goto dispatch0;
		    }
		  else if (r == -1)
		    {
		      vlib_node_increment_counter (vm, ikev2_node.index,
						   IKEV2_ERROR_IKE_REQ_IGNORE,
						   1);
		      goto dispatch0;
		    }

		  ikev2_process_informational_req (vm, sa0, ike0);
		  if (sa0->del)
		    {
		      if (sa0->del[0].protocol_id != IKEV2_PROTOCOL_IKE)
			{
			  ikev2_delete_t *d, *tmp, *resp = 0;
			  vec_foreach (d, sa0->del)
			  {
			    ikev2_child_sa_t *ch_sa;
			    ch_sa = ikev2_sa_get_child (sa0, d->spi,
							d->protocol_id,
							!sa0->is_initiator);
			    if (ch_sa)
			      {
				ikev2_delete_tunnel_interface (km->vnet_main,
							       sa0, ch_sa);
				if (!sa0->is_initiator)
				  {
				    vec_add2 (resp, tmp, 1);
				    tmp->protocol_id = d->protocol_id;
				    tmp->spi = ch_sa->r_proposals[0].spi;
				  }
				ikev2_sa_del_child_sa (sa0, ch_sa);
			      }
			  }
			  if (!sa0->is_initiator)
			    {
			      vec_free (sa0->del);
			      sa0->del = resp;
			    }
			}
		    }
		  if (!sa0->is_initiator)
		    {
		      len = ikev2_generate_message (sa0, ike0, 0);
		    }
		}
	    }
	  else if (ike0->exchange == IKEV2_EXCHANGE_CREATE_CHILD_SA)
	    {
	      uword *p;
	      p = hash_get (km->per_thread_data[thread_index].sa_by_rspi,
			    clib_net_to_host_u64 (ike0->rspi));
	      if (p)
		{
		  sa0 =
		    pool_elt_at_index (km->per_thread_data[thread_index].sas,
				       p[0]);

		  r = ikev2_retransmit_resp (sa0, ike0);
		  if (r == 1)
		    {
		      vlib_node_increment_counter (vm, ikev2_node.index,
						   IKEV2_ERROR_IKE_REQ_RETRANSMIT,
						   1);
		      len = clib_net_to_host_u32 (ike0->length);
		      goto dispatch0;
		    }
		  else if (r == -1)
		    {
		      vlib_node_increment_counter (vm, ikev2_node.index,
						   IKEV2_ERROR_IKE_REQ_IGNORE,
						   1);
		      goto dispatch0;
		    }

		  ikev2_process_create_child_sa_req (vm, sa0, ike0);
		  if (sa0->rekey)
		    {
		      if (sa0->rekey[0].protocol_id != IKEV2_PROTOCOL_IKE)
			{
			  ikev2_child_sa_t *child;
			  vec_add2 (sa0->childs, child, 1);
			  child->r_proposals = sa0->rekey[0].r_proposal;
			  child->i_proposals = sa0->rekey[0].i_proposal;
			  child->tsi = sa0->rekey[0].tsi;
			  child->tsr = sa0->rekey[0].tsr;
			  ikev2_create_tunnel_interface (km->vnet_main, sa0,
							 child);
			}
		      if (sa0->is_initiator)
			{
			  vec_del1 (sa0->rekey, 0);
			}
		      else
			{
			  len = ikev2_generate_message (sa0, ike0, 0);
			}
		    }
		}
	    }
	  else
	    {
	      clib_warning ("IKEv2 exchange %u packet received from %U to %U",
			    ike0->exchange,
			    format_ip4_address, ip40->src_address.as_u8,
			    format_ip4_address, ip40->dst_address.as_u8);
	    }

	dispatch0:
	  /* if we are sending packet back, rewrite headers */
	  if (len)
	    {
	      next0 = IKEV2_NEXT_IP4_LOOKUP;
	      if (sa0->is_initiator)
		{
		  ip40->dst_address.as_u32 = sa0->raddr.as_u32;
		  ip40->src_address.as_u32 = sa0->iaddr.as_u32;
		}
	      else
		{
		  ip40->dst_address.as_u32 = sa0->iaddr.as_u32;
		  ip40->src_address.as_u32 = sa0->raddr.as_u32;
		}
	      udp0->length =
		clib_host_to_net_u16 (len + sizeof (udp_header_t));
	      udp0->checksum = 0;
	      b0->current_length =
		len + sizeof (ip4_header_t) + sizeof (udp_header_t);
	      ip40->length = clib_host_to_net_u16 (b0->current_length);
	      ip40->checksum = ip4_header_checksum (ip40);
	    }
	  /* delete sa */
	  if (sa0 && (sa0->state == IKEV2_STATE_DELETED ||
		      sa0->state == IKEV2_STATE_NOTIFY_AND_DELETE))
	    {
	      ikev2_child_sa_t *c;

	      vec_foreach (c, sa0->childs)
		ikev2_delete_tunnel_interface (km->vnet_main, sa0, c);

	      ikev2_delete_sa (sa0);
	    }
	  sw_if_index0 = vnet_buffer (b0)->sw_if_index[VLIB_RX];

	  if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			     && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	    {
	      ikev2_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	      t->sw_if_index = sw_if_index0;
	      t->next_index = next0;
	    }

	  vlib_validate_buffer_enqueue_x1 (vm, node, next_index, to_next,
					   n_left_to_next, bi0, next0);
	}

      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }

  vlib_node_increment_counter (vm, ikev2_node.index,
			       IKEV2_ERROR_PROCESSED, frame->n_vectors);
  return frame->n_vectors;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ikev2_node,static) = {
  .function = ikev2_node_fn,
  .name = "ikev2",
  .vector_size = sizeof (u32),
  .format_trace = format_ikev2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ikev2_error_strings),
  .error_strings = ikev2_error_strings,

  .n_next_nodes = IKEV2_N_NEXT,

  .next_nodes = {
    [IKEV2_NEXT_IP4_LOOKUP] = "ip4-lookup",
        [IKEV2_NEXT_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */


static clib_error_t *
ikev2_set_initiator_proposals (vlib_main_t * vm, ikev2_sa_t * sa,
			       ikev2_transforms_set * ts,
			       ikev2_sa_proposal_t ** proposals, int is_ike)
{
  clib_error_t *r;
  ikev2_main_t *km = &ikev2_main;
  ikev2_sa_proposal_t *proposal;
  vec_add2 (*proposals, proposal, 1);
  ikev2_sa_transform_t *td;
  int error;

  /* Encryption */
  error = 1;
  vec_foreach (td, km->supported_transforms)
  {
    if (td->type == IKEV2_TRANSFORM_TYPE_ENCR
	&& td->encr_type == IKEV2_TRANSFORM_ENCR_TYPE_AES_CBC
	&& td->key_len == ts->crypto_key_size / 8)
      {
	u16 attr[2];
	attr[0] = clib_host_to_net_u16 (14 | (1 << 15));
	attr[1] = clib_host_to_net_u16 (td->key_len << 3);
	vec_add (td->attrs, (u8 *) attr, 4);
	vec_add1 (proposal->transforms, *td);
	td->attrs = 0;

	error = 0;
	break;
      }
  }
  if (error)
    {
      r = clib_error_return (0, "Unsupported algorithm");
      return r;
    }

  /* Integrity */
  error = 1;
  vec_foreach (td, km->supported_transforms)
  {
    if (td->type == IKEV2_TRANSFORM_TYPE_INTEG
	&& td->integ_type == IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_96)
      {
	vec_add1 (proposal->transforms, *td);
	error = 0;
	break;
      }
  }
  if (error)
    {
      r = clib_error_return (0, "Unsupported algorithm");
      return r;
    }

  /* PRF */
  if (is_ike)
    {
      error = 1;
      vec_foreach (td, km->supported_transforms)
      {
	if (td->type == IKEV2_TRANSFORM_TYPE_PRF
	    && td->prf_type == IKEV2_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA1)
	  {
	    vec_add1 (proposal->transforms, *td);
	    error = 0;
	    break;
	  }
      }
      if (error)
	{
	  r = clib_error_return (0, "Unsupported algorithm");
	  return r;
	}
    }

  /* DH */
  error = 1;
  vec_foreach (td, km->supported_transforms)
  {
    if (td->type == IKEV2_TRANSFORM_TYPE_DH && td->dh_type == ts->dh_type)
      {
	vec_add1 (proposal->transforms, *td);
	if (is_ike)
	  {
	    sa->dh_group = td->dh_type;
	  }
	error = 0;
	break;
      }
  }
  if (error)
    {
      r = clib_error_return (0, "Unsupported algorithm");
      return r;
    }

  if (!is_ike)
    {
      error = 1;
      vec_foreach (td, km->supported_transforms)
      {
	if (td->type == IKEV2_TRANSFORM_TYPE_ESN)
	  {
	    vec_add1 (proposal->transforms, *td);
	    error = 0;
	    break;
	  }
      }
      if (error)
	{
	  r = clib_error_return (0, "Unsupported algorithm");
	  return r;
	}
    }


  return 0;
}

static ikev2_profile_t *
ikev2_profile_index_by_name (u8 * name)
{
  ikev2_main_t *km = &ikev2_main;
  uword *p;

  p = mhash_get (&km->profile_index_by_name, name);
  if (!p)
    return 0;

  return pool_elt_at_index (km->profiles, p[0]);
}


static void
ikev2_send_ike (vlib_main_t * vm, ip4_address_t * src, ip4_address_t * dst,
		u32 bi0, u32 len)
{
  ip4_header_t *ip40;
  udp_header_t *udp0;
  vlib_buffer_t *b0;
  vlib_frame_t *f;
  u32 *to_next;

  b0 = vlib_get_buffer (vm, bi0);
  vlib_buffer_advance (b0, -sizeof (udp_header_t));
  udp0 = vlib_buffer_get_current (b0);
  vlib_buffer_advance (b0, -sizeof (ip4_header_t));
  ip40 = vlib_buffer_get_current (b0);


  ip40->ip_version_and_header_length = 0x45;
  ip40->tos = 0;
  ip40->fragment_id = 0;
  ip40->flags_and_fragment_offset = 0;
  ip40->ttl = 0xff;
  ip40->protocol = IP_PROTOCOL_UDP;
  ip40->dst_address.as_u32 = dst->as_u32;
  ip40->src_address.as_u32 = src->as_u32;
  udp0->dst_port = clib_host_to_net_u16 (500);
  udp0->src_port = clib_host_to_net_u16 (500);
  udp0->length = clib_host_to_net_u16 (len + sizeof (udp_header_t));
  udp0->checksum = 0;
  b0->current_length = len + sizeof (ip4_header_t) + sizeof (udp_header_t);
  ip40->length = clib_host_to_net_u16 (b0->current_length);
  ip40->checksum = ip4_header_checksum (ip40);


  /* send the request */
  f = vlib_get_frame_to_node (vm, ip4_lookup_node.index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, ip4_lookup_node.index, f);

}

static u32
ikev2_get_new_ike_header_buff (vlib_main_t * vm, ike_header_t ** ike)
{
  u32 bi0;
  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    {
      *ike = 0;
      return 0;
    }
  vlib_buffer_t *b0 = vlib_get_buffer (vm, bi0);
  *ike = vlib_buffer_get_current (b0);
  return bi0;
}

clib_error_t *
ikev2_set_local_key (vlib_main_t * vm, u8 * file)
{
  ikev2_main_t *km = &ikev2_main;

  km->pkey = ikev2_load_key_file (file);
  if (km->pkey == NULL)
    return clib_error_return (0, "load key '%s' failed", file);

  return 0;
}

clib_error_t *
ikev2_add_del_profile (vlib_main_t * vm, u8 * name, int is_add)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_profile_t *p;

  if (is_add)
    {
      if (ikev2_profile_index_by_name (name))
	return clib_error_return (0, "policy %v already exists", name);

      pool_get (km->profiles, p);
      memset (p, 0, sizeof (*p));
      p->name = vec_dup (name);
      p->responder.sw_if_index = ~0;
      uword index = p - km->profiles;
      mhash_set_mem (&km->profile_index_by_name, name, &index, 0);
    }
  else
    {
      p = ikev2_profile_index_by_name (name);
      if (!p)
	return clib_error_return (0, "policy %v does not exists", name);

      vec_free (p->name);
      pool_put (km->profiles, p);
      mhash_unset (&km->profile_index_by_name, name, 0);
    }
  return 0;
}

clib_error_t *
ikev2_set_profile_auth (vlib_main_t * vm, u8 * name, u8 auth_method,
			u8 * auth_data, u8 data_hex_format)
{
  ikev2_profile_t *p;
  clib_error_t *r;

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }
  vec_free (p->auth.data);
  p->auth.method = auth_method;
  p->auth.data = vec_dup (auth_data);
  p->auth.hex = data_hex_format;

  if (auth_method == IKEV2_AUTH_METHOD_RSA_SIG)
    {
      vec_add1 (p->auth.data, 0);
      if (p->auth.key)
	EVP_PKEY_free (p->auth.key);
      p->auth.key = ikev2_load_cert_file (auth_data);
      if (p->auth.key == NULL)
	return clib_error_return (0, "load cert '%s' failed", auth_data);
    }

  return 0;
}

clib_error_t *
ikev2_set_profile_id (vlib_main_t * vm, u8 * name, u8 id_type, u8 * data,
		      int is_local)
{
  ikev2_profile_t *p;
  clib_error_t *r;

  if (id_type > IKEV2_ID_TYPE_ID_RFC822_ADDR
      && id_type < IKEV2_ID_TYPE_ID_KEY_ID)
    {
      r = clib_error_return (0, "unsupported identity type %U",
			     format_ikev2_id_type, id_type);
      return r;
    }

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  if (is_local)
    {
      vec_free (p->loc_id.data);
      p->loc_id.type = id_type;
      p->loc_id.data = vec_dup (data);
    }
  else
    {
      vec_free (p->rem_id.data);
      p->rem_id.type = id_type;
      p->rem_id.data = vec_dup (data);
    }

  return 0;
}

clib_error_t *
ikev2_set_profile_ts (vlib_main_t * vm, u8 * name, u8 protocol_id,
		      u16 start_port, u16 end_port, ip4_address_t start_addr,
		      ip4_address_t end_addr, int is_local)
{
  ikev2_profile_t *p;
  clib_error_t *r;

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  if (is_local)
    {
      p->loc_ts.start_addr.as_u32 = start_addr.as_u32;
      p->loc_ts.end_addr.as_u32 = end_addr.as_u32;
      p->loc_ts.start_port = start_port;
      p->loc_ts.end_port = end_port;
      p->loc_ts.protocol_id = protocol_id;
      p->loc_ts.ts_type = 7;
    }
  else
    {
      p->rem_ts.start_addr.as_u32 = start_addr.as_u32;
      p->rem_ts.end_addr.as_u32 = end_addr.as_u32;
      p->rem_ts.start_port = start_port;
      p->rem_ts.end_port = end_port;
      p->rem_ts.protocol_id = protocol_id;
      p->rem_ts.ts_type = 7;
    }

  return 0;
}


clib_error_t *
ikev2_set_profile_responder (vlib_main_t * vm, u8 * name,
			     u32 sw_if_index, ip4_address_t ip4)
{
  ikev2_profile_t *p;
  clib_error_t *r;

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  p->responder.sw_if_index = sw_if_index;
  p->responder.ip4 = ip4;

  return 0;
}

clib_error_t *
ikev2_set_profile_ike_transforms (vlib_main_t * vm, u8 * name,
				  ikev2_transform_encr_type_t crypto_alg,
				  ikev2_transform_integ_type_t integ_alg,
				  ikev2_transform_dh_type_t dh_type,
				  u32 crypto_key_size)
{
  ikev2_profile_t *p;
  clib_error_t *r;

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  p->ike_ts.crypto_alg = crypto_alg;
  p->ike_ts.integ_alg = integ_alg;
  p->ike_ts.dh_type = dh_type;
  p->ike_ts.crypto_key_size = crypto_key_size;
  return 0;
}

clib_error_t *
ikev2_set_profile_esp_transforms (vlib_main_t * vm, u8 * name,
				  ikev2_transform_encr_type_t crypto_alg,
				  ikev2_transform_integ_type_t integ_alg,
				  ikev2_transform_dh_type_t dh_type,
				  u32 crypto_key_size)
{
  ikev2_profile_t *p;
  clib_error_t *r;

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  p->esp_ts.crypto_alg = crypto_alg;
  p->esp_ts.integ_alg = integ_alg;
  p->esp_ts.dh_type = dh_type;
  p->esp_ts.crypto_key_size = crypto_key_size;
  return 0;
}

clib_error_t *
ikev2_set_profile_sa_lifetime (vlib_main_t * vm, u8 * name,
			       u64 lifetime, u32 jitter, u32 handover,
			       u64 maxdata)
{
  ikev2_profile_t *p;
  clib_error_t *r;

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  p->lifetime = lifetime;
  p->lifetime_jitter = jitter;
  p->handover = handover;
  p->lifetime_maxdata = maxdata;
  return 0;
}

clib_error_t *
ikev2_initiate_sa_init (vlib_main_t * vm, u8 * name)
{
  ikev2_profile_t *p;
  clib_error_t *r;
  ip4_main_t *im = &ip4_main;
  ikev2_main_t *km = &ikev2_main;

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  if (p->responder.sw_if_index == ~0 || p->responder.ip4.data_u32 == 0)
    {
      r = clib_error_return (0, "responder not set for profile %v", name);
      return r;
    }


  /* Create the Initiator Request */
  {
    ike_header_t *ike0;
    u32 bi0 = 0;
    ip_lookup_main_t *lm = &im->lookup_main;
    u32 if_add_index0;
    int len = sizeof (ike_header_t);

    /* Get own iface IP */
    if_add_index0 =
      lm->if_address_pool_index_by_sw_if_index[p->responder.sw_if_index];
    ip_interface_address_t *if_add =
      pool_elt_at_index (lm->if_address_pool, if_add_index0);
    ip4_address_t *if_ip = ip_interface_address_get_address (lm, if_add);

    bi0 = ikev2_get_new_ike_header_buff (vm, &ike0);

    /* Prepare the SA and the IKE payload */
    ikev2_sa_t sa;
    memset (&sa, 0, sizeof (ikev2_sa_t));
    ikev2_payload_chain_t *chain = 0;
    ikev2_payload_new_chain (chain);

    /* Build the IKE proposal payload */
    ikev2_sa_proposal_t *proposals = 0;
    ikev2_set_initiator_proposals (vm, &sa, &p->ike_ts, &proposals, 1);
    proposals[0].proposal_num = 1;
    proposals[0].protocol_id = IKEV2_PROTOCOL_IKE;

    /* Add and then cleanup proposal data */
    ikev2_payload_add_sa (chain, proposals);
    ikev2_sa_free_proposal_vector (&proposals);

    sa.is_initiator = 1;
    sa.profile = p;
    sa.state = IKEV2_STATE_SA_INIT;
    ikev2_generate_sa_init_data (&sa);
    ikev2_payload_add_ke (chain, sa.dh_group, sa.i_dh_data);
    ikev2_payload_add_nonce (chain, sa.i_nonce);

    /* Build the child SA proposal */
    vec_resize (sa.childs, 1);
    ikev2_set_initiator_proposals (vm, &sa, &p->esp_ts,
				   &sa.childs[0].i_proposals, 0);
    sa.childs[0].i_proposals[0].proposal_num = 1;
    sa.childs[0].i_proposals[0].protocol_id = IKEV2_PROTOCOL_ESP;
    RAND_bytes ((u8 *) & sa.childs[0].i_proposals[0].spi,
		sizeof (sa.childs[0].i_proposals[0].spi));



    /* Add NAT detection notification messages (mandatory) */
    u8 nat_detection_source[8 + 8 + 4 + 2];
    u8 *nat_detection_sha1 = vec_new (u8, 20);

    u64 tmpspi = clib_host_to_net_u64 (sa.ispi);
    clib_memcpy (&nat_detection_source[0], &tmpspi, sizeof (tmpspi));
    tmpspi = clib_host_to_net_u64 (sa.rspi);
    clib_memcpy (&nat_detection_source[8], &tmpspi, sizeof (tmpspi));
    u16 tmpport = clib_host_to_net_u16 (500);
    clib_memcpy (&nat_detection_source[8 + 8 + 4], &tmpport,
		 sizeof (tmpport));
    u32 tmpip = clib_host_to_net_u32 (if_ip->as_u32);
    clib_memcpy (&nat_detection_source[8 + 8], &tmpip, sizeof (tmpip));
    SHA1 (nat_detection_source, sizeof (nat_detection_source),
	  nat_detection_sha1);
    ikev2_payload_add_notify (chain, IKEV2_NOTIFY_MSG_NAT_DETECTION_SOURCE_IP,
			      nat_detection_sha1);
    tmpip = clib_host_to_net_u32 (p->responder.ip4.as_u32);
    clib_memcpy (&nat_detection_source[8 + 8], &tmpip, sizeof (tmpip));
    SHA1 (nat_detection_source, sizeof (nat_detection_source),
	  nat_detection_sha1);
    ikev2_payload_add_notify (chain,
			      IKEV2_NOTIFY_MSG_NAT_DETECTION_DESTINATION_IP,
			      nat_detection_sha1);
    vec_free (nat_detection_sha1);

    u8 *sig_hash_algo = vec_new (u8, 8);
    u64 tmpsig = clib_host_to_net_u64 (0x0001000200030004);
    clib_memcpy (sig_hash_algo, &tmpsig, sizeof (tmpsig));
    ikev2_payload_add_notify (chain,
			      IKEV2_NOTIFY_MSG_SIGNATURE_HASH_ALGORITHMS,
			      sig_hash_algo);
    vec_free (sig_hash_algo);


    /* Buffer update and bolierplate */
    len += vec_len (chain->data);
    ike0->nextpayload = chain->first_payload_type;
    ike0->length = clib_host_to_net_u32 (len);
    clib_memcpy (ike0->payload, chain->data, vec_len (chain->data));
    ikev2_payload_destroy_chain (chain);

    ike0->version = IKE_VERSION_2;
    ike0->flags = IKEV2_HDR_FLAG_INITIATOR;
    ike0->exchange = IKEV2_EXCHANGE_SA_INIT;
    ike0->ispi = sa.ispi;

    /* store whole IKE payload - needed for PSK auth */
    vec_free (sa.last_sa_init_req_packet_data);
    vec_add (sa.last_sa_init_req_packet_data, ike0, len);

    /* add data to the SA then add it to the pool */
    sa.iaddr.as_u32 = if_ip->as_u32;
    sa.raddr.as_u32 = p->responder.ip4.as_u32;
    sa.i_id.type = p->loc_id.type;
    sa.i_id.data = vec_dup (p->loc_id.data);
    sa.i_auth.method = p->auth.method;
    sa.i_auth.hex = p->auth.hex;
    sa.i_auth.data = vec_dup (p->auth.data);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    clib_memcpy (sa.i_auth.key, p->auth.key, EVP_PKEY_size (p->auth.key));
#else
    sa.i_auth.key = vec_dup (p->auth.key);
#endif
    vec_add (sa.childs[0].tsi, &p->loc_ts, 1);
    vec_add (sa.childs[0].tsr, &p->rem_ts, 1);

    /* add SA to the pool */
    ikev2_sa_t *sa0 = 0;
    pool_get (km->sais, sa0);
    clib_memcpy (sa0, &sa, sizeof (*sa0));
    hash_set (km->sa_by_ispi, sa0->ispi, sa0 - km->sais);

    ikev2_send_ike (vm, if_ip, &p->responder.ip4, bi0, len);

  }

  return 0;
}

static void
ikev2_delete_child_sa_internal (vlib_main_t * vm, ikev2_sa_t * sa,
				ikev2_child_sa_t * csa)
{
  /* Create the Initiator notification for child SA removal */
  ikev2_main_t *km = &ikev2_main;
  ike_header_t *ike0;
  u32 bi0 = 0;
  int len;

  bi0 = ikev2_get_new_ike_header_buff (vm, &ike0);


  ike0->exchange = IKEV2_EXCHANGE_INFORMATIONAL;
  ike0->ispi = clib_host_to_net_u64 (sa->ispi);
  ike0->rspi = clib_host_to_net_u64 (sa->rspi);
  vec_resize (sa->del, 1);
  sa->del->protocol_id = IKEV2_PROTOCOL_ESP;
  sa->del->spi = csa->i_proposals->spi;
  ike0->msgid = clib_host_to_net_u32 (sa->last_init_msg_id + 1);
  sa->last_init_msg_id = clib_net_to_host_u32 (ike0->msgid);
  len = ikev2_generate_message (sa, ike0, 0);

  ikev2_send_ike (vm, &sa->iaddr, &sa->raddr, bi0, len);

  /* delete local child SA */
  ikev2_delete_tunnel_interface (km->vnet_main, sa, csa);
  ikev2_sa_del_child_sa (sa, csa);
}

clib_error_t *
ikev2_initiate_delete_child_sa (vlib_main_t * vm, u32 ispi)
{
  clib_error_t *r;
  ikev2_main_t *km = &ikev2_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *fsa = 0;
  ikev2_child_sa_t *fchild = 0;

  /* Search for the child SA */
  vec_foreach (tkm, km->per_thread_data)
  {
    ikev2_sa_t *sa;
    if (fchild)
      break;
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      fchild = ikev2_sa_get_child(sa, ispi, IKEV2_PROTOCOL_ESP, 1);
      if (fchild)
        {
          fsa = sa;
          break;
        }
    }));
    /* *INDENT-ON* */
  }

  if (!fchild || !fsa)
    {
      r = clib_error_return (0, "Child SA not found");
      return r;
    }
  else
    {
      ikev2_delete_child_sa_internal (vm, fsa, fchild);
    }

  return 0;
}

clib_error_t *
ikev2_initiate_delete_ike_sa (vlib_main_t * vm, u64 ispi)
{
  clib_error_t *r;
  ikev2_main_t *km = &ikev2_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *fsa = 0;
  ikev2_main_per_thread_data_t *ftkm = 0;

  /* Search for the IKE SA */
  vec_foreach (tkm, km->per_thread_data)
  {
    ikev2_sa_t *sa;
    if (fsa)
      break;
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      if (sa->ispi == ispi)
        {
          fsa = sa;
          ftkm = tkm;
          break;
        }
    }));
    /* *INDENT-ON* */
  }

  if (!fsa)
    {
      r = clib_error_return (0, "IKE SA not found");
      return r;
    }


  /* Create the Initiator notification for IKE SA removal */
  {
    ike_header_t *ike0;
    u32 bi0 = 0;
    int len;

    bi0 = ikev2_get_new_ike_header_buff (vm, &ike0);


    ike0->exchange = IKEV2_EXCHANGE_INFORMATIONAL;
    ike0->ispi = clib_host_to_net_u64 (fsa->ispi);
    ike0->rspi = clib_host_to_net_u64 (fsa->rspi);
    vec_resize (fsa->del, 1);
    fsa->del->protocol_id = IKEV2_PROTOCOL_IKE;
    fsa->del->spi = ispi;
    ike0->msgid = clib_host_to_net_u32 (fsa->last_init_msg_id + 1);
    fsa->last_init_msg_id = clib_net_to_host_u32 (ike0->msgid);
    len = ikev2_generate_message (fsa, ike0, 0);

    ikev2_send_ike (vm, &fsa->iaddr, &fsa->raddr, bi0, len);
  }


  /* delete local SA */
  ikev2_child_sa_t *c;
  vec_foreach (c, fsa->childs)
  {
    ikev2_delete_tunnel_interface (km->vnet_main, fsa, c);
    ikev2_sa_del_child_sa (fsa, c);
  }
  ikev2_sa_free_all_vec (fsa);
  uword *p = hash_get (ftkm->sa_by_rspi, fsa->rspi);
  if (p)
    {
      hash_unset (ftkm->sa_by_rspi, fsa->rspi);
      pool_put (ftkm->sas, fsa);
    }


  return 0;
}

static void
ikev2_rekey_child_sa_internal (vlib_main_t * vm, ikev2_sa_t * sa,
			       ikev2_child_sa_t * csa)
{
  /* Create the Initiator request for create child SA */
  ike_header_t *ike0;
  u32 bi0 = 0;
  int len;


  bi0 = ikev2_get_new_ike_header_buff (vm, &ike0);


  ike0->version = IKE_VERSION_2;
  ike0->flags = IKEV2_HDR_FLAG_INITIATOR;
  ike0->exchange = IKEV2_EXCHANGE_CREATE_CHILD_SA;
  ike0->ispi = clib_host_to_net_u64 (sa->ispi);
  ike0->rspi = clib_host_to_net_u64 (sa->rspi);
  ike0->msgid = clib_host_to_net_u32 (sa->last_init_msg_id + 1);
  sa->last_init_msg_id = clib_net_to_host_u32 (ike0->msgid);

  ikev2_rekey_t *rekey;
  vec_add2 (sa->rekey, rekey, 1);
  ikev2_sa_proposal_t *proposals = vec_dup (csa->i_proposals);

  /*need new ispi */
  RAND_bytes ((u8 *) & proposals[0].spi, sizeof (proposals[0].spi));
  rekey->spi = proposals[0].spi;
  rekey->ispi = csa->i_proposals->spi;
  len = ikev2_generate_message (sa, ike0, proposals);
  ikev2_send_ike (vm, &sa->iaddr, &sa->raddr, bi0, len);
  vec_free (proposals);
}

clib_error_t *
ikev2_initiate_rekey_child_sa (vlib_main_t * vm, u32 ispi)
{
  clib_error_t *r;
  ikev2_main_t *km = &ikev2_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *fsa = 0;
  ikev2_child_sa_t *fchild = 0;

  /* Search for the child SA */
  vec_foreach (tkm, km->per_thread_data)
  {
    ikev2_sa_t *sa;
    if (fchild)
      break;
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      fchild = ikev2_sa_get_child(sa, ispi, IKEV2_PROTOCOL_ESP, 1);
      if (fchild)
        {
          fsa = sa;
          break;
        }
    }));
    /* *INDENT-ON* */
  }

  if (!fchild || !fsa)
    {
      r = clib_error_return (0, "Child SA not found");
      return r;
    }
  else
    {
      ikev2_rekey_child_sa_internal (vm, fsa, fchild);
    }

  return 0;
}

clib_error_t *
ikev2_init (vlib_main_t * vm)
{
  ikev2_main_t *km = &ikev2_main;
  clib_error_t *error;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int thread_id;

  memset (km, 0, sizeof (ikev2_main_t));
  km->vnet_main = vnet_get_main ();
  km->vlib_main = vm;

  ikev2_crypto_init (km);

  mhash_init_vec_string (&km->profile_index_by_name, sizeof (uword));

  vec_validate (km->per_thread_data, tm->n_vlib_mains - 1);
  for (thread_id = 0; thread_id < tm->n_vlib_mains - 1; thread_id++)
    {
      km->per_thread_data[thread_id].sa_by_rspi =
	hash_create (0, sizeof (uword));
    }

  km->sa_by_ispi = hash_create (0, sizeof (uword));


  if ((error = vlib_call_init_function (vm, ikev2_cli_init)))
    return error;

  udp_register_dst_port (vm, 500, ikev2_node.index, 1);

  return 0;
}


static u8
ikev2_mngr_process_child_sa (ikev2_sa_t * sa, ikev2_child_sa_t * csa)
{
  ikev2_main_t *km = &ikev2_main;
  vlib_main_t *vm = km->vlib_main;
  f64 now = vlib_time_now (vm);
  u8 res = 0;

  if (sa->is_initiator && sa->profile && csa->time_to_expiration
      && now > csa->time_to_expiration)
    {
      if (!csa->is_expired || csa->rekey_retries > 0)
	{
	  ikev2_rekey_child_sa_internal (vm, sa, csa);
	  csa->time_to_expiration = now + sa->profile->handover;
	  csa->is_expired = 1;
	  if (csa->rekey_retries == 0)
	    {
	      csa->rekey_retries = 5;
	    }
	  else if (csa->rekey_retries > 0)
	    {
	      csa->rekey_retries--;
	      clib_warning ("Rekeing Child SA 0x%x, retries left %d",
			    csa->i_proposals->spi, csa->rekey_retries);
	      if (csa->rekey_retries == 0)
		{
		  csa->rekey_retries = -1;
		}
	    }
	  res |= 1;
	}
      else
	{
	  csa->time_to_expiration = 0;
	  ikev2_delete_child_sa_internal (vm, sa, csa);
	  res |= 1;
	}
    }

  return res;
}

static void
ikev2_mngr_process_ipsec_sa (ipsec_sa_t * ipsec_sa)
{
  ikev2_main_t *km = &ikev2_main;
  vlib_main_t *vm = km->vlib_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *fsa = 0;
  ikev2_child_sa_t *fchild = 0;
  f64 now = vlib_time_now (vm);

  /* Search for the SA and child SA */
  vec_foreach (tkm, km->per_thread_data)
  {
    ikev2_sa_t *sa;
    if (fchild)
      break;
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      fchild = ikev2_sa_get_child(sa, ipsec_sa->spi, IKEV2_PROTOCOL_ESP, 1);
      if (fchild)
        {
          fsa = sa;
          break;
        }
    }));
    /* *INDENT-ON* */
  }

  if (fchild && fsa && fsa->profile && fsa->profile->lifetime_maxdata)
    {
      if (!fchild->is_expired
	  && ipsec_sa->total_data_size > fsa->profile->lifetime_maxdata)
	{
	  fchild->time_to_expiration = now;
	}
    }
}

static vlib_node_registration_t ikev2_mngr_process_node;

static uword
ikev2_mngr_process_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
		       vlib_frame_t * f)
{
  ikev2_main_t *km = &ikev2_main;
  ipsec_main_t *im = &ipsec_main;

  while (1)
    {
      u8 req_sent = 0;
      vlib_process_wait_for_event_or_clock (vm, 1);
      vlib_process_get_events (vm, NULL);

      /* process ike child sas */
      ikev2_main_per_thread_data_t *tkm;
      vec_foreach (tkm, km->per_thread_data)
      {
	ikev2_sa_t *sa;
        /* *INDENT-OFF* */
        pool_foreach (sa, tkm->sas, ({
          ikev2_child_sa_t *c;
          vec_foreach (c, sa->childs)
            {
            req_sent |= ikev2_mngr_process_child_sa(sa, c);
            }
        }));
        /* *INDENT-ON* */
      }

      /* process ipsec sas */
      ipsec_sa_t *sa;
      /* *INDENT-OFF* */
      pool_foreach (sa, im->sad, ({
        ikev2_mngr_process_ipsec_sa(sa);
      }));
      /* *INDENT-ON* */

      if (req_sent)
	{
	  vlib_process_wait_for_event_or_clock (vm, 5);
	  vlib_process_get_events (vm, NULL);
	  req_sent = 0;
	}

    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ikev2_mngr_process_node, static) = {
    .function = ikev2_mngr_process_fn,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name =
    "ikev2-manager-process",
};

/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
