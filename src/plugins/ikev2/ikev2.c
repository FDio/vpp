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
#include <vlib/unix/plugin.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vppinfra/random.h>
#include <vnet/udp/udp.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ipsec_tun.h>
#include <vnet/ipip/ipip.h>
#include <plugins/ikev2/ikev2.h>
#include <plugins/ikev2/ikev2_priv.h>
#include <openssl/sha.h>
#include <vnet/ipsec/ipsec_punt.h>

#define IKEV2_LIVENESS_RETRIES 3
#define IKEV2_LIVENESS_PERIOD_CHECK 30

ikev2_main_t ikev2_main;

static int ikev2_delete_tunnel_interface (vnet_main_t * vnm,
					  ikev2_sa_t * sa,
					  ikev2_child_sa_t * child);

#define ikev2_set_state(sa, v) do { \
    (sa)->state = v; \
    ikev2_elog_sa_state("ispi %lx SA state changed to " #v, sa->ispi); \
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

#define IKEV2_GENERATE_SA_INIT_OK_str ""
#define IKEV2_GENERATE_SA_INIT_OK_ERR_NO_DH_STR \
  "no DH group configured for IKE proposals!"
#define IKEV2_GENERATE_SA_INIT_OK_ERR_UNSUPP_STR \
  "DH group not supported!"

typedef enum
{
  IKEV2_GENERATE_SA_INIT_OK,
  IKEV2_GENERATE_SA_INIT_ERR_NO_DH,
  IKEV2_GENERATE_SA_INIT_ERR_UNSUPPORTED_DH,
} ikev2_generate_sa_error_t;

static u8 *
format_ikev2_gen_sa_error (u8 * s, va_list * args)
{
  ikev2_generate_sa_error_t e = va_arg (*args, ikev2_generate_sa_error_t);
  switch (e)
    {
    case IKEV2_GENERATE_SA_INIT_OK:
      break;
    case IKEV2_GENERATE_SA_INIT_ERR_NO_DH:
      s = format (s, IKEV2_GENERATE_SA_INIT_OK_ERR_NO_DH_STR);
      break;
    case IKEV2_GENERATE_SA_INIT_ERR_UNSUPPORTED_DH:
      s = format (s, IKEV2_GENERATE_SA_INIT_OK_ERR_UNSUPP_STR);
      break;
    }
  return s;
}

#define foreach_ikev2_error \
_(PROCESSED, "IKEv2 packets processed") \
_(IKE_SA_INIT_RETRANSMIT, "IKE_SA_INIT retransmit ") \
_(IKE_SA_INIT_IGNORE, "IKE_SA_INIT ignore (IKE SA already auth)") \
_(IKE_REQ_RETRANSMIT, "IKE request retransmit") \
_(IKE_REQ_IGNORE, "IKE request ignore (old msgid)") \
_(NOT_IKEV2, "Non IKEv2 packets received") \
_(BAD_LENGTH, "Bad packet length") \
_(MALFORMED_PACKET, "Malformed packet") \
_(NO_BUFF_SPACE, "No buffer space")

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
  IKEV2_NEXT_IP4_ERROR_DROP,
  IKEV2_IP4_N_NEXT,
} ikev2_ip4_next_t;

typedef enum
{
  IKEV2_NEXT_IP6_LOOKUP,
  IKEV2_NEXT_IP6_ERROR_DROP,
  IKEV2_IP6_N_NEXT,
} ikev2_ip6_next_t;

typedef u32 ikev2_non_esp_marker;

static_always_inline u16
ikev2_get_port (ikev2_sa_t * sa)
{
  return ikev2_natt_active (sa) ? IKEV2_PORT_NATT : IKEV2_PORT;
}

static_always_inline int
ikev2_insert_non_esp_marker (ike_header_t * ike, int len)
{
  memmove ((u8 *) ike + sizeof (ikev2_non_esp_marker), ike, len);
  clib_memset (ike, 0, sizeof (ikev2_non_esp_marker));
  return len + sizeof (ikev2_non_esp_marker);
}

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
	(1 << IKEV2_TRANSFORM_TYPE_PRF) | (1 << IKEV2_TRANSFORM_TYPE_DH);
      optional_bitmap = mandatory_bitmap | (1 << IKEV2_TRANSFORM_TYPE_INTEG);
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
	  clib_memcpy_fast (new_t, transform, sizeof (*new_t));
	  new_t->attrs = vec_dup (transform->attrs);
	}
    }

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
}

static void
ikev2_sa_free_child_sa (ikev2_child_sa_t * c)
{
  ikev2_sa_free_proposal_vector (&c->r_proposals);
  ikev2_sa_free_proposal_vector (&c->i_proposals);
  vec_free (c->sk_ai);
  vec_free (c->sk_ar);
  vec_free (c->sk_ei);
  vec_free (c->sk_er);
  vec_free (c->tsi);
  vec_free (c->tsr);
}

static void
ikev2_sa_free_all_child_sa (ikev2_child_sa_t ** childs)
{
  ikev2_child_sa_t *c;
  vec_foreach (c, *childs) ikev2_sa_free_child_sa (c);

  vec_free (*childs);
}

static void
ikev2_sa_del_child_sa (ikev2_sa_t * sa, ikev2_child_sa_t * child)
{
  ikev2_sa_free_child_sa (child);
  vec_del1 (sa->childs, child - sa->childs);
}

static void
ikev2_sa_free_all_vec (ikev2_sa_t * sa)
{
  vec_free (sa->i_nonce);
  vec_free (sa->r_nonce);

  vec_free (sa->dh_shared_key);
  vec_free (sa->dh_private_key);
  vec_free (sa->i_dh_data);
  vec_free (sa->r_dh_data);

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
  vec_free (sa->r_id.data);

  vec_free (sa->i_auth.data);
  if (sa->i_auth.key)
    EVP_PKEY_free (sa->i_auth.key);
  vec_free (sa->r_auth.data);
  if (sa->r_auth.key)
    EVP_PKEY_free (sa->r_auth.key);

  vec_free (sa->del);

  vec_free (sa->rekey);

  vec_free (sa->last_sa_init_req_packet_data);
  vec_free (sa->last_sa_init_res_packet_data);

  vec_free (sa->last_res_packet_data);

  ikev2_sa_free_all_child_sa (&sa->childs);
}

static void
ikev2_delete_sa (ikev2_main_per_thread_data_t * ptd, ikev2_sa_t * sa)
{
  uword *p;

  ikev2_sa_free_all_vec (sa);

  p = hash_get (ptd->sa_by_rspi, sa->rspi);
  if (p)
    {
      hash_unset (ptd->sa_by_rspi, sa->rspi);
      pool_put (ptd->sas, sa);
    }
}

static ikev2_generate_sa_error_t
ikev2_generate_sa_init_data (ikev2_sa_t * sa)
{
  ikev2_sa_transform_t *t = 0, *t2;
  ikev2_main_t *km = &ikev2_main;

  if (sa->dh_group == IKEV2_TRANSFORM_DH_TYPE_NONE)
    return IKEV2_GENERATE_SA_INIT_ERR_NO_DH;

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
      sa->dh_group = IKEV2_TRANSFORM_DH_TYPE_NONE;
      return IKEV2_GENERATE_SA_INIT_ERR_UNSUPPORTED_DH;
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

  return IKEV2_GENERATE_SA_INIT_OK;
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
  ip_address_copy (&sa->iaddr, &sai->iaddr);
  ip_address_copy (&sa->raddr, &sai->raddr);
  sa->is_initiator = sai->is_initiator;
  sa->i_id.type = sai->i_id.type;
  sa->r_id.type = sai->r_id.type;
  sa->profile_index = sai->profile_index;
  sa->tun_itf = sai->tun_itf;
  sa->is_tun_itf_set = sai->is_tun_itf_set;
  sa->natt_state = sai->natt_state;
  sa->i_id.data = _(sai->i_id.data);
  sa->r_id.data = _(sai->r_id.data);
  sa->i_auth.method = sai->i_auth.method;
  sa->i_auth.hex = sai->i_auth.hex;
  sa->i_auth.data = _(sai->i_auth.data);
  sa->i_auth.key = _(sai->i_auth.key);
  sa->last_sa_init_req_packet_data = _(sai->last_sa_init_req_packet_data);
  sa->last_init_msg_id = sai->last_init_msg_id;
  sa->childs = _(sai->childs);
  sa->udp_encap = sai->udp_encap;
  sa->ipsec_over_udp_port = sai->ipsec_over_udp_port;
  sa->dst_port = sai->dst_port;
  sa->sw_if_index = sai->sw_if_index;
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
  u16 integ_key_len = 0, salt_len = 0;
  ikev2_sa_transform_t *tr_encr, *tr_prf, *tr_integ;
  tr_encr =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  tr_prf =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);
  tr_integ =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);

  if (tr_integ)
    integ_key_len = tr_integ->key_len;
  else
    salt_len = sizeof (u32);

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
    integ_key_len * 2 +		/* SK_ai, SK_ar */
    tr_encr->key_len * 2 +	/* SK_ei, SK_er */
    tr_prf->key_len * 2 +	/* SK_pi, SK_pr */
    salt_len * 2;

  keymat = ikev2_calc_prfplus (tr_prf, skeyseed, s, len);
  vec_free (skeyseed);
  vec_free (s);

  int pos = 0;

  /* SK_d */
  sa->sk_d = vec_new (u8, tr_prf->key_trunc);
  clib_memcpy_fast (sa->sk_d, keymat + pos, tr_prf->key_trunc);
  pos += tr_prf->key_trunc;

  if (integ_key_len)
    {
      /* SK_ai */
      sa->sk_ai = vec_new (u8, integ_key_len);
      clib_memcpy_fast (sa->sk_ai, keymat + pos, integ_key_len);
      pos += integ_key_len;

      /* SK_ar */
      sa->sk_ar = vec_new (u8, integ_key_len);
      clib_memcpy_fast (sa->sk_ar, keymat + pos, integ_key_len);
      pos += integ_key_len;
    }

  /* SK_ei */
  sa->sk_ei = vec_new (u8, tr_encr->key_len + salt_len);
  clib_memcpy_fast (sa->sk_ei, keymat + pos, tr_encr->key_len + salt_len);
  pos += tr_encr->key_len + salt_len;

  /* SK_er */
  sa->sk_er = vec_new (u8, tr_encr->key_len + salt_len);
  clib_memcpy_fast (sa->sk_er, keymat + pos, tr_encr->key_len + salt_len);
  pos += tr_encr->key_len + salt_len;

  /* SK_pi */
  sa->sk_pi = vec_new (u8, tr_prf->key_len);
  clib_memcpy_fast (sa->sk_pi, keymat + pos, tr_prf->key_len);
  pos += tr_prf->key_len;

  /* SK_pr */
  sa->sk_pr = vec_new (u8, tr_prf->key_len);
  clib_memcpy_fast (sa->sk_pr, keymat + pos, tr_prf->key_len);
  pos += tr_prf->key_len;

  vec_free (keymat);
  sa->keys_generated = 1;
}

static void
ikev2_calc_child_keys (ikev2_sa_t * sa, ikev2_child_sa_t * child)
{
  u8 *s = 0;
  u16 integ_key_len = 0;
  u8 salt_len = 0;

  ikev2_sa_transform_t *tr_prf, *ctr_encr, *ctr_integ;
  tr_prf =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);
  ctr_encr =
    ikev2_sa_get_td_for_type (child->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  ctr_integ =
    ikev2_sa_get_td_for_type (child->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);

  if (ctr_integ)
    integ_key_len = ctr_integ->key_len;
  else
    salt_len = sizeof (u32);

  vec_append (s, sa->i_nonce);
  vec_append (s, sa->r_nonce);
  /* calculate PRFplus */
  u8 *keymat;
  int len = ctr_encr->key_len * 2 + integ_key_len * 2 + salt_len * 2;

  keymat = ikev2_calc_prfplus (tr_prf, sa->sk_d, s, len);

  int pos = 0;

  /* SK_ei */
  child->sk_ei = vec_new (u8, ctr_encr->key_len);
  clib_memcpy_fast (child->sk_ei, keymat + pos, ctr_encr->key_len);
  pos += ctr_encr->key_len;

  if (ctr_integ)
    {
      /* SK_ai */
      child->sk_ai = vec_new (u8, ctr_integ->key_len);
      clib_memcpy_fast (child->sk_ai, keymat + pos, ctr_integ->key_len);
      pos += ctr_integ->key_len;
    }
  else
    {
      clib_memcpy (&child->salt_ei, keymat + pos, salt_len);
      pos += salt_len;
    }

  /* SK_er */
  child->sk_er = vec_new (u8, ctr_encr->key_len);
  clib_memcpy_fast (child->sk_er, keymat + pos, ctr_encr->key_len);
  pos += ctr_encr->key_len;

  if (ctr_integ)
    {
      /* SK_ar */
      child->sk_ar = vec_new (u8, integ_key_len);
      clib_memcpy_fast (child->sk_ar, keymat + pos, integ_key_len);
      pos += integ_key_len;
    }
  else
    {
      clib_memcpy (&child->salt_er, keymat + pos, salt_len);
      pos += salt_len;
    }

  ASSERT (pos == len);

  vec_free (keymat);
}

static_always_inline u8 *
ikev2_compute_nat_sha1 (u64 ispi, u64 rspi, ip_address_t * ia, u16 port)
{
  const u32 max_buf_size =
    sizeof (ispi) + sizeof (rspi) + sizeof (ip6_address_t) + sizeof (u16);
  u8 buf[max_buf_size];
  u8 *res = vec_new (u8, 20);

  clib_memcpy_fast (&buf[0], &ispi, sizeof (ispi));
  clib_memcpy_fast (&buf[8], &rspi, sizeof (rspi));
  clib_memcpy_fast (&buf[8 + 8], ip_addr_bytes (ia), ip_address_size (ia));
  clib_memcpy_fast (&buf[8 + 8 + ip_address_size (ia)], &port, sizeof (port));
  SHA1 (buf, 2 * sizeof (ispi) + sizeof (port) + ip_address_size (ia), res);
  return res;
}

static int
ikev2_parse_ke_payload (const void *p, u32 rlen, ikev2_sa_t * sa,
			u8 ** ke_data)
{
  const ike_ke_payload_header_t *ke = p;
  u16 plen = clib_net_to_host_u16 (ke->length);
  ASSERT (plen >= sizeof (*ke) && plen <= rlen);
  if (sizeof (*ke) > rlen)
    return 0;

  sa->dh_group = clib_net_to_host_u16 (ke->dh_group);
  vec_reset_length (ke_data[0]);
  vec_add (ke_data[0], ke->payload, plen - sizeof (*ke));
  return 1;
}

static int
ikev2_parse_nonce_payload (const void *p, u32 rlen, u8 * nonce)
{
  const ike_payload_header_t *ikep = p;
  u16 plen = clib_net_to_host_u16 (ikep->length);
  ASSERT (plen >= sizeof (*ikep) && plen <= rlen);
  clib_memcpy_fast (nonce, ikep->payload, plen - sizeof (*ikep));
  return 1;
}

static int
ikev2_check_payload_length (const ike_payload_header_t * ikep, int rlen,
			    u16 * plen)
{
  if (sizeof (*ikep) > rlen)
    return 0;
  *plen = clib_net_to_host_u16 (ikep->length);
  if (*plen < sizeof (*ikep) || *plen > rlen)
    return 0;
  return 1;
}

static int
ikev2_process_sa_init_req (vlib_main_t * vm,
			   ikev2_sa_t * sa, ike_header_t * ike,
			   udp_header_t * udp, u32 len)
{
  u8 nonce[IKEV2_NONCE_SIZE];
  int p = 0;
  u8 payload = ike->nextpayload;
  ike_payload_header_t *ikep;
  u16 plen;

  ikev2_elog_exchange ("ispi %lx rspi %lx IKE_INIT request received "
		       "from ", clib_net_to_host_u64 (ike->ispi),
		       clib_net_to_host_u64 (ike->rspi),
		       ip_addr_v4 (&sa->iaddr).as_u32,
		       ip_addr_version (&sa->iaddr) == AF_IP4);

  sa->ispi = clib_net_to_host_u64 (ike->ispi);

  /* store whole IKE payload - needed for PSK auth */
  vec_reset_length (sa->last_sa_init_req_packet_data);
  vec_add (sa->last_sa_init_req_packet_data, ike, len);

  if (len < sizeof (*ike))
    return 0;

  len -= sizeof (*ike);
  while (p < len && payload != IKEV2_PAYLOAD_NONE)
    {
      ikep = (ike_payload_header_t *) & ike->payload[p];
      int current_length = len - p;
      if (!ikev2_check_payload_length (ikep, current_length, &plen))
	return 0;

      if (payload == IKEV2_PAYLOAD_SA)
	{
	  ikev2_sa_free_proposal_vector (&sa->i_proposals);
	  sa->i_proposals = ikev2_parse_sa_payload (ikep, current_length);
	}
      else if (payload == IKEV2_PAYLOAD_KE)
	{
	  if (!ikev2_parse_ke_payload (ikep, current_length, sa,
				       &sa->i_dh_data))
	    return 0;
	}
      else if (payload == IKEV2_PAYLOAD_NONCE)
	{
	  vec_reset_length (sa->i_nonce);
	  if (ikev2_parse_nonce_payload (ikep, current_length, nonce))
	    vec_add (sa->i_nonce, nonce, plen - sizeof (*ikep));
	}
      else if (payload == IKEV2_PAYLOAD_NOTIFY)
	{
	  ikev2_notify_t *n =
	    ikev2_parse_notify_payload (ikep, current_length);
	  if (n->msg_type == IKEV2_NOTIFY_MSG_NAT_DETECTION_SOURCE_IP)
	    {
	      u8 *src_sha = ikev2_compute_nat_sha1 (ike->ispi, 0, &sa->iaddr,
						    udp->src_port);
	      if (clib_memcmp (src_sha, n->data, vec_len (src_sha)))
		{
		  if (sa->natt_state == IKEV2_NATT_ENABLED)
		    sa->natt_state = IKEV2_NATT_ACTIVE;
		  ikev2_elog_uint (IKEV2_LOG_DEBUG, "ispi %lx initiator"
				   " behind NAT", sa->ispi);
		}
	      vec_free (src_sha);
	    }
	  else if (n->msg_type ==
		   IKEV2_NOTIFY_MSG_NAT_DETECTION_DESTINATION_IP)
	    {
	      u8 *dst_sha = ikev2_compute_nat_sha1 (ike->ispi, 0, &sa->raddr,
						    udp->dst_port);
	      if (clib_memcmp (dst_sha, n->data, vec_len (dst_sha)))
		{
		  if (sa->natt_state == IKEV2_NATT_ENABLED)
		    sa->natt_state = IKEV2_NATT_ACTIVE;
		  ikev2_elog_uint (IKEV2_LOG_DEBUG, "ispi %lx responder"
				   " (self) behind NAT", sa->ispi);
		}
	      vec_free (dst_sha);
	    }
	  vec_free (n);
	}
      else if (payload == IKEV2_PAYLOAD_VENDOR)
	{
	  ikev2_parse_vendor_payload (ikep);
	}
      else
	{
	  ikev2_elog_uint (IKEV2_LOG_ERROR, "Unknown payload! type=%d",
			   payload);
	  if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
	    {
	      ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
	      sa->unsupported_cp = payload;
	      return 0;
	    }
	}

      payload = ikep->nextpayload;
      p += plen;
    }

  ikev2_set_state (sa, IKEV2_STATE_SA_INIT);
  return 1;
}

static void
ikev2_process_sa_init_resp (vlib_main_t * vm,
			    ikev2_sa_t * sa, ike_header_t * ike,
			    udp_header_t * udp, u32 len)
{
  u8 nonce[IKEV2_NONCE_SIZE];
  int p = 0;
  u8 payload = ike->nextpayload;
  ike_payload_header_t *ikep;
  u16 plen;

  sa->ispi = clib_net_to_host_u64 (ike->ispi);
  sa->rspi = clib_net_to_host_u64 (ike->rspi);

  ikev2_elog_exchange ("ispi %lx rspi %lx IKE_INIT response received "
		       "from ", sa->ispi, sa->rspi,
		       ip_addr_v4 (&sa->raddr).as_u32,
		       ip_addr_version (&sa->raddr) == AF_IP4);

  /* store whole IKE payload - needed for PSK auth */
  vec_reset_length (sa->last_sa_init_res_packet_data);
  vec_add (sa->last_sa_init_res_packet_data, ike, len);

  if (sizeof (*ike) > len)
    return;

  len -= sizeof (*ike);
  while (p < len && payload != IKEV2_PAYLOAD_NONE)
    {
      int current_length = len - p;
      ikep = (ike_payload_header_t *) & ike->payload[p];
      if (!ikev2_check_payload_length (ikep, current_length, &plen))
	return;

      if (payload == IKEV2_PAYLOAD_SA)
	{
	  ikev2_sa_free_proposal_vector (&sa->r_proposals);
	  sa->r_proposals = ikev2_parse_sa_payload (ikep, current_length);
	  if (sa->r_proposals)
	    {
	      ikev2_set_state (sa, IKEV2_STATE_SA_INIT);
	      ike->msgid =
		clib_host_to_net_u32 (clib_net_to_host_u32 (ike->msgid) + 1);
	    }
	}
      else if (payload == IKEV2_PAYLOAD_KE)
	{
	  if (!ikev2_parse_ke_payload (ikep, current_length, sa,
				       &sa->r_dh_data))
	    return;
	}
      else if (payload == IKEV2_PAYLOAD_NONCE)
	{
	  vec_reset_length (sa->r_nonce);
	  if (ikev2_parse_nonce_payload (ikep, current_length, nonce))
	    vec_add (sa->r_nonce, nonce, plen - sizeof (*ikep));
	}
      else if (payload == IKEV2_PAYLOAD_NOTIFY)
	{
	  ikev2_notify_t *n =
	    ikev2_parse_notify_payload (ikep, current_length);
	  if (n->msg_type == IKEV2_NOTIFY_MSG_NAT_DETECTION_SOURCE_IP)
	    {
	      u8 *src_sha = ikev2_compute_nat_sha1 (ike->ispi, ike->rspi,
						    &sa->raddr,
						    udp->src_port);
	      if (clib_memcmp (src_sha, n->data, vec_len (src_sha)))
		{
		  ikev2_elog_uint (IKEV2_LOG_DEBUG, "ispi %lx responder"
				   " behind NAT, unsupported", sa->ispi);
		}
	      vec_free (src_sha);
	    }
	  else if (n->msg_type ==
		   IKEV2_NOTIFY_MSG_NAT_DETECTION_DESTINATION_IP)
	    {
	      u8 *dst_sha = ikev2_compute_nat_sha1 (ike->ispi, ike->rspi,
						    &sa->iaddr,
						    udp->dst_port);
	      if (clib_memcmp (dst_sha, n->data, vec_len (dst_sha)))
		{
		  if (sa->natt_state == IKEV2_NATT_ENABLED)
		    sa->natt_state = IKEV2_NATT_ACTIVE;
		  ikev2_elog_uint (IKEV2_LOG_DEBUG, "ispi %lx initiator"
				   " (self) behind NAT", sa->ispi);
		}
	      vec_free (dst_sha);
	    }
	  vec_free (n);
	}
      else if (payload == IKEV2_PAYLOAD_VENDOR)
	{
	  ikev2_parse_vendor_payload (ikep);
	}
      else
	{
	  ikev2_elog_uint (IKEV2_LOG_ERROR, "Unknown payload! type=%d",
			   payload);
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
ikev2_decrypt_sk_payload (ikev2_sa_t * sa, ike_header_t * ike,
			  u8 * payload, u32 rlen, u32 * out_len)
{
  ikev2_main_per_thread_data_t *ptd = ikev2_get_per_thread_data ();
  int p = 0;
  u8 last_payload = 0, *hmac = 0, *plaintext = 0;
  ike_payload_header_t *ikep = 0;
  u16 plen = 0;
  u32 dlen = 0;
  ikev2_sa_transform_t *tr_integ;
  ikev2_sa_transform_t *tr_encr;
  tr_integ =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);
  tr_encr =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  int is_aead = tr_encr->encr_type == IKEV2_TRANSFORM_ENCR_TYPE_AES_GCM_16;

  if (((!sa->sk_ar || !sa->sk_ai) && !is_aead) || (!sa->sk_ei || !sa->sk_er))
    return 0;

  if (rlen <= sizeof (*ike))
    return 0;

  int len = rlen - sizeof (*ike);
  while (p < len &&
	 *payload != IKEV2_PAYLOAD_NONE && last_payload != IKEV2_PAYLOAD_SK)
    {
      ikep = (ike_payload_header_t *) & ike->payload[p];
      int current_length = len - p;
      if (!ikev2_check_payload_length (ikep, current_length, &plen))
	return 0;

      if (*payload == IKEV2_PAYLOAD_SK)
	{
	  last_payload = *payload;
	}
      else
	{
	  ikev2_elog_uint (IKEV2_LOG_ERROR, "Unknown payload! type=%d",
			   *payload);
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
      ikev2_elog_error ("Last payload must be SK");
      return 0;
    }

  if (is_aead)
    {
      if (plen < sizeof (*ikep) + IKEV2_GCM_ICV_SIZE)
	return 0;

      plen -= sizeof (*ikep) + IKEV2_GCM_ICV_SIZE;
      u8 *aad = (u8 *) ike;
      u32 aad_len = ikep->payload - aad;
      u8 *tag = ikep->payload + plen;

      int rc = ikev2_decrypt_aead_data (ptd, sa, tr_encr, ikep->payload,
					plen, aad, aad_len, tag, &dlen);
      if (rc)
	{
	  *out_len = dlen;
	  plaintext = ikep->payload + IKEV2_GCM_IV_SIZE;
	}
    }
  else
    {
      if (rlen < tr_integ->key_trunc)
	return 0;

      hmac =
	ikev2_calc_integr (tr_integ, sa->is_initiator ? sa->sk_ar : sa->sk_ai,
			   (u8 *) ike, rlen - tr_integ->key_trunc);

      if (plen < sizeof (*ikep) + tr_integ->key_trunc)
	return 0;

      plen = plen - sizeof (*ikep) - tr_integ->key_trunc;

      if (clib_memcmp (hmac, &ikep->payload[plen], tr_integ->key_trunc))
	{
	  ikev2_elog_error ("message integrity check failed");
	  vec_free (hmac);
	  return 0;
	}
      vec_free (hmac);

      int rc = ikev2_decrypt_data (ptd, sa, tr_encr, ikep->payload, plen,
				   &dlen);
      if (rc)
	{
	  *out_len = dlen;
	  plaintext = ikep->payload + tr_encr->block_size;
	}
    }

  return plaintext;
}

static_always_inline int
ikev2_is_id_equal (ikev2_id_t * i1, ikev2_id_t * i2)
{
  if (i1->type != i2->type)
    return 0;

  if (vec_len (i1->data) != vec_len (i2->data))
    return 0;

  if (clib_memcmp (i1->data, i2->data, vec_len (i1->data)))
    return 0;

  return 1;
}

static void
ikev2_initial_contact_cleanup_internal (ikev2_main_per_thread_data_t * ptd,
					ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_sa_t *tmp;
  u32 i, *delete = 0;
  ikev2_child_sa_t *c;

  /* find old IKE SAs with the same authenticated identity */
  /* *INDENT-OFF* */
  pool_foreach (tmp, ptd->sas, ({
    if (!ikev2_is_id_equal (&tmp->i_id, &sa->i_id)
        || !ikev2_is_id_equal(&tmp->r_id, &sa->r_id))
      continue;

    if (sa->rspi != tmp->rspi)
      vec_add1(delete, tmp - ptd->sas);
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (delete); i++)
    {
      tmp = pool_elt_at_index (ptd->sas, delete[i]);
      vec_foreach (c, tmp->childs)
      {
	ikev2_delete_tunnel_interface (km->vnet_main, tmp, c);
      }
      ikev2_delete_sa (ptd, tmp);
    }

  vec_free (delete);
  sa->initial_contact = 0;
}

static void
ikev2_initial_contact_cleanup (ikev2_main_per_thread_data_t * ptd,
			       ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;

  if (!sa->initial_contact)
    return;

  if (ptd)
    {
      ikev2_initial_contact_cleanup_internal (ptd, sa);
    }
  else
    {
      vec_foreach (ptd, km->per_thread_data)
	ikev2_initial_contact_cleanup_internal (ptd, sa);
    }
  sa->initial_contact = 0;
}

static int
ikev2_parse_id_payload (const void *p, u16 rlen, ikev2_id_t * sa_id)
{
  const ike_id_payload_header_t *id = p;
  u16 plen = clib_net_to_host_u16 (id->length);
  if (plen < sizeof (*id) || plen > rlen)
    return 0;

  sa_id->type = id->id_type;
  vec_reset_length (sa_id->data);
  vec_add (sa_id->data, id->payload, plen - sizeof (*id));

  return 1;
}

static int
ikev2_parse_auth_payload (const void *p, u32 rlen, ikev2_auth_t * a)
{
  const ike_auth_payload_header_t *ah = p;
  u16 plen = clib_net_to_host_u16 (ah->length);

  a->method = ah->auth_method;
  vec_reset_length (a->data);
  vec_add (a->data, ah->payload, plen - sizeof (*ah));
  return 1;
}

static int
ikev2_process_auth_req (vlib_main_t * vm, ikev2_sa_t * sa,
			ike_header_t * ike, u32 len)
{
  int p = 0;
  ikev2_child_sa_t *first_child_sa;
  u8 payload = ike->nextpayload;
  u8 *plaintext = 0;
  ike_payload_header_t *ikep;
  u16 plen;
  u32 dlen = 0;

  ikev2_elog_exchange ("ispi %lx rspi %lx EXCHANGE_IKE_AUTH received "
		       "from ", clib_host_to_net_u64 (ike->ispi),
		       clib_host_to_net_u64 (ike->rspi),
		       sa->is_initiator ?
		       ip_addr_v4 (&sa->raddr).as_u32 :
		       ip_addr_v4 (&sa->iaddr).as_u32,
		       ip_addr_version (&sa->raddr) == AF_IP4);

  ikev2_calc_keys (sa);

  plaintext = ikev2_decrypt_sk_payload (sa, ike, &payload, len, &dlen);

  if (!plaintext)
    {
      if (sa->unsupported_cp)
	{
	  ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
	  return 0;
	}
      goto malformed;
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
  while (p < dlen && payload != IKEV2_PAYLOAD_NONE)
    {
      ikep = (ike_payload_header_t *) & plaintext[p];
      int current_length = dlen - p;
      if (!ikev2_check_payload_length (ikep, current_length, &plen))
	goto malformed;

      if (payload == IKEV2_PAYLOAD_SA)	/* 33 */
	{
	  if (sa->is_initiator)
	    {
	      ikev2_sa_free_proposal_vector (&first_child_sa->r_proposals);
	      first_child_sa->r_proposals = ikev2_parse_sa_payload (ikep,
								    current_length);
	    }
	  else
	    {
	      ikev2_sa_free_proposal_vector (&first_child_sa->i_proposals);
	      first_child_sa->i_proposals = ikev2_parse_sa_payload (ikep,
								    current_length);
	    }
	}
      else if (payload == IKEV2_PAYLOAD_IDI)	/* 35 */
	{
	  if (!ikev2_parse_id_payload (ikep, current_length, &sa->i_id))
	    goto malformed;
	}
      else if (payload == IKEV2_PAYLOAD_IDR)	/* 36 */
	{
	  if (!ikev2_parse_id_payload (ikep, current_length, &sa->r_id))
	    goto malformed;
	}
      else if (payload == IKEV2_PAYLOAD_AUTH)	/* 39 */
	{
	  if (sa->is_initiator)
	    {
	      if (!ikev2_parse_auth_payload (ikep, current_length,
					     &sa->r_auth))
		goto malformed;
	    }
	  else
	    {
	      if (!ikev2_parse_auth_payload (ikep, current_length,
					     &sa->i_auth))
		goto malformed;
	    }
	}
      else if (payload == IKEV2_PAYLOAD_NOTIFY)	/* 41 */
	{
	  ikev2_notify_t *n =
	    ikev2_parse_notify_payload (ikep, current_length);
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
	  vec_free (first_child_sa->tsi);
	  first_child_sa->tsi = ikev2_parse_ts_payload (ikep, current_length);
	}
      else if (payload == IKEV2_PAYLOAD_TSR)	/* 45 */
	{
	  vec_free (first_child_sa->tsr);
	  first_child_sa->tsr = ikev2_parse_ts_payload (ikep, current_length);
	}
      else
	{
	  ikev2_elog_uint (IKEV2_LOG_ERROR, "Unknown payload! type=%d",
			   payload);

	  if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
	    {
	      ikev2_set_state (sa, IKEV2_STATE_NOTIFY_AND_DELETE);
	      sa->unsupported_cp = payload;
	      return 0;
	    }
	}

      payload = ikep->nextpayload;
      p += plen;
    }

  return 1;

malformed:
  ikev2_set_state (sa, IKEV2_STATE_DELETED);
  return 0;
}

static int
ikev2_process_informational_req (vlib_main_t * vm,
				 ikev2_sa_t * sa, ike_header_t * ike, u32 len)
{
  int p = 0;
  u8 payload = ike->nextpayload;
  u8 *plaintext = 0;
  ike_payload_header_t *ikep;
  u32 dlen = 0;
  ikev2_notify_t *n = 0;

  sa->liveness_retries = 0;
  ikev2_elog_exchange ("ispi %lx rspi %lx INFORMATIONAL received "
		       "from ", clib_host_to_net_u64 (ike->ispi),
		       clib_host_to_net_u64 (ike->rspi),
		       ip_addr_v4 (&sa->iaddr).as_u32,
		       ip_addr_version (&sa->iaddr) == AF_IP4);

  plaintext = ikev2_decrypt_sk_payload (sa, ike, &payload, len, &dlen);

  if (!plaintext)
    return 0;

  /* process encrypted payload */
  p = 0;
  while (p < dlen && payload != IKEV2_PAYLOAD_NONE)
    {
      u32 current_length = dlen - p;
      if (p + sizeof (*ikep) > dlen)
	return 0;

      ikep = (ike_payload_header_t *) & plaintext[p];
      u16 plen = clib_net_to_host_u16 (ikep->length);

      if (plen < sizeof (*ikep) || plen > current_length)
	return 0;

      if (payload == IKEV2_PAYLOAD_NOTIFY)	/* 41 */
	{
	  n = ikev2_parse_notify_payload (ikep, current_length);
	  if (!n)
	    return 0;
	  if (n->msg_type == IKEV2_NOTIFY_MSG_AUTHENTICATION_FAILED)
	    ikev2_set_state (sa, IKEV2_STATE_AUTH_FAILED);
	  vec_free (n);
	}
      else if (payload == IKEV2_PAYLOAD_DELETE)	/* 42 */
	{
	  sa->del = ikev2_parse_delete_payload (ikep, current_length);
	}
      else if (payload == IKEV2_PAYLOAD_VENDOR)	/* 43 */
	{
	  ikev2_parse_vendor_payload (ikep);
	}
      else
	{
	  ikev2_elog_uint (IKEV2_LOG_ERROR, "Unknown payload! type=%d",
			   payload);
	  if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
	    {
	      sa->unsupported_cp = payload;
	      return 0;
	    }
	}
      payload = ikep->nextpayload;
      p += plen;
    }
  return 1;
}

static int
ikev2_process_create_child_sa_req (vlib_main_t * vm,
				   ikev2_sa_t * sa, ike_header_t * ike,
				   u32 len)
{
  int p = 0;
  u8 payload = ike->nextpayload;
  u8 *plaintext = 0;
  u8 rekeying = 0;
  u8 nonce[IKEV2_NONCE_SIZE];

  ike_payload_header_t *ikep;
  ikev2_notify_t *n = 0;
  ikev2_ts_t *tsi = 0;
  ikev2_ts_t *tsr = 0;
  ikev2_sa_proposal_t *proposal = 0;
  ikev2_child_sa_t *child_sa;
  u32 dlen = 0;
  u16 plen;

  ikev2_elog_exchange ("ispi %lx rspi %lx CREATE_CHILD_SA received "
		       "from ", clib_host_to_net_u64 (ike->ispi),
		       clib_host_to_net_u64 (ike->rspi),
		       ip_addr_v4 (&sa->raddr).as_u32,
		       ip_addr_version (&sa->raddr) == AF_IP4);

  plaintext = ikev2_decrypt_sk_payload (sa, ike, &payload, len, &dlen);

  if (!plaintext)
    goto cleanup_and_exit;

  /* process encrypted payload */
  p = 0;
  while (payload != IKEV2_PAYLOAD_NONE)
    {
      ikep = (ike_payload_header_t *) & plaintext[p];
      int current_length = dlen - p;
      if (!ikev2_check_payload_length (ikep, current_length, &plen))
	goto cleanup_and_exit;

      if (payload == IKEV2_PAYLOAD_SA)
	{
	  proposal = ikev2_parse_sa_payload (ikep, current_length);
	}
      else if (payload == IKEV2_PAYLOAD_NOTIFY)
	{
	  n = ikev2_parse_notify_payload (ikep, current_length);
	  if (n->msg_type == IKEV2_NOTIFY_MSG_REKEY_SA)
	    {
	      rekeying = 1;
	    }
	}
      else if (payload == IKEV2_PAYLOAD_DELETE)
	{
	  sa->del = ikev2_parse_delete_payload (ikep, current_length);
	}
      else if (payload == IKEV2_PAYLOAD_VENDOR)
	{
	  ikev2_parse_vendor_payload (ikep);
	}
      else if (payload == IKEV2_PAYLOAD_NONCE)
	{
	  ikev2_parse_nonce_payload (ikep, current_length, nonce);
	}
      else if (payload == IKEV2_PAYLOAD_TSI)
	{
	  tsi = ikev2_parse_ts_payload (ikep, current_length);
	}
      else if (payload == IKEV2_PAYLOAD_TSR)
	{
	  tsr = ikev2_parse_ts_payload (ikep, current_length);
	}
      else
	{
	  ikev2_elog_uint (IKEV2_LOG_ERROR, "Unknown payload! type=%d",
			   payload);
	  if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
	    {
	      sa->unsupported_cp = payload;
	      goto cleanup_and_exit;
	    }
	}
      payload = ikep->nextpayload;
      p += plen;
    }

  if (sa->is_initiator && proposal
      && proposal->protocol_id == IKEV2_PROTOCOL_ESP)
    {
      ikev2_rekey_t *rekey = sa->rekey;
      if (vec_len (rekey) == 0)
	goto cleanup_and_exit;
      rekey->protocol_id = proposal->protocol_id;
      rekey->i_proposal =
	ikev2_select_proposal (proposal, IKEV2_PROTOCOL_ESP);
      rekey->i_proposal->spi = rekey->spi;
      rekey->r_proposal = proposal;
      rekey->tsi = tsi;
      rekey->tsr = tsr;
      /* update Nr */
      vec_reset_length (sa->r_nonce);
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
	  ikev2_elog_uint (IKEV2_LOG_ERROR, "child SA spi %lx not found",
			   n->spi);
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
      vec_reset_length (sa->i_nonce);
      vec_add (sa->i_nonce, nonce, IKEV2_NONCE_SIZE);
      /* generate new Nr */
      vec_validate (sa->r_nonce, IKEV2_NONCE_SIZE - 1);
      RAND_bytes ((u8 *) sa->r_nonce, IKEV2_NONCE_SIZE);
    }
  else
    goto cleanup_and_exit;
  vec_free (n);
  return 1;

cleanup_and_exit:
  vec_free (n);
  vec_free (proposal);
  vec_free (tsr);
  vec_free (tsi);
  return 0;
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
      !ip_address_cmp (&ts1->start_addr, &ts2->start_addr) &&
      !ip_address_cmp (&ts1->end_addr, &ts2->end_addr))
    return 1;

  return 0;
}

static void
ikev2_sa_match_ts (ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_profile_t *p;
  ikev2_ts_t *ts, *p_tsi, *p_tsr, *tsi = 0, *tsr = 0;
  ikev2_id_t *id_rem, *id_loc;

  /* *INDENT-OFF* */
  pool_foreach (p, km->profiles, ({

    if (sa->is_initiator)
      {
        p_tsi = &p->loc_ts;
        p_tsr = &p->rem_ts;
        id_rem = &sa->r_id;
        id_loc = &sa->i_id;
      }
    else
      {
        p_tsi = &p->rem_ts;
        p_tsr = &p->loc_ts;
        id_rem = &sa->i_id;
        id_loc = &sa->r_id;
      }

    /* check id */
    if (!ikev2_is_id_equal (&p->rem_id, id_rem)
          || !ikev2_is_id_equal (&p->loc_id, id_loc))
      continue;

    sa->profile_index = p - km->profiles;

    vec_foreach(ts, sa->childs[0].tsi)
      {
        if (ikev2_ts_cmp(p_tsi, ts))
          {
            vec_add1 (tsi, ts[0]);
            break;
          }
      }

    vec_foreach(ts, sa->childs[0].tsr)
      {
        if (ikev2_ts_cmp(p_tsr, ts))
          {
            vec_add1 (tsr, ts[0]);
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
      ikev2_elog_uint (IKEV2_LOG_ERROR,
		       "unsupported authentication method %u",
		       sa->i_auth.method);
      ikev2_set_state (sa, IKEV2_STATE_AUTH_FAILED);
      return;
    }

  key_pad = format (0, "%s", IKEV2_KEY_PAD);
  authmsg = ikev2_sa_generate_authmsg (sa, sa->is_initiator);

  ikev2_id_t *id_rem, *id_loc;
  ikev2_auth_t *sa_auth;

  if (sa->is_initiator)
    {
      id_rem = &sa->r_id;
      id_loc = &sa->i_id;
      sa_auth = &sa->r_auth;
    }
  else
    {
      id_rem = &sa->i_id;
      id_loc = &sa->r_id;
      sa_auth = &sa->i_auth;
    }

  /* *INDENT-OFF* */
  pool_foreach (p, km->profiles, ({

    /* check id */
    if (!ikev2_is_id_equal (&p->rem_id, id_rem)
          || !ikev2_is_id_equal (&p->loc_id, id_loc))
      continue;

    if (sa_auth->method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
      {
        if (!p->auth.data ||
             p->auth.method != IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
          continue;

        psk = ikev2_calc_prf(tr_prf, p->auth.data, key_pad);
        auth = ikev2_calc_prf(tr_prf, psk, authmsg);

        if (!clib_memcmp(auth, sa_auth->data, vec_len(sa_auth->data)))
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

  if (sel_p)
    {
      sa->udp_encap = sel_p->udp_encap;
      sa->ipsec_over_udp_port = sel_p->ipsec_over_udp_port;
    }
  vec_free (authmsg);

  if (sa->state == IKEV2_STATE_AUTHENTICATED)
    {
      if (!sa->is_initiator)
	{
	  vec_free (sa->r_id.data);
	  sa->r_id.data = vec_dup (sel_p->loc_id.data);
	  sa->r_id.type = sel_p->loc_id.type;
	  sa->i_id.data = vec_dup (sel_p->rem_id.data);
	  sa->i_id.type = sel_p->rem_id.type;

	  /* generate our auth data */
	  authmsg = ikev2_sa_generate_authmsg (sa, 1);
	  if (sel_p->auth.method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
	    {
	      vec_free (sa->r_auth.data);
	      sa->r_auth.data = ikev2_calc_prf (tr_prf, psk, authmsg);
	      sa->r_auth.method = IKEV2_AUTH_METHOD_SHARED_KEY_MIC;
	    }
	  else if (sel_p->auth.method == IKEV2_AUTH_METHOD_RSA_SIG)
	    {
	      vec_free (sa->r_auth.data);
	      sa->r_auth.data = ikev2_calc_sign (km->pkey, authmsg);
	      sa->r_auth.method = IKEV2_AUTH_METHOD_RSA_SIG;
	    }
	  vec_free (authmsg);

	  /* select transforms for 1st child sa */
	  ikev2_sa_free_proposal_vector (&sa->childs[0].r_proposals);
	  sa->childs[0].r_proposals =
	    ikev2_select_proposal (sa->childs[0].i_proposals,
				   IKEV2_PROTOCOL_ESP);

	  if (~0 != sel_p->tun_itf)
	    {
	      sa->is_tun_itf_set = 1;
	      sa->tun_itf = sel_p->tun_itf;
	    }
	}
    }
  else
    {
      ikev2_elog_uint (IKEV2_LOG_ERROR, "authentication failed, no matching "
		       "profile found! ispi %lx", sa->ispi);
      ikev2_set_state (sa, IKEV2_STATE_AUTH_FAILED);
    }
  vec_free (psk);
  vec_free (key_pad);
}


static void
ikev2_sa_auth_init (ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  u8 *authmsg, *key_pad, *psk = 0;
  ikev2_sa_transform_t *tr_prf;

  tr_prf =
    ikev2_sa_get_td_for_type (sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);

  /* only shared key and rsa signature */
  if (!(sa->i_auth.method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC ||
	sa->i_auth.method == IKEV2_AUTH_METHOD_RSA_SIG))
    {
      ikev2_elog_uint (IKEV2_LOG_ERROR,
		       "unsupported authentication method %u",
		       sa->i_auth.method);
      ikev2_set_state (sa, IKEV2_STATE_AUTH_FAILED);
      return;
    }

  key_pad = format (0, "%s", IKEV2_KEY_PAD);
  authmsg = ikev2_sa_generate_authmsg (sa, 0);
  psk = ikev2_calc_prf (tr_prf, sa->i_auth.data, key_pad);

  if (sa->i_auth.method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
    {
      vec_free (sa->i_auth.data);
      sa->i_auth.data = ikev2_calc_prf (tr_prf, psk, authmsg);
      sa->i_auth.method = IKEV2_AUTH_METHOD_SHARED_KEY_MIC;
    }
  else if (sa->i_auth.method == IKEV2_AUTH_METHOD_RSA_SIG)
    {
      vec_free (sa->i_auth.data);
      sa->i_auth.data = ikev2_calc_sign (km->pkey, authmsg);
      sa->i_auth.method = IKEV2_AUTH_METHOD_RSA_SIG;
    }

  vec_free (psk);
  vec_free (key_pad);
  vec_free (authmsg);
}

static u32
ikev2_mk_local_sa_id (u32 sai, u32 ci, u32 ti)
{
  return (0x80000000 | (ti << 24) | (sai << 12) | ci);
}

static u32
ikev2_mk_remote_sa_id (u32 sai, u32 ci, u32 ti)
{
  return (0xc0000000 | (ti << 24) | (sai << 12) | ci);
}

typedef struct
{
  u32 sw_if_index;
  u32 salt_local;
  u32 salt_remote;
  u32 local_sa_id;
  u32 remote_sa_id;
  ipsec_sa_flags_t flags;
  u32 local_spi;
  u32 remote_spi;
  ipsec_crypto_alg_t encr_type;
  ipsec_integ_alg_t integ_type;
  ip46_address_t local_ip;
  ip46_address_t remote_ip;
  ipsec_key_t loc_ckey, rem_ckey, loc_ikey, rem_ikey;
  u8 is_rekey;
  u32 old_remote_sa_id;
  u16 ipsec_over_udp_port;
  u16 src_port;
  u16 dst_port;
} ikev2_add_ipsec_tunnel_args_t;

static void
ikev2_add_tunnel_from_main (ikev2_add_ipsec_tunnel_args_t * a)
{
  ikev2_main_t *km = &ikev2_main;
  u32 sw_if_index;
  int rv = 0;

  if (~0 == a->sw_if_index)
    {
      /* no tunnel associated with the SA/profile - create a new one */
      rv = ipip_add_tunnel (IPIP_TRANSPORT_IP4, ~0,
			    &a->local_ip, &a->remote_ip, 0,
			    TUNNEL_ENCAP_DECAP_FLAG_NONE, IP_DSCP_CS0,
			    TUNNEL_MODE_P2P, &sw_if_index);

      if (rv == VNET_API_ERROR_IF_ALREADY_EXISTS)
	{
	  if (hash_get (km->sw_if_indices, sw_if_index))
	    /* interface is managed by IKE; proceed with updating SAs */
	    rv = 0;
	}
      hash_set1 (km->sw_if_indices, sw_if_index);
    }
  else
    {
      sw_if_index = a->sw_if_index;
      vnet_sw_interface_admin_up (vnet_get_main (), sw_if_index);
    }

  if (rv)
    {
      ikev2_elog_uint (IKEV2_LOG_ERROR,
		       "installing ipip tunnel failed! local spi: %x",
		       a->local_spi);
      return;
    }

  u32 *sas_in = NULL;
  vec_add1 (sas_in, a->remote_sa_id);
  if (a->is_rekey)
    {
      ipsec_tun_protect_del (sw_if_index, NULL);

      /* replace local SA immediately */
      ipsec_sa_unlock_id (a->local_sa_id);

      /* keep the old sa */
      vec_add1 (sas_in, a->old_remote_sa_id);
    }

  rv = ipsec_sa_add_and_lock (a->local_sa_id,
			      a->local_spi,
			      IPSEC_PROTOCOL_ESP, a->encr_type,
			      &a->loc_ckey, a->integ_type, &a->loc_ikey,
			      a->flags, 0, a->salt_local, &a->local_ip,
			      &a->remote_ip, TUNNEL_ENCAP_DECAP_FLAG_NONE,
			      IP_DSCP_CS0, NULL, a->src_port, a->dst_port);
  if (rv)
    goto err0;

  rv = ipsec_sa_add_and_lock (a->remote_sa_id, a->remote_spi,
			      IPSEC_PROTOCOL_ESP, a->encr_type, &a->rem_ckey,
			      a->integ_type, &a->rem_ikey,
			      (a->flags | IPSEC_SA_FLAG_IS_INBOUND), 0,
			      a->salt_remote, &a->remote_ip,
			      &a->local_ip, TUNNEL_ENCAP_DECAP_FLAG_NONE,
			      IP_DSCP_CS0, NULL,
			      a->ipsec_over_udp_port, a->ipsec_over_udp_port);
  if (rv)
    goto err1;

  rv = ipsec_tun_protect_update (sw_if_index, NULL, a->local_sa_id, sas_in);
  if (rv)
    goto err2;

  return;

err2:
  ipsec_sa_unlock_id (a->remote_sa_id);
err1:
  ipsec_sa_unlock_id (a->local_sa_id);
err0:
  vec_free (sas_in);
}

static int
ikev2_create_tunnel_interface (vlib_main_t * vm,
			       ikev2_sa_t * sa,
			       ikev2_child_sa_t * child, u32 sa_index,
			       u32 child_index, u8 is_rekey)
{
  u32 thread_index = vlib_get_thread_index ();
  ikev2_main_t *km = &ikev2_main;
  ipsec_crypto_alg_t encr_type;
  ipsec_integ_alg_t integ_type;
  ikev2_profile_t *p = 0;
  ikev2_sa_transform_t *tr;
  ikev2_sa_proposal_t *proposals;
  u8 is_aead = 0;
  ikev2_add_ipsec_tunnel_args_t a;

  clib_memset (&a, 0, sizeof (a));

  if (!child->r_proposals)
    {
      ikev2_set_state (sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
      return 1;
    }

  if (sa->is_initiator)
    {
      ip_address_to_46 (&sa->iaddr, &a.local_ip);
      ip_address_to_46 (&sa->raddr, &a.remote_ip);
      proposals = child->r_proposals;
      a.local_spi = child->r_proposals[0].spi;
      a.remote_spi = child->i_proposals[0].spi;
    }
  else
    {
      ip_address_to_46 (&sa->raddr, &a.local_ip);
      ip_address_to_46 (&sa->iaddr, &a.remote_ip);
      proposals = child->i_proposals;
      a.local_spi = child->i_proposals[0].spi;
      a.remote_spi = child->r_proposals[0].spi;
    }

  a.flags = IPSEC_SA_FLAG_USE_ANTI_REPLAY;
  if (sa->udp_encap)
    {
      a.flags |= IPSEC_SA_FLAG_IS_TUNNEL;
      a.flags |= IPSEC_SA_FLAG_UDP_ENCAP;
    }
  if (ikev2_natt_active (sa))
    a.flags |= IPSEC_SA_FLAG_UDP_ENCAP;
  a.is_rekey = is_rekey;

  tr = ikev2_sa_get_td_for_type (proposals, IKEV2_TRANSFORM_TYPE_ESN);
  if (tr && tr->esn_type)
    a.flags |= IPSEC_SA_FLAG_USE_ESN;

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
      else if (tr->encr_type == IKEV2_TRANSFORM_ENCR_TYPE_AES_GCM_16
	       && tr->key_len)
	{
	  switch (tr->key_len)
	    {
	    case 16:
	      encr_type = IPSEC_CRYPTO_ALG_AES_GCM_128;
	      break;
	    case 24:
	      encr_type = IPSEC_CRYPTO_ALG_AES_GCM_192;
	      break;
	    case 32:
	      encr_type = IPSEC_CRYPTO_ALG_AES_GCM_256;
	      break;
	    default:
	      ikev2_set_state (sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
	      return 1;
	      break;
	    }
	  is_aead = 1;
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
  a.encr_type = encr_type;

  if (!is_aead)
    {
      tr = ikev2_sa_get_td_for_type (proposals, IKEV2_TRANSFORM_TYPE_INTEG);
      if (tr)
	{
	  switch (tr->integ_type)
	    {
	    case IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_256_128:
	      integ_type = IPSEC_INTEG_ALG_SHA_256_128;
	      break;
	    case IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_384_192:
	      integ_type = IPSEC_INTEG_ALG_SHA_384_192;
	      break;
	    case IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA2_512_256:
	      integ_type = IPSEC_INTEG_ALG_SHA_512_256;
	      break;
	    case IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_96:
	      integ_type = IPSEC_INTEG_ALG_SHA1_96;
	      break;
	    default:
	      ikev2_set_state (sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
	      return 1;
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
      integ_type = IPSEC_INTEG_ALG_NONE;
    }

  a.integ_type = integ_type;
  ikev2_calc_child_keys (sa, child);

  if (sa->is_initiator)
    {
      ipsec_mk_key (&a.loc_ikey, child->sk_ai, vec_len (child->sk_ai));
      ipsec_mk_key (&a.rem_ikey, child->sk_ar, vec_len (child->sk_ar));
      ipsec_mk_key (&a.loc_ckey, child->sk_ei, vec_len (child->sk_ei));
      ipsec_mk_key (&a.rem_ckey, child->sk_er, vec_len (child->sk_er));
      if (is_aead)
	{
	  a.salt_remote = child->salt_er;
	  a.salt_local = child->salt_ei;
	}
      a.dst_port = a.src_port = sa->ipsec_over_udp_port;
    }
  else
    {
      ipsec_mk_key (&a.loc_ikey, child->sk_ar, vec_len (child->sk_ar));
      ipsec_mk_key (&a.rem_ikey, child->sk_ai, vec_len (child->sk_ai));
      ipsec_mk_key (&a.loc_ckey, child->sk_er, vec_len (child->sk_er));
      ipsec_mk_key (&a.rem_ckey, child->sk_ei, vec_len (child->sk_ei));
      if (is_aead)
	{
	  a.salt_remote = child->salt_ei;
	  a.salt_local = child->salt_er;
	}
      a.dst_port =
	ikev2_natt_active (sa) ? sa->dst_port : sa->ipsec_over_udp_port;
      a.src_port = sa->ipsec_over_udp_port;
    }

  if (sa->is_initiator && sa->profile_index != ~0)
    p = pool_elt_at_index (km->profiles, sa->profile_index);

  if (p && p->lifetime)
    {
      child->time_to_expiration = vlib_time_now (vm) + p->lifetime;
      if (p->lifetime_jitter)
	{
	  // This is not much better than rand(3), which Coverity warns
	  // is unsuitable for security applications; random_u32 is
	  // however fast. If this perturbance to the expiration time
	  // needs to use a better RNG then we may need to use something
	  // like /dev/urandom which has significant overhead.
	  u32 rnd = (u32) (vlib_time_now (vm) * 1e6);
	  rnd = random_u32 (&rnd);

	  child->time_to_expiration += 1 + (rnd % p->lifetime_jitter);
	}
    }

  if (thread_index & 0xffffffc0)
    ikev2_elog_error ("error: thread index exceeds max range 0x3f!");

  if (child_index & 0xfffff000 || sa_index & 0xfffff000)
    ikev2_elog_error ("error: sa/child index exceeds max range 0xfff!");

  child->local_sa_id =
    a.local_sa_id =
    ikev2_mk_local_sa_id (sa_index, child_index, thread_index);

  u32 remote_sa_id = ikev2_mk_remote_sa_id (sa_index, child_index,
					    thread_index);

  if (is_rekey)
    {
      /* create a new remote SA ID to keep the old SA for a bit longer
       * so the peer has some time to swap their SAs */

      /* use most significat bit of child index part in id */
      u32 mask = 0x800;
      if (sa->current_remote_id_mask)
	{
	  sa->old_remote_id = a.old_remote_sa_id = remote_sa_id | mask;
	  sa->current_remote_id_mask = 0;
	}
      else
	{
	  sa->old_remote_id = a.old_remote_sa_id = remote_sa_id;
	  sa->current_remote_id_mask = mask;
	  remote_sa_id |= mask;
	}
      sa->old_id_expiration = 3.0;
      sa->old_remote_id_present = 1;
    }

  child->remote_sa_id = a.remote_sa_id = remote_sa_id;

  a.sw_if_index = (sa->is_tun_itf_set ? sa->tun_itf : ~0);
  a.ipsec_over_udp_port = sa->ipsec_over_udp_port;

  vl_api_rpc_call_main_thread (ikev2_add_tunnel_from_main,
			       (u8 *) & a, sizeof (a));
  return 0;
}

typedef struct
{
  ip46_address_t local_ip;
  ip46_address_t remote_ip;
  u32 remote_sa_id;
  u32 local_sa_id;
  u32 sw_if_index;
} ikev2_del_ipsec_tunnel_args_t;

static_always_inline u32
ikev2_flip_alternate_sa_bit (u32 id)
{
  u32 mask = 0x800;
  if (mask & id)
    return id & ~mask;
  return id | mask;
}

static void
ikev2_del_tunnel_from_main (ikev2_del_ipsec_tunnel_args_t * a)
{
  ikev2_main_t *km = &ikev2_main;
  ipip_tunnel_t *ipip = NULL;
  u32 sw_if_index;

  if (~0 == a->sw_if_index)
    {
    /* *INDENT-OFF* */
    ipip_tunnel_key_t key = {
      .src = a->local_ip,
      .dst = a->remote_ip,
      .transport = IPIP_TRANSPORT_IP4,
      .fib_index = 0,
    };
    /* *INDENT-ON* */

      ipip = ipip_tunnel_db_find (&key);

      if (ipip)
	{
	  sw_if_index = ipip->sw_if_index;
	  hash_unset (km->sw_if_indices, ipip->sw_if_index);
	}
      else
	sw_if_index = ~0;
    }
  else
    {
      sw_if_index = a->sw_if_index;
      vnet_sw_interface_admin_down (vnet_get_main (), sw_if_index);
    }

  if (~0 != sw_if_index)
    ipsec_tun_protect_del (sw_if_index, NULL);

  ipsec_sa_unlock_id (a->remote_sa_id);
  ipsec_sa_unlock_id (a->local_sa_id);
  ipsec_sa_unlock_id (ikev2_flip_alternate_sa_bit (a->remote_sa_id));

  if (ipip)
    ipip_del_tunnel (ipip->sw_if_index);
}

static int
ikev2_delete_tunnel_interface (vnet_main_t * vnm, ikev2_sa_t * sa,
			       ikev2_child_sa_t * child)
{
  ikev2_del_ipsec_tunnel_args_t a;

  clib_memset (&a, 0, sizeof (a));

  if (sa->is_initiator)
    {
      ip_address_to_46 (&sa->iaddr, &a.local_ip);
      ip_address_to_46 (&sa->raddr, &a.remote_ip);
    }
  else
    {
      ip_address_to_46 (&sa->raddr, &a.local_ip);
      ip_address_to_46 (&sa->iaddr, &a.remote_ip);
    }

  a.remote_sa_id = child->remote_sa_id;
  a.local_sa_id = child->local_sa_id;
  a.sw_if_index = (sa->is_tun_itf_set ? sa->tun_itf : ~0);

  vl_api_rpc_call_main_thread (ikev2_del_tunnel_from_main, (u8 *) & a,
			       sizeof (a));
  return 0;
}

static u32
ikev2_generate_message (vlib_buffer_t * b, ikev2_sa_t * sa,
			ike_header_t * ike, void *user, udp_header_t * udp)
{
  ikev2_main_t *km = &ikev2_main;
  u16 buffer_data_size = vlib_buffer_get_default_data_size (km->vlib_main);
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
	  ASSERT (udp);

	  ike->rspi = clib_host_to_net_u64 (sa->rspi);
	  ikev2_payload_add_sa (chain, sa->r_proposals);
	  ikev2_payload_add_ke (chain, sa->dh_group, sa->r_dh_data);
	  ikev2_payload_add_nonce (chain, sa->r_nonce);

	  u8 *nat_detection_sha1 =
	    ikev2_compute_nat_sha1 (clib_host_to_net_u64 (sa->ispi),
				    clib_host_to_net_u64 (sa->rspi),
				    &sa->raddr, udp->dst_port);
	  ikev2_payload_add_notify (chain,
				    IKEV2_NOTIFY_MSG_NAT_DETECTION_SOURCE_IP,
				    nat_detection_sha1);
	  vec_free (nat_detection_sha1);
	  nat_detection_sha1 =
	    ikev2_compute_nat_sha1 (clib_host_to_net_u64 (sa->ispi),
				    clib_host_to_net_u64 (sa->rspi),
				    &sa->iaddr, udp->src_port);
	  ikev2_payload_add_notify (chain,
				    IKEV2_NOTIFY_MSG_NAT_DETECTION_DESTINATION_IP,
				    nat_detection_sha1);
	  vec_free (nat_detection_sha1);
	}
    }
  else if (ike->exchange == IKEV2_EXCHANGE_IKE_AUTH)
    {
      if (sa->state == IKEV2_STATE_AUTHENTICATED)
	{
	  ikev2_payload_add_id (chain, &sa->r_id, IKEV2_PAYLOAD_IDR);
	  ikev2_payload_add_id (chain, &sa->i_id, IKEV2_PAYLOAD_IDI);
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
	  ikev2_payload_add_id (chain, &sa->r_id, IKEV2_PAYLOAD_IDR);
	  ikev2_payload_add_auth (chain, &sa->i_auth);
	  ikev2_payload_add_sa (chain, sa->childs[0].i_proposals);
	  ikev2_payload_add_ts (chain, sa->childs[0].tsi, IKEV2_PAYLOAD_TSI);
	  ikev2_payload_add_ts (chain, sa->childs[0].tsr, IKEV2_PAYLOAD_TSR);
	  ikev2_payload_add_notify (chain, IKEV2_NOTIFY_MSG_INITIAL_CONTACT,
				    0);
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
	      if (ike_hdr_is_request (ike))
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
	  clib_memset (&notify, 0, sizeof (notify));
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
	  if (vec_len (sa->rekey) > 0)
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
    ike->flags |= IKEV2_HDR_FLAG_INITIATOR;

  if (ike->exchange == IKEV2_EXCHANGE_SA_INIT)
    {
      tlen += vec_len (chain->data);
      ike->nextpayload = chain->first_payload_type;
      ike->length = clib_host_to_net_u32 (tlen);

      if (tlen + b->current_length + b->current_data > buffer_data_size)
	{
	  tlen = ~0;
	  goto done;
	}

      clib_memcpy_fast (ike->payload, chain->data, vec_len (chain->data));

      /* store whole IKE payload - needed for PSK auth */
      vec_reset_length (sa->last_sa_init_res_packet_data);
      vec_add (sa->last_sa_init_res_packet_data, ike, tlen);
    }
  else
    {
      ikev2_main_per_thread_data_t *ptd = ikev2_get_per_thread_data ();
      ikev2_payload_chain_add_padding (chain, tr_encr->block_size);

      /* SK payload */
      plen = sizeof (*ph);
      ph = (ike_payload_header_t *) & ike->payload[0];
      ph->nextpayload = chain->first_payload_type;
      ph->flags = 0;
      int is_aead =
	tr_encr->encr_type == IKEV2_TRANSFORM_ENCR_TYPE_AES_GCM_16;
      int iv_len = is_aead ? IKEV2_GCM_IV_SIZE : tr_encr->block_size;
      plen += vec_len (chain->data) + iv_len;

      /* add space for hmac/tag */
      if (tr_integ)
	plen += tr_integ->key_trunc;
      else
	plen += IKEV2_GCM_ICV_SIZE;
      tlen += plen;

      if (tlen + b->current_length + b->current_data > buffer_data_size)
	{
	  tlen = ~0;
	  goto done;
	}

      /* payload and total length */
      ph->length = clib_host_to_net_u16 (plen);
      ike->length = clib_host_to_net_u32 (tlen);

      if (is_aead)
	{
	  if (!ikev2_encrypt_aead_data (ptd, sa, tr_encr, chain->data,
					ph->payload, (u8 *) ike,
					sizeof (*ike) + sizeof (*ph),
					ph->payload + plen - sizeof (*ph) -
					IKEV2_GCM_ICV_SIZE))
	    {
	      tlen = ~0;
	      goto done;
	    }
	}
      else
	{
	  if (!ikev2_encrypt_data
	      (ptd, sa, tr_encr, chain->data, ph->payload))
	    {
	      tlen = ~0;
	      goto done;
	    }
	  integ =
	    ikev2_calc_integr (tr_integ,
			       sa->is_initiator ? sa->sk_ai : sa->sk_ar,
			       (u8 *) ike, tlen - tr_integ->key_trunc);
	  clib_memcpy_fast (ike->payload + tlen - tr_integ->key_trunc -
			    sizeof (*ike), integ, tr_integ->key_trunc);
	}

      /* store whole IKE payload - needed for retransmit */
      vec_reset_length (sa->last_res_packet_data);
      vec_add (sa->last_res_packet_data, ike, tlen);
    }

done:
  ikev2_payload_destroy_chain (chain);
  vec_free (integ);
  return tlen;
}

static u32
ikev2_retransmit_sa_init_one (ikev2_sa_t * sa, ike_header_t * ike,
			      ip_address_t iaddr, ip_address_t raddr,
			      u32 rlen)
{
  int p = 0;
  ike_header_t *tmp;
  u8 payload = ike->nextpayload;

  if (sa->ispi != clib_net_to_host_u64 (ike->ispi) ||
      ip_address_cmp (&sa->iaddr, &iaddr) ||
      ip_address_cmp (&sa->raddr, &raddr))
    {
      return 0;
    }

  while (p < rlen && payload != IKEV2_PAYLOAD_NONE)
    {
      ike_payload_header_t *ikep = (ike_payload_header_t *) & ike->payload[p];
      u32 plen = clib_net_to_host_u16 (ikep->length);

      if (plen < sizeof (ike_payload_header_t))
	return ~0;

      if (payload == IKEV2_PAYLOAD_NONCE &&
	  !clib_memcmp (sa->i_nonce, ikep->payload, plen - sizeof (*ikep)))
	{
	  /* req is retransmit */
	  if (sa->state == IKEV2_STATE_SA_INIT)
	    {
	      tmp = (ike_header_t *) sa->last_sa_init_res_packet_data;
	      u32 slen = clib_net_to_host_u32 (tmp->length);
	      ike->ispi = tmp->ispi;
	      ike->rspi = tmp->rspi;
	      ike->nextpayload = tmp->nextpayload;
	      ike->version = tmp->version;
	      ike->exchange = tmp->exchange;
	      ike->flags = tmp->flags;
	      ike->msgid = tmp->msgid;
	      ike->length = tmp->length;
	      clib_memcpy_fast (ike->payload, tmp->payload,
				slen - sizeof (*ike));
	      ikev2_elog_uint_peers (IKEV2_LOG_DEBUG,
				     "ispi %lx IKE_SA_INIT retransmit "
				     "from %d.%d.%d.%d to %d.%d.%d.%d",
				     ike->ispi,
				     ip_addr_v4 (&raddr).as_u32,
				     ip_addr_v4 (&iaddr).as_u32);
	      return slen;
	    }
	  /* else ignore req */
	  else
	    {
	      ikev2_elog_uint_peers (IKEV2_LOG_DEBUG,
				     "ispi %lx IKE_SA_INIT ignore "
				     "from %d.%d.%d.%d to %d.%d.%d.%d",
				     ike->ispi,
				     ip_addr_v4 (&raddr).as_u32,
				     ip_addr_v4 (&iaddr).as_u32);
	      return ~0;
	    }
	}
      payload = ikep->nextpayload;
      p += plen;
    }

  return 0;
}

static u32
ikev2_retransmit_sa_init (ike_header_t * ike, ip_address_t iaddr,
			  ip_address_t raddr, u32 rlen)
{
  ikev2_sa_t *sa;
  u32 res;
  ikev2_main_per_thread_data_t *ptd = ikev2_get_per_thread_data ();

  /* *INDENT-OFF* */
  pool_foreach (sa, ptd->sas, ({
    res = ikev2_retransmit_sa_init_one (sa, ike, iaddr, raddr, rlen);
    if (res)
      return res;
  }));
  /* *INDENT-ON* */

  /* req is not retransmit */
  return 0;
}

static u32
ikev2_retransmit_resp (ikev2_sa_t * sa, ike_header_t * ike)
{
  if (ike_hdr_is_response (ike))
    return 0;

  u32 msg_id = clib_net_to_host_u32 (ike->msgid);

  /* new req */
  if (msg_id > sa->last_msg_id)
    {
      sa->last_msg_id = msg_id;
      return 0;
    }

  /* retransmitted req */
  if (msg_id == sa->last_msg_id)
    {
      ike_header_t *tmp = (ike_header_t *) sa->last_res_packet_data;
      u32 slen = clib_net_to_host_u32 (tmp->length);
      ike->ispi = tmp->ispi;
      ike->rspi = tmp->rspi;
      ike->nextpayload = tmp->nextpayload;
      ike->version = tmp->version;
      ike->exchange = tmp->exchange;
      ike->flags = tmp->flags;
      ike->msgid = tmp->msgid;
      ike->length = tmp->length;
      clib_memcpy_fast (ike->payload, tmp->payload, slen - sizeof (*ike));
      ikev2_elog_uint_peers (IKEV2_LOG_DEBUG, "IKE retransmit msgid %d",
			     msg_id, ip_addr_v4 (&sa->raddr).as_u32,
			     ip_addr_v4 (&sa->iaddr).as_u32);
      return slen;
    }

  /* old req ignore */
  ikev2_elog_uint_peers (IKEV2_LOG_DEBUG, "IKE req ignore msgid %d",
			 msg_id, ip_addr_v4 (&sa->raddr).as_u32,
			 ip_addr_v4 (&sa->iaddr).as_u32);
  return ~0;
}

static void
ikev2_init_sa (vlib_main_t * vm, ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  sa->liveness_period_check = vlib_time_now (vm) + km->liveness_period;
  sa->profile_index = ~0;
}

static void
ikev2_del_sa_init_from_main (u64 * ispi)
{
  ikev2_main_t *km = &ikev2_main;
  uword *p = hash_get (km->sa_by_ispi, *ispi);
  if (p)
    {
      ikev2_sa_t *sai = pool_elt_at_index (km->sais, p[0]);
      hash_unset (km->sa_by_ispi, sai->ispi);
      ikev2_sa_free_all_vec (sai);
      pool_put (km->sais, sai);
    }
}

static void
ikev2_del_sa_init (u64 ispi)
{
  vl_api_rpc_call_main_thread (ikev2_del_sa_init_from_main, (u8 *) & ispi,
			       sizeof (ispi));
}

static_always_inline void
ikev2_rewrite_v6_addrs (ikev2_sa_t * sa, ip6_header_t * ih)
{
  if (sa->is_initiator)
    {
      ip_address_copy_addr (&ih->dst_address, &sa->raddr);
      ip_address_copy_addr (&ih->src_address, &sa->iaddr);
    }
  else
    {
      ip_address_copy_addr (&ih->dst_address, &sa->iaddr);
      ip_address_copy_addr (&ih->src_address, &sa->raddr);
    }
}

static_always_inline void
ikev2_rewrite_v4_addrs (ikev2_sa_t * sa, ip4_header_t * ih)
{
  if (sa->is_initiator)
    {
      ip_address_copy_addr (&ih->dst_address, &sa->raddr);
      ip_address_copy_addr (&ih->src_address, &sa->iaddr);
    }
  else
    {
      ip_address_copy_addr (&ih->dst_address, &sa->iaddr);
      ip_address_copy_addr (&ih->src_address, &sa->raddr);
    }
}

static_always_inline void
ikev2_set_ip_address (ikev2_sa_t * sa, const void *iaddr,
		      const void *raddr, const int af)
{
  ip_address_set (&sa->raddr, raddr, af);
  ip_address_set (&sa->iaddr, iaddr, af);
}

static void
ikev2_elog_uint_peers_addr (u32 exchange, ip4_header_t * ip4,
			    ip6_header_t * ip6, u8 is_ip4)
{
  u32 src, dst;
  if (is_ip4)
    {
      src = ip4->src_address.as_u32;
      dst = ip4->dst_address.as_u32;
    }
  else
    {
      src = ip6->src_address.as_u32[3];
      dst = ip6->dst_address.as_u32[3];
    }
  ikev2_elog_uint_peers (IKEV2_LOG_WARNING, "IKEv2 exchange %d "
			 "received from %d.%d.%d.%d to %d.%d.%d.%d",
			 exchange, src, dst);
}

static void
ikev2_generate_sa_init_data_and_log (ikev2_sa_t * sa)
{
  ikev2_generate_sa_error_t rc = ikev2_generate_sa_init_data (sa);

  if (PREDICT_TRUE (rc == IKEV2_GENERATE_SA_INIT_OK))
    return;

  if (rc == IKEV2_GENERATE_SA_INIT_ERR_NO_DH)
    ikev2_elog_error (IKEV2_GENERATE_SA_INIT_OK_ERR_NO_DH_STR);
  else if (rc == IKEV2_GENERATE_SA_INIT_ERR_UNSUPPORTED_DH)
    ikev2_elog_error (IKEV2_GENERATE_SA_INIT_OK_ERR_UNSUPP_STR);
}

static_always_inline uword
ikev2_node_internal (vlib_main_t * vm,
		     vlib_node_runtime_t * node, vlib_frame_t * frame,
		     u8 is_ip4)
{
  u32 n_left = frame->n_vectors, *from;
  ikev2_main_t *km = &ikev2_main;
  vlib_buffer_t *bufs[VLIB_FRAME_SIZE], **b;
  u16 nexts[VLIB_FRAME_SIZE], *next = nexts;
  ikev2_main_per_thread_data_t *ptd = ikev2_get_per_thread_data ();
  int res;

  from = vlib_frame_vector_args (frame);
  vlib_get_buffers (vm, from, bufs, n_left);
  b = bufs;

  while (n_left > 0)
    {
      vlib_buffer_t *b0 = b[0];
      next[0] = is_ip4 ? IKEV2_NEXT_IP4_ERROR_DROP
	: IKEV2_NEXT_IP6_ERROR_DROP;
      ip4_header_t *ip40 = 0;
      ip6_header_t *ip60 = 0;
      udp_header_t *udp0;
      ike_header_t *ike0;
      ikev2_sa_t *sa0 = 0;
      ikev2_sa_t sa;		/* temporary store for SA */
      u32 rlen, slen = 0;
      int ip_hdr_sz = 0;
      int is_req = 0, has_non_esp_marker = 0;

      ASSERT (0 == b0->punt_reason
	      || (is_ip4
		  && b0->punt_reason ==
		  ipsec_punt_reason[IPSEC_PUNT_IP4_SPI_UDP_0]));

      if (is_ip4
	  && b0->punt_reason == ipsec_punt_reason[IPSEC_PUNT_IP4_SPI_UDP_0])
	{
	  u8 *ptr = vlib_buffer_get_current (b0);
	  ip40 = (ip4_header_t *) ptr;
	  ptr += sizeof (*ip40);
	  udp0 = (udp_header_t *) ptr;
	  ptr += sizeof (*udp0);
	  ike0 = (ike_header_t *) ptr;
	  ip_hdr_sz = sizeof (*ip40);
	}
      else
	{
	  u8 *ipx_hdr = b0->data + vnet_buffer (b0)->l3_hdr_offset;
	  ike0 = vlib_buffer_get_current (b0);
	  vlib_buffer_advance (b0, -sizeof (*udp0));
	  udp0 = vlib_buffer_get_current (b0);

	  if (is_ip4)
	    {
	      ip40 = (ip4_header_t *) ipx_hdr;
	      ip_hdr_sz = sizeof (*ip40);
	    }
	  else
	    {
	      ip60 = (ip6_header_t *) ipx_hdr;
	      ip_hdr_sz = sizeof (*ip60);
	    }
	  vlib_buffer_advance (b0, -ip_hdr_sz);
	}

      rlen = b0->current_length - ip_hdr_sz - sizeof (*udp0);

      /* check for non-esp marker */
      if (*((u32 *) ike0) == 0)
	{
	  ike0 =
	    (ike_header_t *) ((u8 *) ike0 + sizeof (ikev2_non_esp_marker));
	  rlen -= sizeof (ikev2_non_esp_marker);
	  has_non_esp_marker = 1;
	}

      if (clib_net_to_host_u32 (ike0->length) != rlen)
	{
	  vlib_node_increment_counter (vm, node->node_index,
				       IKEV2_ERROR_BAD_LENGTH, 1);
	  goto dispatch0;
	}

      if (ike0->version != IKE_VERSION_2)
	{
	  vlib_node_increment_counter (vm, node->node_index,
				       IKEV2_ERROR_NOT_IKEV2, 1);
	  goto dispatch0;
	}

      if (ike0->exchange == IKEV2_EXCHANGE_SA_INIT)
	{
	  sa0 = &sa;
	  clib_memset (sa0, 0, sizeof (*sa0));

	  if (ike_hdr_is_initiator (ike0))
	    {
	      if (ike0->rspi == 0)
		{
		  if (is_ip4)
		    ikev2_set_ip_address (sa0, &ip40->src_address,
					  &ip40->dst_address, AF_IP4);
		  else
		    ikev2_set_ip_address (sa0, &ip60->src_address,
					  &ip60->dst_address, AF_IP6);

		  sa0->dst_port = clib_net_to_host_u16 (udp0->src_port);

		  slen =
		    ikev2_retransmit_sa_init (ike0, sa0->iaddr,
					      sa0->raddr, rlen);
		  if (slen)
		    {
		      vlib_node_increment_counter (vm, node->node_index,
						   ~0 ==
						   slen ?
						   IKEV2_ERROR_IKE_SA_INIT_IGNORE
						   :
						   IKEV2_ERROR_IKE_SA_INIT_RETRANSMIT,
						   1);
		      goto dispatch0;
		    }

		  res = ikev2_process_sa_init_req (vm, sa0, ike0, udp0, rlen);
		  if (!res)
		    vlib_node_increment_counter (vm, node->node_index,
						 IKEV2_ERROR_MALFORMED_PACKET,
						 1);

		  if (sa0->state == IKEV2_STATE_SA_INIT)
		    {
		      ikev2_sa_free_proposal_vector (&sa0->r_proposals);
		      sa0->r_proposals =
			ikev2_select_proposal (sa0->i_proposals,
					       IKEV2_PROTOCOL_IKE);
		      ikev2_generate_sa_init_data_and_log (sa0);
		    }

		  if (sa0->state == IKEV2_STATE_SA_INIT
		      || sa0->state == IKEV2_STATE_NOTIFY_AND_DELETE)
		    {
		      ike0->flags = IKEV2_HDR_FLAG_RESPONSE;
		      slen = ikev2_generate_message (b0, sa0, ike0, 0, udp0);
		      if (~0 == slen)
			vlib_node_increment_counter (vm, node->node_index,
						     IKEV2_ERROR_NO_BUFF_SPACE,
						     1);
		    }

		  if (sa0->state == IKEV2_STATE_SA_INIT)
		    {
		      /* add SA to the pool */
		      pool_get (ptd->sas, sa0);
		      clib_memcpy_fast (sa0, &sa, sizeof (*sa0));
		      ikev2_init_sa (vm, sa0);
		      hash_set (ptd->sa_by_rspi, sa0->rspi, sa0 - ptd->sas);
		    }
		  else
		    {
		      ikev2_sa_free_all_vec (sa0);
		    }
		}
	    }
	  else			//received sa_init without initiator flag
	    {
	      if (is_ip4)
		ikev2_set_ip_address (sa0, &ip40->dst_address,
				      &ip40->src_address, AF_IP4);
	      else
		ikev2_set_ip_address (sa0, &ip60->dst_address,
				      &ip60->src_address, AF_IP6);

	      ikev2_process_sa_init_resp (vm, sa0, ike0, udp0, rlen);

	      if (sa0->state == IKEV2_STATE_SA_INIT)
		{
		  is_req = 1;
		  ike0->exchange = IKEV2_EXCHANGE_IKE_AUTH;
		  uword *p = hash_get (km->sa_by_ispi, sa0->ispi);
		  if (p)
		    {
		      ikev2_sa_t *sai = pool_elt_at_index (km->sais, p[0]);

		      if (clib_atomic_bool_cmp_and_swap
			  (&sai->init_response_received, 0, 1))
			{
			  ikev2_complete_sa_data (sa0, sai);
			  ikev2_calc_keys (sa0);
			  ikev2_sa_auth_init (sa0);
			  ike0->flags = IKEV2_HDR_FLAG_INITIATOR;
			  ike0->msgid =
			    clib_net_to_host_u32 (sai->last_init_msg_id);
			  sa0->last_init_msg_id = sai->last_init_msg_id + 1;
			  slen =
			    ikev2_generate_message (b0, sa0, ike0, 0, udp0);
			  if (~0 == slen)
			    vlib_node_increment_counter (vm,
							 node->node_index,
							 IKEV2_ERROR_NO_BUFF_SPACE,
							 1);
			}
		      else
			{
			  /* we've already processed sa-init response */
			  sa0->state = IKEV2_STATE_UNKNOWN;
			}
		    }
		}

	      if (sa0->state == IKEV2_STATE_SA_INIT)
		{
		  /* add SA to the pool */
		  pool_get (ptd->sas, sa0);
		  clib_memcpy_fast (sa0, &sa, sizeof (*sa0));
		  hash_set (ptd->sa_by_rspi, sa0->rspi, sa0 - ptd->sas);
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
	  p = hash_get (ptd->sa_by_rspi, clib_net_to_host_u64 (ike0->rspi));
	  if (p)
	    {
	      sa0 = pool_elt_at_index (ptd->sas, p[0]);
	      slen = ikev2_retransmit_resp (sa0, ike0);
	      if (slen)
		{
		  vlib_node_increment_counter (vm, node->node_index,
					       ~0 ==
					       slen ?
					       IKEV2_ERROR_IKE_REQ_IGNORE
					       :
					       IKEV2_ERROR_IKE_REQ_RETRANSMIT,
					       1);
		  goto dispatch0;
		}

	      sa0->dst_port = clib_net_to_host_u16 (udp0->src_port);
	      res = ikev2_process_auth_req (vm, sa0, ike0, rlen);
	      if (res)
		ikev2_sa_auth (sa0);
	      else
		vlib_node_increment_counter (vm, node->node_index,
					     IKEV2_ERROR_MALFORMED_PACKET, 1);
	      if (sa0->state == IKEV2_STATE_AUTHENTICATED)
		{
		  ikev2_initial_contact_cleanup (ptd, sa0);
		  ikev2_sa_match_ts (sa0);
		  if (sa0->state != IKEV2_STATE_TS_UNACCEPTABLE)
		    ikev2_create_tunnel_interface (vm, sa0,
						   &sa0->childs[0],
						   p[0], 0, 0);
		}

	      if (sa0->is_initiator)
		{
		  ikev2_del_sa_init (sa0->ispi);
		}
	      else
		{
		  ike0->flags = IKEV2_HDR_FLAG_RESPONSE;
		  slen = ikev2_generate_message (b0, sa0, ike0, 0, udp0);
		  if (~0 == slen)
		    vlib_node_increment_counter (vm, node->node_index,
						 IKEV2_ERROR_NO_BUFF_SPACE,
						 1);
		}
	    }
	}
      else if (ike0->exchange == IKEV2_EXCHANGE_INFORMATIONAL)
	{
	  uword *p;
	  p = hash_get (ptd->sa_by_rspi, clib_net_to_host_u64 (ike0->rspi));
	  if (p)
	    {
	      sa0 = pool_elt_at_index (ptd->sas, p[0]);
	      slen = ikev2_retransmit_resp (sa0, ike0);
	      if (slen)
		{
		  vlib_node_increment_counter (vm, node->node_index,
					       ~0 ==
					       slen ?
					       IKEV2_ERROR_IKE_REQ_IGNORE
					       :
					       IKEV2_ERROR_IKE_REQ_RETRANSMIT,
					       1);
		  goto dispatch0;
		}

	      res = ikev2_process_informational_req (vm, sa0, ike0, rlen);
	      if (!res)
		{
		  vlib_node_increment_counter (vm, node->node_index,
					       IKEV2_ERROR_MALFORMED_PACKET,
					       1);
		  slen = ~0;
		  goto dispatch0;
		}

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
	      if (ike_hdr_is_request (ike0))
		{
		  ike0->flags = IKEV2_HDR_FLAG_RESPONSE;
		  slen = ikev2_generate_message (b0, sa0, ike0, 0, udp0);
		  if (~0 == slen)
		    vlib_node_increment_counter (vm, node->node_index,
						 IKEV2_ERROR_NO_BUFF_SPACE,
						 1);
		}
	    }
	}
      else if (ike0->exchange == IKEV2_EXCHANGE_CREATE_CHILD_SA)
	{
	  uword *p;
	  p = hash_get (ptd->sa_by_rspi, clib_net_to_host_u64 (ike0->rspi));
	  if (p)
	    {
	      sa0 = pool_elt_at_index (ptd->sas, p[0]);
	      slen = ikev2_retransmit_resp (sa0, ike0);
	      if (slen)
		{
		  vlib_node_increment_counter (vm, node->node_index,
					       ~0 ==
					       slen ?
					       IKEV2_ERROR_IKE_REQ_IGNORE
					       :
					       IKEV2_ERROR_IKE_REQ_RETRANSMIT,
					       1);
		  goto dispatch0;
		}

	      res = ikev2_process_create_child_sa_req (vm, sa0, ike0, rlen);
	      if (!res)
		{
		  vlib_node_increment_counter (vm, node->node_index,
					       IKEV2_ERROR_MALFORMED_PACKET,
					       1);
		  slen = ~0;
		  goto dispatch0;
		}

	      if (sa0->rekey)
		{
		  if (sa0->rekey[0].protocol_id != IKEV2_PROTOCOL_IKE)
		    {
		      if (sa0->childs)
			ikev2_sa_free_all_child_sa (&sa0->childs);
		      ikev2_child_sa_t *child;
		      vec_add2 (sa0->childs, child, 1);
		      clib_memset (child, 0, sizeof (*child));
		      child->r_proposals = sa0->rekey[0].r_proposal;
		      child->i_proposals = sa0->rekey[0].i_proposal;
		      child->tsi = sa0->rekey[0].tsi;
		      child->tsr = sa0->rekey[0].tsr;
		      ikev2_create_tunnel_interface (vm, sa0, child, p[0],
						     child - sa0->childs, 1);
		    }
		  if (ike_hdr_is_response (ike0))
		    {
		      vec_free (sa0->rekey);
		    }
		  else
		    {
		      ike0->flags = IKEV2_HDR_FLAG_RESPONSE;
		      slen = ikev2_generate_message (b0, sa0, ike0, 0, udp0);
		      if (~0 == slen)
			vlib_node_increment_counter (vm, node->node_index,
						     IKEV2_ERROR_NO_BUFF_SPACE,
						     1);
		    }
		}
	    }
	}
      else
	{
	  ikev2_elog_uint_peers_addr (ike0->exchange, ip40, ip60, is_ip4);
	}

    dispatch0:
      /* if we are sending packet back, rewrite headers */
      if (slen && ~0 != slen)
	{
	  if (is_ip4)
	    {
	      next[0] = IKEV2_NEXT_IP4_LOOKUP;
	      ikev2_rewrite_v4_addrs (sa0, ip40);
	    }
	  else
	    {
	      next[0] = IKEV2_NEXT_IP6_LOOKUP;
	      ikev2_rewrite_v6_addrs (sa0, ip60);
	    }

	  if (is_req)
	    {
	      udp0->dst_port = udp0->src_port =
		clib_net_to_host_u16 (ikev2_get_port (sa0));

	      if (udp0->dst_port == clib_net_to_host_u16 (IKEV2_PORT_NATT)
		  && ikev2_natt_active (sa0))
		{
		  if (!has_non_esp_marker)
		    slen = ikev2_insert_non_esp_marker (ike0, slen);
		}
	    }
	  else
	    {
	      if (has_non_esp_marker)
		slen += sizeof (ikev2_non_esp_marker);

	      u16 tp = udp0->dst_port;
	      udp0->dst_port = udp0->src_port;
	      udp0->src_port = tp;
	    }

	  udp0->length = clib_host_to_net_u16 (slen + sizeof (udp_header_t));
	  udp0->checksum = 0;
	  b0->current_length = slen + ip_hdr_sz + sizeof (udp_header_t);
	  if (is_ip4)
	    {
	      ip40->length = clib_host_to_net_u16 (b0->current_length);
	      ip40->checksum = ip4_header_checksum (ip40);
	    }
	  else
	    {
	      ip60->payload_length =
		clib_host_to_net_u16 (b0->current_length - sizeof (*ip60));
	    }
	}
      /* delete sa */
      if (sa0 && (sa0->state == IKEV2_STATE_DELETED ||
		  sa0->state == IKEV2_STATE_NOTIFY_AND_DELETE))
	{
	  ikev2_child_sa_t *c;

	  vec_foreach (c, sa0->childs)
	    ikev2_delete_tunnel_interface (km->vnet_main, sa0, c);

	  ikev2_delete_sa (ptd, sa0);
	}
      if (PREDICT_FALSE ((node->flags & VLIB_NODE_FLAG_TRACE)
			 && (b0->flags & VLIB_BUFFER_IS_TRACED)))
	{

	  ikev2_trace_t *t = vlib_add_trace (vm, node, b0, sizeof (*t));
	  t->sw_if_index = vnet_buffer (b0)->sw_if_index[VLIB_RX];
	  t->next_index = next[0];
	}
      n_left -= 1;
      next += 1;
      b += 1;
    }

  vlib_node_increment_counter (vm, node->node_index,
			       IKEV2_ERROR_PROCESSED, frame->n_vectors);
  vlib_buffer_enqueue_to_next (vm, node, from, nexts, frame->n_vectors);
  return frame->n_vectors;
}

static uword
ikev2_ip4 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ikev2_node_internal (vm, node, frame, 1 /* is_ip4 */ );
}

static uword
ikev2_ip6 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  return ikev2_node_internal (vm, node, frame, 0 /* is_ip4 */ );
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (ikev2_node_ip4,static) = {
  .function = ikev2_ip4,
  .name = "ikev2-ip4",
  .vector_size = sizeof (u32),
  .format_trace = format_ikev2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ikev2_error_strings),
  .error_strings = ikev2_error_strings,

  .n_next_nodes = IKEV2_IP4_N_NEXT,
  .next_nodes = {
    [IKEV2_NEXT_IP4_LOOKUP] = "ip4-lookup",
    [IKEV2_NEXT_IP4_ERROR_DROP] = "error-drop",
  },
};

VLIB_REGISTER_NODE (ikev2_node_ip6,static) = {
  .function = ikev2_ip6,
  .name = "ikev2-ip6",
  .vector_size = sizeof (u32),
  .format_trace = format_ikev2_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = ARRAY_LEN(ikev2_error_strings),
  .error_strings = ikev2_error_strings,

  .n_next_nodes = IKEV2_IP6_N_NEXT,
  .next_nodes = {
    [IKEV2_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [IKEV2_NEXT_IP6_ERROR_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

// set ikev2 proposals when vpp is used as initiator
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
	&& td->encr_type == ts->crypto_alg
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

  if (IKEV2_TRANSFORM_INTEG_TYPE_NONE != ts->integ_alg)
    {
      /* Integrity */
      error = 1;
      vec_foreach (td, km->supported_transforms)
      {
	if (td->type == IKEV2_TRANSFORM_TYPE_INTEG
	    && td->integ_type == ts->integ_alg)
	  {
	    vec_add1 (proposal->transforms, *td);
	    error = 0;
	    break;
	  }
      }
      if (error)
	{
	  ikev2_elog_error
	    ("Didn't find any supported algorithm for IKEV2_TRANSFORM_TYPE_INTEG");
	  r = clib_error_return (0, "Unsupported algorithm");
	  return r;
	}
    }

  /* PRF */
  if (is_ike)
    {
      error = 1;
      vec_foreach (td, km->supported_transforms)
      {
	if (td->type == IKEV2_TRANSFORM_TYPE_PRF
	    && td->prf_type == IKEV2_TRANSFORM_PRF_TYPE_PRF_HMAC_SHA2_256)
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
  if (is_ike)
    {
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
ikev2_send_ike (vlib_main_t * vm, ip_address_t * src, ip_address_t * dst,
		u32 bi0, u32 len, u16 src_port, u16 dst_port, u32 sw_if_index)
{
  ip4_header_t *ip40;
  ip6_header_t *ip60;
  udp_header_t *udp0;
  vlib_buffer_t *b0;
  vlib_frame_t *f;
  u32 *to_next;

  b0 = vlib_get_buffer (vm, bi0);
  vlib_buffer_advance (b0, -sizeof (udp_header_t));
  udp0 = vlib_buffer_get_current (b0);
  udp0->dst_port = clib_host_to_net_u16 (dst_port);
  udp0->src_port = clib_host_to_net_u16 (src_port);
  udp0->length = clib_host_to_net_u16 (len + sizeof (udp_header_t));
  udp0->checksum = 0;

  if (ip_addr_version (dst) == AF_IP4)
    {
      vlib_buffer_advance (b0, -sizeof (ip4_header_t));
      ip40 = vlib_buffer_get_current (b0);
      ip40->ip_version_and_header_length = 0x45;
      ip40->tos = 0;
      ip40->fragment_id = 0;
      ip40->flags_and_fragment_offset = 0;
      ip40->ttl = 0xff;
      ip40->protocol = IP_PROTOCOL_UDP;
      ip40->dst_address.as_u32 = ip_addr_v4 (dst).as_u32;
      ip40->src_address.as_u32 = ip_addr_v4 (src).as_u32;
      b0->current_length =
	len + sizeof (ip4_header_t) + sizeof (udp_header_t);
      ip40->length = clib_host_to_net_u16 (b0->current_length);
      ip40->checksum = ip4_header_checksum (ip40);
    }
  else
    {
      vlib_buffer_advance (b0, -sizeof (ip6_header_t));
      ip60 = vlib_buffer_get_current (b0);

      b0->current_length = len + sizeof (*ip60) + sizeof (udp_header_t);
      ip60->ip_version_traffic_class_and_flow_label =
	clib_host_to_net_u32 (0x6 << 28);
      ip60->payload_length =
	clib_host_to_net_u16 (b0->current_length - sizeof (*ip60));
      ip60->protocol = IP_PROTOCOL_UDP;
      ip60->hop_limit = 0xff;
      clib_memcpy_fast (ip60->src_address.as_u8, ip_addr_v6 (src).as_u8,
			sizeof (ip60->src_address));
      clib_memcpy_fast (ip60->dst_address.as_u8, ip_addr_v6 (dst).as_u8,
			sizeof (ip60->src_address));
    }

  b0->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  vnet_buffer (b0)->sw_if_index[VLIB_RX] = sw_if_index;
  vnet_buffer (b0)->sw_if_index[VLIB_TX] = ~0;

  u32 next_index = (ip_addr_version (dst) == AF_IP4) ?
    ip4_lookup_node.index : ip6_lookup_node.index;

  /* send the request */
  f = vlib_get_frame_to_node (vm, next_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi0;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);

}

static u32
ikev2_get_new_ike_header_buff (vlib_main_t * vm, vlib_buffer_t ** b)
{
  u32 bi0;
  if (vlib_buffer_alloc (vm, &bi0, 1) != 1)
    {
      *b = 0;
      return 0;
    }
  *b = vlib_get_buffer (vm, bi0);
  return bi0;
}

clib_error_t *
ikev2_set_local_key (vlib_main_t * vm, u8 * file)
{
  ikev2_main_t *km = &ikev2_main;

  if (km->pkey)
    EVP_PKEY_free (km->pkey);
  km->pkey = ikev2_load_key_file (file);
  if (km->pkey == NULL)
    return clib_error_return (0, "load key '%s' failed", file);

  return 0;
}

static_always_inline vnet_api_error_t
ikev2_register_udp_port (ikev2_profile_t * p, u16 port)
{
  ikev2_main_t *km = &ikev2_main;
  udp_dst_port_info_t *pi;

  uword *v = hash_get (km->udp_ports, port);
  pi = udp_get_dst_port_info (&udp_main, port, UDP_IP4);

  if (v)
    {
      /* IKE already uses this port, only increment reference counter */
      ASSERT (pi);
      v[0]++;
    }
  else
    {
      if (pi)
	return VNET_API_ERROR_UDP_PORT_TAKEN;

      udp_register_dst_port (km->vlib_main, port,
			     ipsec4_tun_input_node.index, 1);
      hash_set (km->udp_ports, port, 1);
    }
  p->ipsec_over_udp_port = port;
  return 0;
}

static_always_inline void
ikev2_unregister_udp_port (ikev2_profile_t * p)
{
  ikev2_main_t *km = &ikev2_main;
  uword *v;

  if (p->ipsec_over_udp_port == IPSEC_UDP_PORT_NONE)
    return;

  v = hash_get (km->udp_ports, p->ipsec_over_udp_port);
  if (!v)
    return;

  v[0]--;

  if (v[0] == 0)
    {
      udp_unregister_dst_port (km->vlib_main, p->ipsec_over_udp_port, 1);
      hash_unset (km->udp_ports, p->ipsec_over_udp_port);
    }

  p->ipsec_over_udp_port = IPSEC_UDP_PORT_NONE;
}

static void
ikev2_initiate_delete_ike_sa_internal (vlib_main_t * vm,
				       ikev2_main_per_thread_data_t * tkm,
				       ikev2_sa_t * sa, u8 send_notification)
{
  ikev2_main_t *km = &ikev2_main;
  ip_address_t *src, *dst;
  vlib_buffer_t *b0;
  ikev2_child_sa_t *c;

  /* Create the Initiator notification for IKE SA removal */
  ike_header_t *ike0;
  u32 bi0 = 0;
  int len;

  vec_resize (sa->del, 1);
  sa->del->protocol_id = IKEV2_PROTOCOL_IKE;
  sa->del->spi = sa->ispi;

  if (send_notification)
    {
      bi0 = ikev2_get_new_ike_header_buff (vm, &b0);
      if (!bi0)
	{
	  ikev2_log_error ("buffer alloc failure");
	  goto delete_sa;
	}

      ike0 = vlib_buffer_get_current (b0);
      ike0->exchange = IKEV2_EXCHANGE_INFORMATIONAL;
      ike0->ispi = clib_host_to_net_u64 (sa->ispi);
      ike0->rspi = clib_host_to_net_u64 (sa->rspi);
      ike0->flags = 0;
      ike0->msgid = clib_host_to_net_u32 (sa->last_init_msg_id);
      sa->last_init_msg_id += 1;
      len = ikev2_generate_message (b0, sa, ike0, 0, 0);
      if (~0 == len)
	return;

      if (ikev2_natt_active (sa))
	len = ikev2_insert_non_esp_marker (ike0, len);

      if (sa->is_initiator)
	{
	  src = &sa->iaddr;
	  dst = &sa->raddr;
	}
      else
	{
	  dst = &sa->iaddr;
	  src = &sa->raddr;
	}

      ikev2_send_ike (vm, src, dst, bi0, len,
		      ikev2_get_port (sa), sa->dst_port, 0);
    }

delete_sa:
  /* delete local SA */
  vec_foreach (c, sa->childs)
    ikev2_delete_tunnel_interface (km->vnet_main, sa, c);

  u64 rspi = sa->rspi;
  ikev2_sa_free_all_vec (sa);
  uword *p = hash_get (tkm->sa_by_rspi, rspi);
  if (p)
    {
      hash_unset (tkm->sa_by_rspi, rspi);
      pool_put (tkm->sas, sa);
    }
}

static void
ikev2_cleanup_profile_sessions (ikev2_main_t * km, ikev2_profile_t * p)
{
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *sa;
  u32 pi = p - km->profiles;
  u32 *sai;
  u32 *del_sai = 0;

  /* *INDENT-OFF* */
  pool_foreach(sa, km->sais, ({
    if (pi == sa->profile_index)
      vec_add1 (del_sai, sa - km->sais);
  }));
  /* *INDENT-ON* */

  vec_foreach (sai, del_sai)
  {
    sa = pool_elt_at_index (km->sais, sai[0]);
    ikev2_sa_free_all_vec (sa);
    hash_unset (km->sa_by_ispi, sa->ispi);
    pool_put (km->sais, sa);
  }
  vec_reset_length (del_sai);

  vec_foreach (tkm, km->per_thread_data)
  {
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      if (sa->profile_index != ~0 && pi == sa->profile_index)
        vec_add1 (del_sai, sa - tkm->sas);
    }));
    /* *INDENT-ON* */

    vec_foreach (sai, del_sai)
    {
      sa = pool_elt_at_index (tkm->sas, sai[0]);
      ikev2_initiate_delete_ike_sa_internal (km->vlib_main, tkm, sa, 1);
    }

    vec_reset_length (del_sai);
  }

  vec_free (del_sai);
}

static void
ikev2_profile_free (ikev2_profile_t * p)
{
  vec_free (p->name);

  vec_free (p->auth.data);
  if (p->auth.key)
    EVP_PKEY_free (p->auth.key);

  vec_free (p->loc_id.data);
  vec_free (p->rem_id.data);
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
      clib_memset (p, 0, sizeof (*p));
      p->name = vec_dup (name);
      p->ipsec_over_udp_port = IPSEC_UDP_PORT_NONE;
      p->responder.sw_if_index = ~0;
      p->tun_itf = ~0;
      uword index = p - km->profiles;
      mhash_set_mem (&km->profile_index_by_name, name, &index, 0);
    }
  else
    {
      p = ikev2_profile_index_by_name (name);
      if (!p)
	return clib_error_return (0, "policy %v does not exists", name);

      ikev2_unregister_udp_port (p);
      ikev2_cleanup_profile_sessions (km, p);

      ikev2_profile_free (p);
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

  if (p->auth.key)
    EVP_PKEY_free (p->auth.key);
  vec_free (p->auth.data);

  p->auth.method = auth_method;
  p->auth.data = vec_dup (auth_data);
  p->auth.hex = data_hex_format;

  if (auth_method == IKEV2_AUTH_METHOD_RSA_SIG)
    {
      vec_add1 (p->auth.data, 0);
      p->auth.key = ikev2_load_cert_file (p->auth.data);
      if (p->auth.key == NULL)
	return clib_error_return (0, "load cert '%s' failed", p->auth.data);
    }

  return 0;
}

static int
ikev2_is_id_supported (u8 id_type)
{
  return (id_type == IKEV2_ID_TYPE_ID_IPV4_ADDR ||
	  id_type == IKEV2_ID_TYPE_ID_IPV6_ADDR ||
	  id_type == IKEV2_ID_TYPE_ID_RFC822_ADDR ||
	  id_type == IKEV2_ID_TYPE_ID_FQDN);
}

clib_error_t *
ikev2_set_profile_id (vlib_main_t * vm, u8 * name, u8 id_type, u8 * data,
		      int is_local)
{
  ikev2_profile_t *p;
  clib_error_t *r;

  if (!ikev2_is_id_supported (id_type))
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

static_always_inline void
ikev2_set_ts_type (ikev2_ts_t * ts, const ip_address_t * addr)
{
  if (ip_addr_version (addr) == AF_IP4)
    ts->ts_type = TS_IPV4_ADDR_RANGE;
  else
    ts->ts_type = TS_IPV6_ADDR_RANGE;
}

static_always_inline void
ikev2_set_ts_addrs (ikev2_ts_t * ts, const ip_address_t * start,
		    const ip_address_t * end)
{
  ip_address_copy (&ts->start_addr, start);
  ip_address_copy (&ts->end_addr, end);
}

clib_error_t *
ikev2_set_profile_ts (vlib_main_t * vm, u8 * name, u8 protocol_id,
		      u16 start_port, u16 end_port, ip_address_t start_addr,
		      ip_address_t end_addr, int is_local)
{
  ikev2_profile_t *p;
  clib_error_t *r;

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  if (ip_addr_version (&start_addr) != ip_addr_version (&end_addr))
    return clib_error_return (0, "IP address version mismatch!");

  if (is_local)
    {
      ikev2_set_ts_addrs (&p->loc_ts, &start_addr, &end_addr);
      p->loc_ts.start_port = start_port;
      p->loc_ts.end_port = end_port;
      p->loc_ts.protocol_id = protocol_id;
      ikev2_set_ts_type (&p->loc_ts, &start_addr);
    }
  else
    {
      ikev2_set_ts_addrs (&p->rem_ts, &start_addr, &end_addr);
      p->rem_ts.start_port = start_port;
      p->rem_ts.end_port = end_port;
      p->rem_ts.protocol_id = protocol_id;
      ikev2_set_ts_type (&p->rem_ts, &start_addr);
    }

  return 0;
}


clib_error_t *
ikev2_set_profile_responder (vlib_main_t * vm, u8 * name,
			     u32 sw_if_index, ip_address_t addr)
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
  ip_address_copy (&p->responder.addr, &addr);

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
  p->esp_ts.crypto_key_size = crypto_key_size;
  return 0;
}

clib_error_t *
ikev2_set_profile_tunnel_interface (vlib_main_t * vm,
				    u8 * name, u32 sw_if_index)
{
  ikev2_profile_t *p;
  clib_error_t *r;

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  p->tun_itf = sw_if_index;

  return 0;
}

vnet_api_error_t
ikev2_set_profile_ipsec_udp_port (vlib_main_t * vm, u8 * name, u16 port,
				  u8 is_set)
{
  ikev2_profile_t *p = ikev2_profile_index_by_name (name);
  ikev2_main_t *km = &ikev2_main;
  vnet_api_error_t rv = 0;
  uword *v;

  if (!p)
    return VNET_API_ERROR_INVALID_VALUE;

  if (is_set)
    {
      if (p->ipsec_over_udp_port != IPSEC_UDP_PORT_NONE)
	return VNET_API_ERROR_VALUE_EXIST;

      rv = ikev2_register_udp_port (p, port);
    }
  else
    {
      v = hash_get (km->udp_ports, port);
      if (!v)
	return VNET_API_ERROR_IKE_NO_PORT;

      if (p->ipsec_over_udp_port == IPSEC_UDP_PORT_NONE)
	return VNET_API_ERROR_INVALID_VALUE;

      ikev2_unregister_udp_port (p);
    }
  return rv;
}

clib_error_t *
ikev2_set_profile_udp_encap (vlib_main_t * vm, u8 * name)
{
  ikev2_profile_t *p = ikev2_profile_index_by_name (name);
  clib_error_t *r;

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  p->udp_encap = 1;
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

static int
ikev2_get_if_address (u32 sw_if_index, ip_address_family_t af,
		      ip_address_t * out_addr)
{
  ip4_address_t *if_ip4;
  ip6_address_t *if_ip6;

  if (af == AF_IP4)
    {
      if_ip4 = ip4_interface_first_address (&ip4_main, sw_if_index, 0);
      if (if_ip4)
	{
	  ip_address_set (out_addr, if_ip4, AF_IP4);
	  return 1;
	}
    }
  else
    {
      if_ip6 = ip6_interface_first_address (&ip6_main, sw_if_index);
      if (if_ip6)
	{
	  ip_address_set (out_addr, if_ip6, AF_IP6);
	  return 1;
	}
    }
  return 0;
}

clib_error_t *
ikev2_initiate_sa_init (vlib_main_t * vm, u8 * name)
{
  ikev2_profile_t *p;
  clib_error_t *r;
  ikev2_main_t *km = &ikev2_main;
  vlib_buffer_t *b0;
  ike_header_t *ike0;
  u32 bi0 = 0;
  int len = sizeof (ike_header_t), valid_ip = 0;
  ip_address_t if_ip = ip_address_initializer;

  p = ikev2_profile_index_by_name (name);

  if (!p)
    {
      r = clib_error_return (0, "unknown profile %v", name);
      return r;
    }

  if (p->responder.sw_if_index == ~0
      || ip_address_is_zero (&p->responder.addr))
    {
      r = clib_error_return (0, "responder not set for profile %v", name);
      return r;
    }

  if (ikev2_get_if_address (p->responder.sw_if_index,
			    ip_addr_version (&p->responder.addr), &if_ip))
    {
      valid_ip = 1;
    }

  /* Prepare the SA and the IKE payload */
  ikev2_sa_t sa;
  clib_memset (&sa, 0, sizeof (ikev2_sa_t));
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
  sa.profile_index = p - km->profiles;
  sa.state = IKEV2_STATE_SA_INIT;
  sa.tun_itf = p->tun_itf;
  sa.udp_encap = p->udp_encap;
  if (p->natt_disabled)
    sa.natt_state = IKEV2_NATT_DISABLED;
  sa.ipsec_over_udp_port = p->ipsec_over_udp_port;
  sa.is_tun_itf_set = 1;
  sa.initial_contact = 1;
  sa.dst_port = IKEV2_PORT;

  ikev2_generate_sa_error_t rc = ikev2_generate_sa_init_data (&sa);
  if (rc != IKEV2_GENERATE_SA_INIT_OK)
    {
      ikev2_sa_free_all_vec (&sa);
      ikev2_payload_destroy_chain (chain);
      return clib_error_return (0, "%U", format_ikev2_gen_sa_error, rc);
    }

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
  u8 *nat_detection_sha1 =
    ikev2_compute_nat_sha1 (clib_host_to_net_u64 (sa.ispi),
			    clib_host_to_net_u64 (sa.rspi),
			    &if_ip, clib_host_to_net_u16 (IKEV2_PORT));

  ikev2_payload_add_notify (chain, IKEV2_NOTIFY_MSG_NAT_DETECTION_SOURCE_IP,
			    nat_detection_sha1);
  vec_free (nat_detection_sha1);
  nat_detection_sha1 =
    ikev2_compute_nat_sha1 (clib_host_to_net_u64 (sa.ispi),
			    clib_host_to_net_u64 (sa.rspi),
			    &p->responder.addr,
			    clib_host_to_net_u16 (sa.dst_port));
  ikev2_payload_add_notify (chain,
			    IKEV2_NOTIFY_MSG_NAT_DETECTION_DESTINATION_IP,
			    nat_detection_sha1);
  vec_free (nat_detection_sha1);

  u8 *sig_hash_algo = vec_new (u8, 8);
  u64 tmpsig = clib_host_to_net_u64 (0x0001000200030004);
  clib_memcpy_fast (sig_hash_algo, &tmpsig, sizeof (tmpsig));
  ikev2_payload_add_notify (chain,
			    IKEV2_NOTIFY_MSG_SIGNATURE_HASH_ALGORITHMS,
			    sig_hash_algo);
  vec_free (sig_hash_algo);

  bi0 = ikev2_get_new_ike_header_buff (vm, &b0);
  if (!bi0)
    {
      ikev2_sa_free_all_vec (&sa);
      ikev2_payload_destroy_chain (chain);
      char *errmsg = "buffer alloc failure";
      ikev2_log_error (errmsg);
      return clib_error_return (0, errmsg);
    }
  ike0 = vlib_buffer_get_current (b0);

  /* Buffer update and boilerplate */
  len += vec_len (chain->data);
  ike0->nextpayload = chain->first_payload_type;
  ike0->length = clib_host_to_net_u32 (len);
  clib_memcpy_fast (ike0->payload, chain->data, vec_len (chain->data));
  ikev2_payload_destroy_chain (chain);

  ike0->version = IKE_VERSION_2;
  ike0->flags = IKEV2_HDR_FLAG_INITIATOR;
  ike0->exchange = IKEV2_EXCHANGE_SA_INIT;
  ike0->ispi = clib_host_to_net_u64 (sa.ispi);
  ike0->rspi = 0;
  ike0->msgid = 0;
  sa.last_init_msg_id += 1;

  /* store whole IKE payload - needed for PSK auth */
  vec_reset_length (sa.last_sa_init_req_packet_data);
  vec_add (sa.last_sa_init_req_packet_data, ike0, len);

  /* add data to the SA then add it to the pool */
  ip_address_copy (&sa.iaddr, &if_ip);
  ip_address_copy (&sa.raddr, &p->responder.addr);
  sa.i_id.type = p->loc_id.type;
  sa.i_id.data = vec_dup (p->loc_id.data);
  sa.r_id.type = p->rem_id.type;
  sa.r_id.data = vec_dup (p->rem_id.data);
  sa.i_auth.method = p->auth.method;
  sa.i_auth.hex = p->auth.hex;
  sa.i_auth.data = vec_dup (p->auth.data);
  sa.sw_if_index = p->responder.sw_if_index;
  vec_add (sa.childs[0].tsi, &p->loc_ts, 1);
  vec_add (sa.childs[0].tsr, &p->rem_ts, 1);

  ikev2_initial_contact_cleanup (0, &sa);

  /* add SA to the pool */
  ikev2_sa_t *sa0 = 0;
  pool_get (km->sais, sa0);
  clib_memcpy_fast (sa0, &sa, sizeof (*sa0));
  hash_set (km->sa_by_ispi, sa0->ispi, sa0 - km->sais);

  if (valid_ip)
    {
      ikev2_send_ike (vm, &if_ip, &p->responder.addr, bi0, len,
		      IKEV2_PORT, sa.dst_port, sa.sw_if_index);

      ikev2_elog_exchange
	("ispi %lx rspi %lx IKEV2_EXCHANGE_SA_INIT sent to ",
	 clib_host_to_net_u64 (sa0->ispi), 0,
	 ip_addr_v4 (&p->responder.addr).as_u32,
	 ip_addr_version (&p->responder.addr) == AF_IP4);
    }
  else
    {
      r =
	clib_error_return (0, "interface  %U does not have any IP address!",
			   format_vnet_sw_if_index_name, vnet_get_main (),
			   p->responder.sw_if_index);
      return r;
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
  vlib_buffer_t *b0;
  int len;

  bi0 = ikev2_get_new_ike_header_buff (vm, &b0);
  if (!bi0)
    {
      ikev2_log_error ("buffer alloc failure");
      return;
    }

  ike0 = vlib_buffer_get_current (b0);
  ike0->exchange = IKEV2_EXCHANGE_INFORMATIONAL;
  ike0->ispi = clib_host_to_net_u64 (sa->ispi);
  ike0->rspi = clib_host_to_net_u64 (sa->rspi);
  ike0->flags = 0;
  vec_resize (sa->del, 1);
  sa->del->protocol_id = IKEV2_PROTOCOL_ESP;
  sa->del->spi = csa->i_proposals->spi;
  ike0->msgid = clib_host_to_net_u32 (sa->last_init_msg_id);
  sa->last_init_msg_id += 1;
  len = ikev2_generate_message (b0, sa, ike0, 0, 0);
  if (~0 == len)
    return;

  if (ikev2_natt_active (sa))
    len = ikev2_insert_non_esp_marker (ike0, len);
  ikev2_send_ike (vm, &sa->iaddr, &sa->raddr, bi0, len,
		  ikev2_get_port (sa), sa->dst_port, sa->sw_if_index);

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

  ikev2_initiate_delete_ike_sa_internal (vm, ftkm, fsa, 1);
  return 0;
}

static void
ikev2_rekey_child_sa_internal (vlib_main_t * vm, ikev2_sa_t * sa,
			       ikev2_child_sa_t * csa)
{
  /* Create the Initiator request for create child SA */
  ike_header_t *ike0;
  vlib_buffer_t *b0;
  u32 bi0 = 0;
  int len;

  bi0 = ikev2_get_new_ike_header_buff (vm, &b0);
  if (!bi0)
    {
      ikev2_log_error ("buffer alloc failure");
      return;
    }

  ike0 = vlib_buffer_get_current (b0);
  ike0->version = IKE_VERSION_2;
  ike0->flags = IKEV2_HDR_FLAG_INITIATOR;
  ike0->exchange = IKEV2_EXCHANGE_CREATE_CHILD_SA;
  ike0->ispi = clib_host_to_net_u64 (sa->ispi);
  ike0->rspi = clib_host_to_net_u64 (sa->rspi);
  ike0->msgid = clib_host_to_net_u32 (sa->last_init_msg_id);
  sa->last_init_msg_id += 1;

  ikev2_rekey_t *rekey;
  vec_reset_length (sa->rekey);
  vec_add2 (sa->rekey, rekey, 1);
  ikev2_sa_proposal_t *proposals = vec_dup (csa->i_proposals);

  /*need new ispi */
  RAND_bytes ((u8 *) & proposals[0].spi, sizeof (proposals[0].spi));
  rekey->spi = proposals[0].spi;
  rekey->ispi = csa->i_proposals->spi;
  len = ikev2_generate_message (b0, sa, ike0, proposals, 0);
  if (~0 == len)
    return;

  if (ikev2_natt_active (sa))
    len = ikev2_insert_non_esp_marker (ike0, len);
  ikev2_send_ike (vm, &sa->iaddr, &sa->raddr, bi0, len,
		  ikev2_get_port (sa), ikev2_get_port (sa), sa->sw_if_index);
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

static int
ikev2_sa_sw_if_match (ikev2_sa_t * sa, u32 sw_if_index)
{
  return (sa->sw_if_index == sw_if_index) && sa->is_initiator;
}

static void
ikev2_sa_del (ikev2_profile_t * p, u32 sw_if_index)
{
  u64 *ispi, *ispi_vec = 0;
  ikev2_sa_t *sa, **sap, **sa_vec = 0;
  ikev2_main_t *km = &ikev2_main;
  ikev2_main_per_thread_data_t *tkm;
  p->responder.sw_if_index = ~0;

  vec_foreach (tkm, km->per_thread_data)
  {
    /* *INDENT-OFF* */
    pool_foreach (sa, tkm->sas, ({
      if (ikev2_sa_sw_if_match (sa, sw_if_index))
        vec_add1 (sa_vec, sa);
    }));
    /* *INDENT-ON* */

    vec_foreach (sap, sa_vec)
    {
      ikev2_initiate_delete_ike_sa_internal (km->vlib_main, tkm, *sap, 0);
    }
    vec_reset_length (sa_vec);
  }
  vec_free (sa_vec);

  /* *INDENT-OFF* */
  pool_foreach (sa, km->sais, ({
    if (ikev2_sa_sw_if_match (sa, sw_if_index))
      vec_add1 (ispi_vec, sa->ispi);
  }));
  /* *INDENT-ON* */

  vec_foreach (ispi, ispi_vec)
  {
    ikev2_del_sa_init_from_main (ispi);
  }

  vec_free (ispi_vec);
}

static clib_error_t *
ikev2_sw_interface_add_del (vnet_main_t * vnm, u32 sw_if_index, u32 is_add)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_profile_t *p;

  if (is_add)
    return 0;

  /* *INDENT-OFF* */
  pool_foreach (p, km->profiles, ({
    if (p->responder.sw_if_index == sw_if_index)
      ikev2_sa_del (p, sw_if_index);
  }));
  /* *INDENT-ON* */

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (ikev2_sw_interface_add_del);

clib_error_t *
ikev2_init (vlib_main_t * vm)
{
  ikev2_main_t *km = &ikev2_main;
  vlib_thread_main_t *tm = vlib_get_thread_main ();
  int thread_id;

  clib_memset (km, 0, sizeof (ikev2_main_t));
  km->vnet_main = vnet_get_main ();
  km->vlib_main = vm;

  km->liveness_period = IKEV2_LIVENESS_PERIOD_CHECK;
  km->liveness_max_retries = IKEV2_LIVENESS_RETRIES;
  ikev2_crypto_init (km);

  mhash_init_vec_string (&km->profile_index_by_name, sizeof (uword));

  vec_validate_aligned (km->per_thread_data, tm->n_vlib_mains - 1,
			CLIB_CACHE_LINE_BYTES);
  for (thread_id = 0; thread_id < tm->n_vlib_mains; thread_id++)
    {
      ikev2_main_per_thread_data_t *ptd =
	vec_elt_at_index (km->per_thread_data, thread_id);

      ptd->sa_by_rspi = hash_create (0, sizeof (uword));

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
      ptd->evp_ctx = EVP_CIPHER_CTX_new ();
      ptd->hmac_ctx = HMAC_CTX_new ();
#else
      EVP_CIPHER_CTX_init (&ptd->_evp_ctx);
      ptd->evp_ctx = &ptd->_evp_ctx;
      HMAC_CTX_init (&(ptd->_hmac_ctx));
      ptd->hmac_ctx = &ptd->_hmac_ctx;
#endif
    }

  km->sa_by_ispi = hash_create (0, sizeof (uword));
  km->sw_if_indices = hash_create (0, 0);
  km->udp_ports = hash_create (0, sizeof (uword));

  udp_register_dst_port (vm, IKEV2_PORT, ikev2_node_ip4.index, 1);
  udp_register_dst_port (vm, IKEV2_PORT, ikev2_node_ip6.index, 0);
  udp_register_dst_port (vm, IKEV2_PORT_NATT, ikev2_node_ip4.index, 1);
  udp_register_dst_port (vm, IKEV2_PORT_NATT, ikev2_node_ip6.index, 0);

  vlib_punt_hdl_t punt_hdl = vlib_punt_client_register ("ikev2-ip4");
  vlib_punt_register (punt_hdl, ipsec_punt_reason[IPSEC_PUNT_IP4_SPI_UDP_0],
		      "ikev2-ip4");
  ikev2_cli_reference ();

  km->log_level = IKEV2_LOG_ERROR;
  km->log_class = vlib_log_register_class ("ikev2", 0);
  return 0;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (ikev2_init) =
{
  .runs_after = VLIB_INITS("ipsec_init", "ipsec_punt_init"),
};
/* *INDENT-ON* */

static u8
ikev2_mngr_process_child_sa (ikev2_sa_t * sa, ikev2_child_sa_t * csa,
			     u8 del_old_ids)
{
  ikev2_main_t *km = &ikev2_main;
  ikev2_profile_t *p = 0;
  vlib_main_t *vm = km->vlib_main;
  f64 now = vlib_time_now (vm);
  u8 res = 0;

  if (sa->profile_index != ~0)
    p = pool_elt_at_index (km->profiles, sa->profile_index);

  if (sa->is_initiator && p && csa->time_to_expiration
      && now > csa->time_to_expiration)
    {
      if (!csa->is_expired || csa->rekey_retries > 0)
	{
	  ikev2_rekey_child_sa_internal (vm, sa, csa);
	  csa->time_to_expiration = now + p->handover;
	  csa->is_expired = 1;
	  if (csa->rekey_retries == 0)
	    {
	      csa->rekey_retries = 5;
	    }
	  else if (csa->rekey_retries > 0)
	    {
	      csa->rekey_retries--;
	      ikev2_log_debug ("Rekeying Child SA 0x%x, retries left %d",
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
	  return res;
	}
    }

  if (del_old_ids)
    {
      ipip_tunnel_t *ipip = NULL;
      u32 sw_if_index = sa->is_tun_itf_set ? sa->tun_itf : ~0;
      if (~0 == sw_if_index)
	{
	  ip46_address_t local_ip;
	  ip46_address_t remote_ip;
	  if (sa->is_initiator)
	    {
	      local_ip = to_ip46 (ip_addr_version (&sa->iaddr),
				  ip_addr_bytes (&sa->iaddr));
	      remote_ip = to_ip46 (ip_addr_version (&sa->raddr),
				   ip_addr_bytes (&sa->raddr));
	    }
	  else
	    {
	      local_ip = to_ip46 (ip_addr_version (&sa->raddr),
				  ip_addr_bytes (&sa->raddr));
	      remote_ip = to_ip46 (ip_addr_version (&sa->iaddr),
				   ip_addr_bytes (&sa->iaddr));
	    }

       /* *INDENT-OFF* */
       ipip_tunnel_key_t key = {
         .src = local_ip,
         .dst = remote_ip,
         .transport = IPIP_TRANSPORT_IP4,
         .fib_index = 0,
       };
       /* *INDENT-ON* */

	  ipip = ipip_tunnel_db_find (&key);

	  if (ipip)
	    sw_if_index = ipip->sw_if_index;
	  else
	    return res;
	}

      u32 *sas_in = NULL;
      vec_add1 (sas_in, csa->remote_sa_id);
      vlib_worker_thread_barrier_sync (vm);
      int rv = ipsec_tun_protect_update (sw_if_index, NULL,
					 csa->local_sa_id, sas_in);
      if (rv)
	vec_free (sas_in);
      ipsec_sa_unlock_id (ikev2_flip_alternate_sa_bit (csa->remote_sa_id));
      vlib_worker_thread_barrier_release (vm);
    }

  return res;
}

int
ikev2_set_log_level (ikev2_log_level_t log_level)
{
  ikev2_main_t *km = &ikev2_main;

  if (log_level >= IKEV2_LOG_MAX)
    {
      ikev2_log_error ("unknown logging level %d", log_level);
      return -1;
    }

  km->log_level = log_level;
  return 0;
}

clib_error_t *
ikev2_set_liveness_params (u32 period, u32 max_retries)
{
  ikev2_main_t *km = &ikev2_main;

  if (period == 0 || max_retries == 0)
    return clib_error_return (0, "invalid args");

  km->liveness_period = period;
  km->liveness_max_retries = max_retries;
  return 0;
}

clib_error_t *
ikev2_profile_natt_disable (u8 * name)
{
  ikev2_profile_t *p = ikev2_profile_index_by_name (name);
  if (!p)
    return clib_error_return (0, "unknown profile %v", name);

  p->natt_disabled = 1;
  return 0;
}

static void
ikev2_mngr_process_ipsec_sa (ipsec_sa_t * ipsec_sa)
{
  ikev2_main_t *km = &ikev2_main;
  vlib_main_t *vm = km->vlib_main;
  ikev2_main_per_thread_data_t *tkm;
  ikev2_sa_t *fsa = 0;
  ikev2_profile_t *p = 0;
  ikev2_child_sa_t *fchild = 0;
  f64 now = vlib_time_now (vm);
  vlib_counter_t counts;

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
  vlib_get_combined_counter (&ipsec_sa_counters,
			     ipsec_sa->stat_index, &counts);

  if (fsa && fsa->profile_index != ~0 && fsa->is_initiator)
    p = pool_elt_at_index (km->profiles, fsa->profile_index);

  if (fchild && p && p->lifetime_maxdata)
    {
      if (!fchild->is_expired && counts.bytes > p->lifetime_maxdata)
	{
	  fchild->time_to_expiration = now;
	}
    }
}

static void
ikev2_process_pending_sa_init_one (ikev2_main_t * km, ikev2_sa_t * sa)
{
  ikev2_profile_t *p;
  u32 bi0;
  u8 *nat_sha, *np;

  if (ip_address_is_zero (&sa->iaddr))
    {
      p = pool_elt_at_index (km->profiles, sa->profile_index);
      if (!ikev2_get_if_address (p->responder.sw_if_index,
				 ip_addr_version (&p->responder.addr),
				 &sa->iaddr))
	return;

      /* update NAT detection payload */
      np =
	ikev2_find_ike_notify_payload
	((ike_header_t *) sa->last_sa_init_req_packet_data,
	 IKEV2_NOTIFY_MSG_NAT_DETECTION_SOURCE_IP);
      if (np)
	{
	  nat_sha =
	    ikev2_compute_nat_sha1 (clib_host_to_net_u64 (sa->ispi),
				    clib_host_to_net_u64 (sa->rspi),
				    &sa->iaddr,
				    clib_host_to_net_u16 (IKEV2_PORT));
	  clib_memcpy_fast (np, nat_sha, vec_len (nat_sha));
	  vec_free (nat_sha);
	}
    }

  if (vlib_buffer_alloc (km->vlib_main, &bi0, 1) != 1)
    return;

  vlib_buffer_t *b = vlib_get_buffer (km->vlib_main, bi0);
  clib_memcpy_fast (vlib_buffer_get_current (b),
		    sa->last_sa_init_req_packet_data,
		    vec_len (sa->last_sa_init_req_packet_data));

  ikev2_send_ike (km->vlib_main, &sa->iaddr, &sa->raddr, bi0,
		  vec_len (sa->last_sa_init_req_packet_data),
		  ikev2_get_port (sa), IKEV2_PORT, sa->sw_if_index);
}

static void
ikev2_process_pending_sa_init (ikev2_main_t * km)
{
  u32 sai;
  u64 ispi;
  ikev2_sa_t *sa;

  /* *INDENT-OFF* */
  hash_foreach (ispi, sai, km->sa_by_ispi,
  ({
    sa = pool_elt_at_index (km->sais, sai);
    if (sa->init_response_received)
      continue;

    ikev2_process_pending_sa_init_one (km, sa);
  }));
  /* *INDENT-ON* */
}

static void
ikev2_send_informational_request (ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  ip_address_t *src, *dst;
  ike_header_t *ike0;
  vlib_buffer_t *b0;
  u32 bi0 = 0;
  u16 dp;
  int len;

  bi0 = ikev2_get_new_ike_header_buff (km->vlib_main, &b0);
  if (!bi0)
    {
      ikev2_log_error ("buffer alloc failure");
      return;
    }

  ike0 = vlib_buffer_get_current (b0);
  ike0->exchange = IKEV2_EXCHANGE_INFORMATIONAL;
  ike0->ispi = clib_host_to_net_u64 (sa->ispi);
  ike0->rspi = clib_host_to_net_u64 (sa->rspi);
  ike0->msgid = clib_host_to_net_u32 (sa->last_init_msg_id);
  ike0->flags = 0;
  sa->last_init_msg_id += 1;
  len = ikev2_generate_message (b0, sa, ike0, 0, 0);
  if (~0 == len)
    return;

  if (ikev2_natt_active (sa))
    len = ikev2_insert_non_esp_marker (ike0, len);

  if (sa->is_initiator)
    {
      src = &sa->iaddr;
      dst = &sa->raddr;
    }
  else
    {
      dst = &sa->iaddr;
      src = &sa->raddr;
    }

  dp = sa->dst_port ? sa->dst_port : ikev2_get_port (sa);
  ikev2_send_ike (km->vlib_main, src, dst, bi0, len, ikev2_get_port (sa), dp,
		  sa->sw_if_index);
}

void
ikev2_disable_dpd (void)
{
  ikev2_main_t *km = &ikev2_main;
  km->dpd_disabled = 1;
}

static_always_inline int
ikev2_mngr_process_responder_sas (ikev2_sa_t * sa)
{
  ikev2_main_t *km = &ikev2_main;
  vlib_main_t *vm = km->vlib_main;

  if (!sa->keys_generated)
    return 0;

  if (sa->liveness_retries >= km->liveness_max_retries)
    return 1;

  f64 now = vlib_time_now (vm);

  if (sa->liveness_period_check < now)
    {
      sa->liveness_retries++;
      sa->liveness_period_check = now + km->liveness_period;
      ikev2_send_informational_request (sa);
    }
  return 0;
}

static uword
ikev2_mngr_process_fn (vlib_main_t * vm, vlib_node_runtime_t * rt,
		       vlib_frame_t * f)
{
  ikev2_main_t *km = &ikev2_main;
  ipsec_main_t *im = &ipsec_main;
  ikev2_profile_t *p;
  ikev2_child_sa_t *c;
  u32 *sai;

  while (1)
    {
      vlib_process_wait_for_event_or_clock (vm, 2);
      vlib_process_get_events (vm, NULL);

      /* process ike child sas */
      ikev2_main_per_thread_data_t *tkm;
      vec_foreach (tkm, km->per_thread_data)
      {
	ikev2_sa_t *sa;
	u32 *to_be_deleted = 0;

        /* *INDENT-OFF* */
        pool_foreach (sa, tkm->sas, ({
          ikev2_child_sa_t *c;
          u8 del_old_ids = 0;

          if (sa->state != IKEV2_STATE_AUTHENTICATED)
            continue;

          if (sa->old_remote_id_present && 0 > sa->old_id_expiration)
            {
              sa->old_remote_id_present = 0;
              del_old_ids = 1;
            }
          else
            sa->old_id_expiration -= 1;

          vec_foreach (c, sa->childs)
            ikev2_mngr_process_child_sa(sa, c, del_old_ids);

          if (!km->dpd_disabled && ikev2_mngr_process_responder_sas (sa))
            vec_add1 (to_be_deleted, sa - tkm->sas);
        }));
        /* *INDENT-ON* */

	vec_foreach (sai, to_be_deleted)
	{
	  sa = pool_elt_at_index (tkm->sas, sai[0]);
	  u8 reinitiate = (sa->is_initiator && sa->profile_index != ~0);
	  vec_foreach (c, sa->childs)
	  {
	    ikev2_delete_tunnel_interface (km->vnet_main, sa, c);
	    ikev2_sa_del_child_sa (sa, c);
	  }
	  ikev2_sa_free_all_vec (sa);
	  hash_unset (tkm->sa_by_rspi, sa->rspi);
	  pool_put (tkm->sas, sa);

	  if (reinitiate)
	    {
	      p = pool_elt_at_index (km->profiles, sa->profile_index);
	      if (p)
		{
		  clib_error_t *e = ikev2_initiate_sa_init (vm, p->name);
		  if (e)
		    {
		      ikev2_log_error ("%U", format_clib_error, e);
		      clib_error_free (e);
		    }
		}
	    }
	}
	vec_free (to_be_deleted);
      }

      /* process ipsec sas */
      ipsec_sa_t *sa;
      /* *INDENT-OFF* */
      pool_foreach (sa, im->sad, ({
        ikev2_mngr_process_ipsec_sa(sa);
      }));
      /* *INDENT-ON* */

      ikev2_process_pending_sa_init (km);
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

VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "Internet Key Exchange (IKEv2) Protocol",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
