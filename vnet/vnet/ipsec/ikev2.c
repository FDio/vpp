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
#include <vnet/ip/udp.h>
#include <vnet/ipsec/ipsec.h>
#include <vnet/ipsec/ikev2.h>
#include <vnet/ipsec/ikev2_priv.h>

static int ikev2_delete_tunnel_interface(vnet_main_t * vnm,
                                         ikev2_sa_t *sa,
                                         ikev2_child_sa_t * child);

#define ikev2_set_state(sa, v) do { \
    (sa)->state = v; \
    clib_warning("sa state changed to " #v); \
  } while(0);

typedef struct {
  u32 next_index;
  u32 sw_if_index;
} ikev2_trace_t;

static u8 * format_ikev2_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  ikev2_trace_t * t = va_arg (*args, ikev2_trace_t *);

  s = format (s, "ikev2: sw_if_index %d, next index %d",
              t->sw_if_index, t->next_index);
  return s;
}

vlib_node_registration_t ikev2_node;

#define foreach_ikev2_error \
_(PROCESSED, "IKEv2 packets processed") \
_(IKE_SA_INIT_RETRANSMIT, "IKE_SA_INIT retransmit ") \
_(IKE_SA_INIT_IGNORE, "IKE_SA_INIT ignore (IKE SA already auth)") \
_(IKE_REQ_RETRANSMIT, "IKE request retransmit") \
_(IKE_REQ_IGNORE, "IKE request ignore (old msgid)") \
_(NOT_IKEV2, "Non IKEv2 packets received")

typedef enum {
#define _(sym,str) IKEV2_ERROR_##sym,
  foreach_ikev2_error
#undef _
  IKEV2_N_ERROR,
} ikev2_error_t;

static char * ikev2_error_strings[] = {
#define _(sym,string) string,
  foreach_ikev2_error
#undef _
};

typedef enum {
  IKEV2_NEXT_IP4_LOOKUP,
  IKEV2_NEXT_ERROR_DROP,
  IKEV2_N_NEXT,
} ikev2_next_t;

static ikev2_sa_transform_t *
ikev2_find_transform_data(ikev2_sa_transform_t * t)
{
  ikev2_main_t * km = &ikev2_main;
  ikev2_sa_transform_t * td;

  vec_foreach(td, km->supported_transforms)
    {
      if (td->type != t->type)
        continue;

      if (td->transform_id != t->transform_id)
        continue;

      if (td->type == IKEV2_TRANSFORM_TYPE_ENCR)
        {
          if (vec_len(t->attrs) != 4 || t->attrs[0] != 0x80 || t->attrs[1] != 14)
            continue;

          if (((t->attrs[2] << 8 | t->attrs[3]) / 8) != td->key_len)
            continue;
        }
      return td;
    }
  return 0;
}

static ikev2_sa_proposal_t *
ikev2_select_proposal(ikev2_sa_proposal_t *proposals, ikev2_protocol_id_t prot_id)
{
  ikev2_sa_proposal_t * rv = 0;
  ikev2_sa_proposal_t * proposal;
  ikev2_sa_transform_t * transform, * new_t;
  u8 mandatory_bitmap, optional_bitmap;

  if (prot_id == IKEV2_PROTOCOL_IKE)
    {
      mandatory_bitmap = (1 << IKEV2_TRANSFORM_TYPE_ENCR)  |
                         (1 << IKEV2_TRANSFORM_TYPE_PRF)   |
                         (1 << IKEV2_TRANSFORM_TYPE_INTEG) |
                         (1 << IKEV2_TRANSFORM_TYPE_DH);
      optional_bitmap  = mandatory_bitmap;
    }
  else if (prot_id == IKEV2_PROTOCOL_ESP)
    {
      mandatory_bitmap = (1 << IKEV2_TRANSFORM_TYPE_ENCR) |
                         (1 << IKEV2_TRANSFORM_TYPE_ESN);
      optional_bitmap =  mandatory_bitmap |
                         (1 << IKEV2_TRANSFORM_TYPE_INTEG) |
                         (1 << IKEV2_TRANSFORM_TYPE_DH);
    }
  else if (prot_id == IKEV2_PROTOCOL_AH)
    {
      mandatory_bitmap = (1 << IKEV2_TRANSFORM_TYPE_INTEG) |
                         (1 << IKEV2_TRANSFORM_TYPE_ESN);
      optional_bitmap =  mandatory_bitmap |
                         (1 << IKEV2_TRANSFORM_TYPE_DH);
    }
  else
    return 0;

  vec_add2(rv, proposal, 1);

  vec_foreach(proposal, proposals)
    {
      u8 bitmap = 0;
      if (proposal->protocol_id != prot_id)
        continue;

      vec_foreach(transform, proposal->transforms)
        {
          if ((1 << transform->type) & bitmap)
            continue;

          if (ikev2_find_transform_data(transform))
            {
              bitmap |= 1 << transform->type;
              vec_add2(rv->transforms, new_t, 1);
              memcpy(new_t, transform, sizeof(*new_t));
              new_t->attrs = vec_dup(transform->attrs);
            }
        }

      clib_warning("bitmap is %x mandatory is %x optional is %x",
                   bitmap, mandatory_bitmap, optional_bitmap);

      if ((bitmap & mandatory_bitmap) == mandatory_bitmap &&
          (bitmap & ~optional_bitmap) == 0)
        {
          rv->proposal_num = proposal->proposal_num;
          rv->protocol_id = proposal->protocol_id;
          RAND_bytes((u8 *) &rv->spi, sizeof(rv->spi));
          goto done;
        }
      else
        {
          vec_free(rv->transforms);
        }
    }

  vec_free(rv);
done:
  return rv;
}

ikev2_sa_transform_t *
ikev2_sa_get_td_for_type(ikev2_sa_proposal_t * p, ikev2_transform_type_t type)
{
  ikev2_sa_transform_t * t;

  if (!p)
    return 0;

  vec_foreach(t, p->transforms)
    {
      if (t->type == type)
        return ikev2_find_transform_data(t);
    }
  return 0;
}

ikev2_child_sa_t *
ikev2_sa_get_child(ikev2_sa_t * sa, u32 spi, ikev2_protocol_id_t prot_id)
{
  ikev2_child_sa_t * c;
  vec_foreach(c, sa->childs)
    {
      if (c->i_proposals[0].spi == spi && c->i_proposals[0].protocol_id == prot_id)
        return c;
    }

  return 0;
}

void
ikev2_sa_free_proposal_vector(ikev2_sa_proposal_t ** v)
{
  ikev2_sa_proposal_t * p;
  ikev2_sa_transform_t * t;

  if (!*v)
        return;

  vec_foreach(p, *v) {
    vec_foreach(t, p->transforms) {
        vec_free(t->attrs);
    }
    vec_free(p->transforms);
  }
  vec_free(*v);
};

static void
ikev2_sa_free_all_child_sa(ikev2_child_sa_t ** childs)
{
  ikev2_child_sa_t * c;
  vec_foreach(c, *childs)
    {
      ikev2_sa_free_proposal_vector(&c->r_proposals);
      ikev2_sa_free_proposal_vector(&c->i_proposals);
      vec_free(c->sk_ai);
      vec_free(c->sk_ar);
      vec_free(c->sk_ei);
      vec_free(c->sk_er);
    }

  vec_free(*childs);
}

static void
ikev2_sa_del_child_sa(ikev2_sa_t * sa, ikev2_child_sa_t * child)
{
  ikev2_sa_free_proposal_vector(&child->r_proposals);
  ikev2_sa_free_proposal_vector(&child->i_proposals);
  vec_free(child->sk_ai);
  vec_free(child->sk_ar);
  vec_free(child->sk_ei);
  vec_free(child->sk_er);

  vec_del1(sa->childs, child - sa->childs);
}

static void
ikev2_sa_free_all_vec(ikev2_sa_t *sa)
{
  vec_free(sa->i_nonce);
  vec_free(sa->i_dh_data);
  vec_free(sa->dh_shared_key);

  ikev2_sa_free_proposal_vector(&sa->r_proposals);
  ikev2_sa_free_proposal_vector(&sa->i_proposals);

  vec_free(sa->sk_d);
  vec_free(sa->sk_ai);
  vec_free(sa->sk_ar);
  vec_free(sa->sk_ei);
  vec_free(sa->sk_er);
  vec_free(sa->sk_pi);
  vec_free(sa->sk_pr);

  vec_free(sa->i_id.data);
  vec_free(sa->i_auth.data);
  vec_free(sa->r_id.data);
  vec_free(sa->r_auth.data);
  if (sa->r_auth.key)
    EVP_PKEY_free(sa->r_auth.key);

  vec_free(sa->del);

  ikev2_sa_free_all_child_sa(&sa->childs);
}

static void
ikev2_delete_sa(ikev2_sa_t *sa)
{
  ikev2_main_t * km = &ikev2_main;
  uword * p;

  ikev2_sa_free_all_vec(sa);

  p = hash_get(km->sa_by_rspi, sa->rspi);
  if (p)
    {
      hash_unset(km->sa_by_rspi, sa->rspi);
      pool_put(km->sas, sa);
    }
}

static void
ikev2_generate_sa_init_data(ikev2_sa_t *sa)
{
  ikev2_sa_transform_t * t = 0, * t2;
  ikev2_main_t * km = &ikev2_main;

  if (sa->dh_group == IKEV2_TRANSFORM_DH_TYPE_NONE)
    {
      return;
    }

  /* check if received DH group is on our list of supported groups */
  vec_foreach(t2, km->supported_transforms)
    {
       if (t2->type == IKEV2_TRANSFORM_TYPE_DH &&
           sa->dh_group == t2->dh_type)
         {
            t = t2;
            break;
         }
    }

  if (!t)
    {
      clib_warning("unknown dh data group %u (data len %u)", sa->dh_group,
                 vec_len(sa->i_dh_data));
      sa->dh_group = IKEV2_TRANSFORM_DH_TYPE_NONE;
      return;
    }

  /* generate rspi */
  RAND_bytes((u8 *) &sa->rspi, 8);

  /* generate nonce */
  sa->r_nonce = vec_new(u8, IKEV2_NONCE_SIZE);
  RAND_bytes((u8 *) sa->r_nonce, IKEV2_NONCE_SIZE);

  /* generate dh keys */
  ikev2_generate_dh(sa, t);
}

static void
ikev2_calc_keys(ikev2_sa_t *sa)
{
  u8 * tmp;
  /* calculate SKEYSEED = prf(Ni | Nr, g^ir) */
  u8 * skeyseed = 0;
  u8 * s = 0;
  ikev2_sa_transform_t * tr_encr, * tr_prf, * tr_integ;
  tr_encr = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  tr_prf = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);
  tr_integ = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);

  vec_append(s, sa->i_nonce);
  vec_append(s, sa->r_nonce);
  skeyseed = ikev2_calc_prf(tr_prf, s, sa->dh_shared_key);

  /* Calculate S = Ni | Nr | SPIi | SPIr*/
  u64 * spi;
  vec_add2(s, tmp, 2 * sizeof(*spi));
  spi = (u64 *) tmp;
  spi[0] = clib_host_to_net_u64(sa->ispi);
  spi[1] = clib_host_to_net_u64(sa->rspi);

  /* calculate PRFplus */
  u8 * keymat;
  int len = tr_prf->key_trunc     + /* SK_d */
            tr_integ->key_len * 2 + /* SK_ai, SK_ar */
            tr_encr->key_len * 2  + /* SK_ei, SK_er */
            tr_prf->key_len * 2   ; /* SK_pi, SK_pr */

  keymat = ikev2_calc_prfplus(tr_prf, skeyseed, s, len);
  vec_free(skeyseed);
  vec_free(s);

  int pos = 0;

  /* SK_d */
  sa->sk_d = vec_new(u8, tr_prf->key_trunc);
  memcpy(sa->sk_d, keymat + pos, tr_prf->key_trunc);
  pos += tr_prf->key_trunc;

  /* SK_ai */
  sa->sk_ai = vec_new(u8, tr_integ->key_len);
  memcpy(sa->sk_ai, keymat + pos, tr_integ->key_len);
  pos += tr_integ->key_len;

  /* SK_ar */
  sa->sk_ar = vec_new(u8, tr_integ->key_len);
  memcpy(sa->sk_ar, keymat + pos, tr_integ->key_len);
  pos += tr_integ->key_len;

  /* SK_ei */
  sa->sk_ei = vec_new(u8, tr_encr->key_len);
  memcpy(sa->sk_ei, keymat + pos, tr_encr->key_len);
  pos += tr_encr->key_len;

  /* SK_er */
  sa->sk_er = vec_new(u8, tr_encr->key_len);
  memcpy(sa->sk_er, keymat + pos, tr_encr->key_len);
  pos += tr_encr->key_len;

  /* SK_pi */
  sa->sk_pi = vec_new(u8, tr_prf->key_len);
  memcpy(sa->sk_pi, keymat + pos, tr_prf->key_len);
  pos += tr_prf->key_len;

  /* SK_pr */
  sa->sk_pr = vec_new(u8, tr_prf->key_len);
  memcpy(sa->sk_pr, keymat + pos, tr_prf->key_len);
  pos += tr_prf->key_len;

  vec_free(keymat);
}

static void
ikev2_calc_child_keys(ikev2_sa_t *sa, ikev2_child_sa_t * child)
{
  u8 * s = 0;
  ikev2_sa_transform_t * tr_prf, * ctr_encr, * ctr_integ;
  tr_prf = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);
  ctr_encr = ikev2_sa_get_td_for_type(child->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  ctr_integ = ikev2_sa_get_td_for_type(child->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);

  vec_append(s, sa->i_nonce);
  vec_append(s, sa->r_nonce);
  /* calculate PRFplus */
  u8 * keymat;
  int len = ctr_encr->key_len * 2 + ctr_integ->key_len * 2;

  keymat = ikev2_calc_prfplus(tr_prf, sa->sk_d, s, len);

  int pos = 0;

  /* SK_ei */
  child->sk_ei = vec_new(u8, ctr_encr->key_len);
  memcpy(child->sk_ei, keymat + pos, ctr_encr->key_len);
  pos += ctr_encr->key_len;

  /* SK_ai */
  child->sk_ai = vec_new(u8, ctr_integ->key_len);
  memcpy(child->sk_ai, keymat + pos, ctr_integ->key_len);
  pos += ctr_integ->key_len;

  /* SK_er */
  child->sk_er = vec_new(u8, ctr_encr->key_len);
  memcpy(child->sk_er, keymat + pos, ctr_encr->key_len);
  pos += ctr_encr->key_len;

  /* SK_ar */
  child->sk_ar = vec_new(u8, ctr_integ->key_len);
  memcpy(child->sk_ar, keymat + pos, ctr_integ->key_len);
  pos += ctr_integ->key_len;

  ASSERT(pos == len);

  vec_free(keymat);
}

static void
ikev2_process_sa_init_req(vlib_main_t * vm, ikev2_sa_t *sa, ike_header_t * ike)
{
  int p = 0;
  u32 len = clib_net_to_host_u32(ike->length);
  u8 payload = ike->nextpayload;

  clib_warning("ispi %lx rspi %lx nextpayload %x version %x "
               "exchange %x flags %x msgid %x length %u",
               clib_net_to_host_u64(ike->ispi),
               clib_net_to_host_u64(ike->rspi),
               payload, ike->version,
               ike->exchange, ike->flags,
               clib_net_to_host_u32(ike->msgid),
               len);

  sa->ispi = clib_net_to_host_u64(ike->ispi);

  /* store whole IKE payload - needed for PSK auth */
  vec_free(sa->last_sa_init_req_packet_data);
  vec_add(sa->last_sa_init_req_packet_data, ike, len);

  while (p < len && payload!= IKEV2_PAYLOAD_NONE) {
    ike_payload_header_t * ikep = (ike_payload_header_t *) &ike->payload[p];
    u32 plen = clib_net_to_host_u16(ikep->length);

    if (plen < sizeof(ike_payload_header_t))
      return;

    if (payload == IKEV2_PAYLOAD_SA)
      {
        ikev2_sa_free_proposal_vector(&sa->i_proposals);
        sa->i_proposals = ikev2_parse_sa_payload(ikep);
      }
    else if (payload == IKEV2_PAYLOAD_KE)
      {
        ike_ke_payload_header_t * ke = (ike_ke_payload_header_t *) ikep;
        sa->dh_group = clib_net_to_host_u16(ke->dh_group);
        vec_free(sa->i_dh_data);
        vec_add(sa->i_dh_data, ke->payload, plen - sizeof(*ke));
      }
    else if (payload == IKEV2_PAYLOAD_NONCE)
      {
        vec_free(sa->i_nonce);
        vec_add(sa->i_nonce, ikep->payload, plen - sizeof(*ikep));
      }
    else if (payload == IKEV2_PAYLOAD_NOTIFY)
      {
        ikev2_notify_t * n = ikev2_parse_notify_payload(ikep);
        vec_free(n);
      }
    else if (payload == IKEV2_PAYLOAD_VENDOR)
      {
        ikev2_parse_vendor_payload(ikep);
      }
    else
      {
        clib_warning("unknown payload %u flags %x length %u", payload, ikep->flags, plen);
        if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL) {
          ikev2_set_state(sa, IKEV2_STATE_NOTIFY_AND_DELETE);
          sa->unsupported_cp = payload;
          return;
        }
      }

    payload = ikep->nextpayload;
    p+=plen;
  }

  ikev2_set_state(sa, IKEV2_STATE_SA_INIT);
}

static u8 *
ikev2_decrypt_sk_payload(ikev2_sa_t * sa, ike_header_t * ike, u8 * payload)
{
  int p = 0;
  u8 last_payload = 0;
  u8 * hmac = 0;
  u32 len = clib_net_to_host_u32(ike->length);
  ike_payload_header_t * ikep;
  u32 plen;
  ikev2_sa_transform_t * tr_integ;
  tr_integ = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);

  while (p < len &&
         *payload != IKEV2_PAYLOAD_NONE && last_payload != IKEV2_PAYLOAD_SK)
    {
      ikep = (ike_payload_header_t *) &ike->payload[p];
      plen = clib_net_to_host_u16(ikep->length);

      if (plen < sizeof(*ikep))
        return 0;

      if (*payload == IKEV2_PAYLOAD_SK)
        {
          clib_warning("received IKEv2 payload SK, len %u", plen - 4);
          last_payload = *payload;
        }
      else
        {
          clib_warning("unknown payload %u flags %x length %u", payload, ikep->flags, plen);
          if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL)
            {
              sa->unsupported_cp = *payload;
              return 0;
            }
        }

    *payload = ikep->nextpayload;
    p+=plen;
  }

  if (last_payload != IKEV2_PAYLOAD_SK) {
    clib_warning("Last payload must be SK");
    return 0;
  }

  hmac = ikev2_calc_integr(tr_integ, sa->sk_ai,  (u8 *) ike,
                           len - tr_integ->key_trunc);

  plen = plen - sizeof(*ikep) - tr_integ->key_trunc;

  if (memcmp(hmac, &ikep->payload[plen], tr_integ->key_trunc))
    {
      clib_warning("message integrity check failed");
      vec_free(hmac);
      return 0;
    }
  vec_free(hmac);

  return ikev2_decrypt_data(sa, ikep->payload, plen);
}

static void
ikev2_initial_contact_cleanup (ikev2_sa_t * sa)
{
  ikev2_main_t * km = &ikev2_main;
  ikev2_sa_t * tmp;
  u32 i, * delete = 0;
  ikev2_child_sa_t * c;

  if (!sa->initial_contact)
    return;

  /* find old IKE SAs with the same authenticated identity */
  pool_foreach (tmp, km->sas, ({
        if (tmp->i_id.type != sa->i_id.type ||
            vec_len(tmp->i_id.data) != vec_len(sa->i_id.data) ||
            memcmp(sa->i_id.data, tmp->i_id.data, vec_len(sa->i_id.data)))
          continue;

        if (sa->rspi != tmp->rspi)
          vec_add1(delete, tmp - km->sas);
  }));

  for (i = 0; i < vec_len(delete); i++)
    {
      tmp = pool_elt_at_index(km->sas, delete[i]);
      vec_foreach(c, tmp->childs)
        ikev2_delete_tunnel_interface(km->vnet_main, tmp, c);
      ikev2_delete_sa(tmp);
    }

  vec_free(delete);
  sa->initial_contact = 0;
}

static void
ikev2_process_auth_req(vlib_main_t * vm, ikev2_sa_t *sa, ike_header_t * ike)
{
  ikev2_child_sa_t * first_child_sa;
  int p = 0;
  u32 len = clib_net_to_host_u32(ike->length);
  u8 payload = ike->nextpayload;
  u8 * plaintext = 0;

  ike_payload_header_t * ikep;
  u32 plen;

  clib_warning("ispi %lx rspi %lx nextpayload %x version %x "
               "exchange %x flags %x msgid %x length %u",
               clib_net_to_host_u64(ike->ispi),
               clib_net_to_host_u64(ike->rspi),
               payload, ike->version,
               ike->exchange, ike->flags,
               clib_net_to_host_u32(ike->msgid),
               len);

  ikev2_calc_keys(sa);

  plaintext = ikev2_decrypt_sk_payload(sa, ike, &payload);

  if (!plaintext)
    {
      if (sa->unsupported_cp)
        ikev2_set_state(sa, IKEV2_STATE_NOTIFY_AND_DELETE);
      goto cleanup_and_exit;
    }

  /* create 1st child SA */
  ikev2_sa_free_all_child_sa(&sa->childs);
  vec_add2(sa->childs, first_child_sa, 1);


  /* process encrypted payload */
  p = 0;
  while (p < vec_len(plaintext) && payload != IKEV2_PAYLOAD_NONE)
    {
      ikep = (ike_payload_header_t *) &plaintext[p];
      plen = clib_net_to_host_u16(ikep->length);

      if (plen < sizeof(ike_payload_header_t))
        goto cleanup_and_exit;

      if (payload == IKEV2_PAYLOAD_SA) /* 33 */
        {
          clib_warning("received payload SA, len %u", plen - sizeof(*ikep));
          ikev2_sa_free_proposal_vector(&first_child_sa->i_proposals);
          first_child_sa->i_proposals = ikev2_parse_sa_payload(ikep);
        }
      else if (payload == IKEV2_PAYLOAD_IDI) /* 35 */
        {
          ike_id_payload_header_t * id = (ike_id_payload_header_t *) ikep;

          sa->i_id.type = id->id_type;
          vec_free(sa->i_id.data);
          vec_add(sa->i_id.data, id->payload, plen - sizeof(*id));

          clib_warning("received payload IDi, len %u id_type %u",
                       plen - sizeof(*id), id->id_type);
        }
      else if (payload == IKEV2_PAYLOAD_AUTH) /* 39 */
        {
          ike_auth_payload_header_t * a = (ike_auth_payload_header_t *) ikep;

          sa->i_auth.method = a->auth_method;
          vec_free(sa->i_auth.data);
          vec_add(sa->i_auth.data, a->payload, plen - sizeof(*a));

          clib_warning("received payload AUTH, len %u auth_type %u",
                       plen - sizeof(*a), a->auth_method);
        }
      else if (payload == IKEV2_PAYLOAD_NOTIFY) /* 41 */
        {
          ikev2_notify_t * n = ikev2_parse_notify_payload(ikep);
          if (n->msg_type == IKEV2_NOTIFY_MSG_INITIAL_CONTACT)
            {
              sa->initial_contact = 1;
            }
          vec_free(n);
        }
      else if (payload == IKEV2_PAYLOAD_VENDOR) /* 43 */
        {
          ikev2_parse_vendor_payload(ikep);
        }
      else if (payload == IKEV2_PAYLOAD_TSI) /* 44 */
        {
          clib_warning("received payload TSi, len %u", plen - sizeof(*ikep));

          vec_free(first_child_sa->tsi);
          first_child_sa->tsi = ikev2_parse_ts_payload(ikep);
        }
      else if (payload == IKEV2_PAYLOAD_TSR) /* 45 */
        {
          clib_warning("received payload TSr, len %u", plen - sizeof(*ikep));

          vec_free(first_child_sa->tsr);
          first_child_sa->tsr = ikev2_parse_ts_payload(ikep);
        }
      else
        {
          clib_warning("unknown payload %u flags %x length %u data %u",
                       payload, ikep->flags, plen - 4,
                       format_hex_bytes, ikep->payload, plen - 4);

          if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL) {
            ikev2_set_state(sa, IKEV2_STATE_NOTIFY_AND_DELETE);
            sa->unsupported_cp = payload;
            return;
          }
        }

      payload = ikep->nextpayload;
      p += plen;
    }

cleanup_and_exit:
  vec_free(plaintext);
}

static void
ikev2_process_informational_req(vlib_main_t * vm, ikev2_sa_t *sa, ike_header_t * ike)
{
  int p = 0;
  u32 len = clib_net_to_host_u32(ike->length);
  u8 payload = ike->nextpayload;
  u8 * plaintext = 0;

  ike_payload_header_t * ikep;
  u32 plen;

  clib_warning("ispi %lx rspi %lx nextpayload %x version %x "
               "exchange %x flags %x msgid %x length %u",
               clib_net_to_host_u64(ike->ispi),
               clib_net_to_host_u64(ike->rspi),
               payload, ike->version,
               ike->exchange, ike->flags,
               clib_net_to_host_u32(ike->msgid),
               len);

  plaintext = ikev2_decrypt_sk_payload(sa, ike, &payload);

  if (!plaintext)
    goto cleanup_and_exit;

  /* process encrypted payload */
  p = 0;
  while (p < vec_len(plaintext) && payload != IKEV2_PAYLOAD_NONE)
    {
      ikep = (ike_payload_header_t *) &plaintext[p];
      plen = clib_net_to_host_u16(ikep->length);

      if (plen < sizeof(ike_payload_header_t))
        goto cleanup_and_exit;

      if (payload == IKEV2_PAYLOAD_NOTIFY) /* 41 */
        {
          ikev2_notify_t * n = ikev2_parse_notify_payload(ikep);
          if (n->msg_type == IKEV2_NOTIFY_MSG_AUTHENTICATION_FAILED)
            ikev2_set_state(sa, IKEV2_STATE_AUTH_FAILED);
          vec_free(n);
        }
      else if (payload == IKEV2_PAYLOAD_DELETE) /* 42 */
        {
          sa->del = ikev2_parse_delete_payload(ikep);
        }
      else if (payload == IKEV2_PAYLOAD_VENDOR) /* 43 */
        {
          ikev2_parse_vendor_payload(ikep);
        }
      else
        {
          clib_warning("unknown payload %u flags %x length %u data %u",
                       payload, ikep->flags, plen - 4,
                       format_hex_bytes, ikep->payload, plen - 4);

          if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL) {
            sa->unsupported_cp = payload;
            return;
          }
        }

      payload = ikep->nextpayload;
      p += plen;
    }

cleanup_and_exit:
  vec_free(plaintext);
}

static void
ikev2_process_create_child_sa_req(vlib_main_t * vm, ikev2_sa_t *sa, ike_header_t * ike)
{
  int p = 0;
  u32 len = clib_net_to_host_u32(ike->length);
  u8 payload = ike->nextpayload;
  u8 * plaintext = 0;
  u8 rekeying = 0;
  u8 i_nonce[IKEV2_NONCE_SIZE];

  ike_payload_header_t * ikep;
  u32 plen;
  ikev2_notify_t * n = 0;
  ikev2_ts_t * tsi = 0;
  ikev2_ts_t * tsr = 0;
  ikev2_sa_proposal_t * proposal = 0;
  ikev2_child_sa_t * child_sa;

  clib_warning("ispi %lx rspi %lx nextpayload %x version %x "
               "exchange %x flags %x msgid %x length %u",
               clib_net_to_host_u64(ike->ispi),
               clib_net_to_host_u64(ike->rspi),
               payload, ike->version,
               ike->exchange, ike->flags,
               clib_net_to_host_u32(ike->msgid),
               len);

  plaintext = ikev2_decrypt_sk_payload(sa, ike, &payload);

  if (!plaintext)
    goto cleanup_and_exit;

  /* process encrypted payload */
  p = 0;
  while (p < vec_len(plaintext) && payload != IKEV2_PAYLOAD_NONE)
    {
      ikep = (ike_payload_header_t *) &plaintext[p];
      plen = clib_net_to_host_u16(ikep->length);

      if (plen < sizeof(ike_payload_header_t))
        goto cleanup_and_exit;

      else if (payload == IKEV2_PAYLOAD_SA)
        {
          proposal = ikev2_parse_sa_payload(ikep);
        }
      else if (payload == IKEV2_PAYLOAD_NOTIFY)
        {
          n = ikev2_parse_notify_payload(ikep);
          if (n->msg_type == IKEV2_NOTIFY_MSG_REKEY_SA)
            {
              rekeying = 1;
            }
        }
      else if (payload == IKEV2_PAYLOAD_DELETE)
        {
          sa->del = ikev2_parse_delete_payload(ikep);
        }
      else if (payload == IKEV2_PAYLOAD_VENDOR)
        {
          ikev2_parse_vendor_payload(ikep);
        }
      else if (payload == IKEV2_PAYLOAD_NONCE)
        {
          memcpy(i_nonce, ikep->payload, plen - sizeof(*ikep));
        }
      else if (payload == IKEV2_PAYLOAD_TSI)
        {
          tsi = ikev2_parse_ts_payload(ikep);
        }
      else if (payload == IKEV2_PAYLOAD_TSR)
        {
          tsr = ikev2_parse_ts_payload(ikep);
        }
      else
        {
          clib_warning("unknown payload %u flags %x length %u data %u",
                       payload, ikep->flags, plen - 4,
                       format_hex_bytes, ikep->payload, plen - 4);

          if (ikep->flags & IKEV2_PAYLOAD_FLAG_CRITICAL) {
            sa->unsupported_cp = payload;
            return;
          }
        }

      payload = ikep->nextpayload;
      p += plen;
    }

  if (rekeying)
    {
      ikev2_rekey_t * rekey;
      child_sa = ikev2_sa_get_child(sa, n->spi, n->protocol_id);
      if (!child_sa)
        {
          clib_warning("child SA spi %lx not found", n->spi);
          goto cleanup_and_exit;
        }
      vec_add2(sa->rekey, rekey, 1);
      rekey->protocol_id = n->protocol_id;
      rekey->spi = n->spi;
      rekey->i_proposal = proposal;
      rekey->r_proposal = ikev2_select_proposal(proposal, IKEV2_PROTOCOL_ESP);
      rekey->tsi = tsi;
      rekey->tsr = tsr;
      /* update Ni */
      vec_free(sa->i_nonce);
      vec_add(sa->i_nonce, i_nonce, IKEV2_NONCE_SIZE);
      /* generate new Nr */
      vec_free(sa->r_nonce);
      sa->r_nonce = vec_new(u8, IKEV2_NONCE_SIZE);
      RAND_bytes((u8 *) sa->r_nonce, IKEV2_NONCE_SIZE);
    }

cleanup_and_exit:
  vec_free(plaintext);
  vec_free(n);
}

static u8 *
ikev2_sa_generate_authmsg(ikev2_sa_t *sa, int is_responder)
{
  u8 * authmsg = 0;
  u8 * data;
  u8 * nonce;
  ikev2_id_t * id;
  u8 * key;
  u8 * packet_data;
  ikev2_sa_transform_t * tr_prf;

  tr_prf = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);

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

  data = vec_new(u8, 4);
  data[0] = id->type;
  vec_append(data, id->data);

  u8 * id_hash = ikev2_calc_prf(tr_prf, key, data);
  vec_append(authmsg, packet_data);
  vec_append(authmsg, nonce);
  vec_append(authmsg, id_hash);
  vec_free(id_hash);
  vec_free(data);

  return authmsg;
}

static int
ikev2_ts_cmp(ikev2_ts_t * ts1, ikev2_ts_t * ts2)
{
  if (ts1->ts_type == ts2->ts_type && ts1->protocol_id == ts2->protocol_id &&
      ts1->start_port == ts2->start_port && ts1->end_port == ts2->end_port &&
      ts1->start_addr.as_u32 == ts2->start_addr.as_u32 &&
      ts1->end_addr.as_u32 == ts2->end_addr.as_u32)
    return 1;

  return 0;
}

static void
ikev2_sa_match_ts(ikev2_sa_t *sa)
{
  ikev2_main_t * km = &ikev2_main;
  ikev2_profile_t * p;
  ikev2_ts_t * ts, * tsi = 0, * tsr = 0;

  pool_foreach (p, km->profiles, ({

    /* check id */
    if (p->rem_id.type != sa->i_id.type ||
        vec_len(p->rem_id.data) != vec_len(sa->i_id.data) ||
        memcmp(p->rem_id.data, sa->i_id.data, vec_len(p->rem_id.data)))
      continue;

    vec_foreach(ts, sa->childs[0].tsi)
      {
        if (ikev2_ts_cmp(&p->rem_ts, ts))
          {
            tsi = vec_dup(ts);
            break;
          }
      }

    vec_foreach(ts, sa->childs[0].tsr)
      {
        if (ikev2_ts_cmp(&p->loc_ts, ts))
          {
            tsr = vec_dup(ts);
            break;
          }
      }

    break;
  }));

  if (tsi && tsr)
    {
      vec_free(sa->childs[0].tsi);
      vec_free(sa->childs[0].tsr);
      sa->childs[0].tsi = tsi;
      sa->childs[0].tsr = tsr;
    }
  else
    {
      vec_free(tsi);
      vec_free(tsr);
      ikev2_set_state(sa, IKEV2_STATE_TS_UNACCEPTABLE);
    }
}

static void
ikev2_sa_auth(ikev2_sa_t *sa)
{
  ikev2_main_t * km = &ikev2_main;
  ikev2_profile_t * p, * sel_p = 0;
  u8 * authmsg, * key_pad, * psk = 0, * auth = 0;
  ikev2_sa_transform_t * tr_prf;

  tr_prf = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_PRF);

  /* only shared key and rsa signature */
  if (!(sa->i_auth.method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC ||
        sa->i_auth.method == IKEV2_AUTH_METHOD_RSA_SIG))
    {
      clib_warning("unsupported authentication method %u", sa->i_auth.method);
      ikev2_set_state(sa, IKEV2_STATE_AUTH_FAILED);
      return;
    }

  key_pad = format(0, "%s", IKEV2_KEY_PAD);
  authmsg = ikev2_sa_generate_authmsg(sa, 0);

  pool_foreach (p, km->profiles, ({

    /* check id */
    if (p->rem_id.type != sa->i_id.type ||
        vec_len(p->rem_id.data) != vec_len(sa->i_id.data) ||
        memcmp(p->rem_id.data, sa->i_id.data, vec_len(p->rem_id.data)))
      continue;

    if (sa->i_auth.method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
      {
        if (!p->auth.data ||
             p->auth.method != IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
          continue;

        psk = ikev2_calc_prf(tr_prf, p->auth.data, key_pad);
        auth = ikev2_calc_prf(tr_prf, psk, authmsg);

        if (!memcmp(auth, sa->i_auth.data, vec_len(sa->i_auth.data)))
          {
            ikev2_set_state(sa, IKEV2_STATE_AUTHENTICATED);
            vec_free(auth);
            sel_p = p;
            break;
          }

      }
    else if (sa->i_auth.method == IKEV2_AUTH_METHOD_RSA_SIG)
      {
        if (p->auth.method != IKEV2_AUTH_METHOD_RSA_SIG)
          continue;

        if (ikev2_verify_sign(p->auth.key, sa->i_auth.data, authmsg) == 1)
          {
            ikev2_set_state(sa, IKEV2_STATE_AUTHENTICATED);
            sel_p = p;
            break;
          }
      }

    vec_free(auth);
    vec_free(psk);
  }));

  vec_free(authmsg);

  if (sa->state == IKEV2_STATE_AUTHENTICATED)
    {
      vec_free(sa->r_id.data);
      sa->r_id.data = vec_dup(sel_p->loc_id.data);
      sa->r_id.type = sel_p->loc_id.type;

      /* generate our auth data */
      authmsg = ikev2_sa_generate_authmsg(sa, 1);
      if (sel_p->auth.method == IKEV2_AUTH_METHOD_SHARED_KEY_MIC)
        {
          sa->r_auth.data = ikev2_calc_prf(tr_prf, psk, authmsg);
          sa->r_auth.method = IKEV2_AUTH_METHOD_SHARED_KEY_MIC;
        }
      else if (sel_p->auth.method == IKEV2_AUTH_METHOD_RSA_SIG)
        {
          sa->r_auth.data = ikev2_calc_sign(km->pkey, authmsg);
          sa->r_auth.method = IKEV2_AUTH_METHOD_RSA_SIG;
        }
      vec_free(authmsg);

      /* select transforms for 1st child sa */
      ikev2_sa_free_proposal_vector(&sa->childs[0].r_proposals);
      sa->childs[0].r_proposals = ikev2_select_proposal(sa->childs[0].i_proposals,
                                                       IKEV2_PROTOCOL_ESP);
    }
  else
    {
      ikev2_set_state(sa, IKEV2_STATE_AUTH_FAILED);
    }
  vec_free(psk);
  vec_free(key_pad);
}

static int
ikev2_create_tunnel_interface(vnet_main_t * vnm, ikev2_sa_t *sa, ikev2_child_sa_t * child)
{
  ipsec_add_del_tunnel_args_t a;
  ikev2_sa_transform_t * tr;
  u32 hw_if_index;
  u8  encr_type = 0;

  if (!child->r_proposals)
    {
      ikev2_set_state(sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
      return 1;
    }

  a.is_add = 1;
  a.local_ip.as_u32 = sa->raddr.as_u32;
  a.remote_ip.as_u32 = sa->iaddr.as_u32;
  a.local_spi = child->i_proposals[0].spi;
  a.remote_spi = child->r_proposals[0].spi;
  a.anti_replay = 1;

  tr = ikev2_sa_get_td_for_type(child->r_proposals, IKEV2_TRANSFORM_TYPE_ESN);
  if (tr)
      a.esn = tr->esn_type;
  else
    a.esn = 0;

  tr = ikev2_sa_get_td_for_type(child->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
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
                ikev2_set_state(sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
                return 1;
                break;
            }
        }
      else
        {
          ikev2_set_state(sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
          return 1;
        }
    }
  else
    {
      ikev2_set_state(sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
      return 1;
    }

  tr = ikev2_sa_get_td_for_type(child->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);
  if (tr)
    {
      if (tr->integ_type != IKEV2_TRANSFORM_INTEG_TYPE_AUTH_HMAC_SHA1_96)
        {
          ikev2_set_state(sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
          return 1;
        }
    }
  else
    {
      ikev2_set_state(sa, IKEV2_STATE_NO_PROPOSAL_CHOSEN);
      return 1;
    }

  hw_if_index = ipsec_add_del_tunnel_if(vnm, &a);
  if (hw_if_index == VNET_API_ERROR_INVALID_VALUE)
    {
      clib_warning("create tunnel interface failed remote-ip %U remote-spi %u",
                   format_ip4_address, &sa->raddr, child->r_proposals[0].spi);
      ikev2_set_state(sa, IKEV2_STATE_DELETED);
      return hw_if_index;
    }

  ikev2_calc_child_keys(sa, child);

  ipsec_set_interface_key(vnm, hw_if_index,
                          IPSEC_IF_SET_KEY_TYPE_LOCAL_CRYPTO,
                          encr_type,
                          child->sk_er);

  ipsec_set_interface_key(vnm, hw_if_index,
                          IPSEC_IF_SET_KEY_TYPE_REMOTE_CRYPTO,
                          encr_type,
                          child->sk_ei);

  ipsec_set_interface_key(vnm, hw_if_index,
                          IPSEC_IF_SET_KEY_TYPE_LOCAL_INTEG,
                          IPSEC_INTEG_ALG_SHA1_96,
                          child->sk_ar);

  ipsec_set_interface_key(vnm, hw_if_index,
                          IPSEC_IF_SET_KEY_TYPE_REMOTE_INTEG,
                          IPSEC_INTEG_ALG_SHA1_96,
                          child->sk_ai);

  return 0;
}

static int
ikev2_delete_tunnel_interface(vnet_main_t * vnm, ikev2_sa_t *sa, ikev2_child_sa_t * child)
{
  ipsec_add_del_tunnel_args_t a;

  if (!vec_len(child->r_proposals))
    return 0;

  a.is_add = 0;
  a.local_ip.as_u32 = sa->raddr.as_u32;
  a.remote_ip.as_u32 = sa->iaddr.as_u32;
  a.local_spi = child->i_proposals[0].spi;
  a.remote_spi = child->r_proposals[0].spi;

  return ipsec_add_del_tunnel_if(vnm, &a);
}

static u32
ikev2_generate_resp(ikev2_sa_t *sa, ike_header_t * ike)
{
  v8 * integ = 0;
  ike_payload_header_t * ph;
  u16 plen;
  u32 tlen = 0;

  ikev2_sa_transform_t * tr_encr, *tr_integ;
  tr_encr = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_ENCR);
  tr_integ = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_INTEG);

  ikev2_payload_chain_t * chain = 0;
  ikev2_payload_new_chain(chain);

  if (ike->exchange == IKEV2_EXCHANGE_SA_INIT)
    {
      if (sa->r_proposals == 0)
        {
          ikev2_payload_add_notify(chain, IKEV2_NOTIFY_MSG_NO_PROPOSAL_CHOSEN, 0);
          ikev2_set_state(sa, IKEV2_STATE_NOTIFY_AND_DELETE);
        }
      else if (sa->dh_group == IKEV2_TRANSFORM_DH_TYPE_NONE)
        {
           u8 * data = vec_new(u8, 2);
           ikev2_sa_transform_t * tr_dh;
           tr_dh = ikev2_sa_get_td_for_type(sa->r_proposals, IKEV2_TRANSFORM_TYPE_DH);
           ASSERT(tr_dh && tr_dh->dh_type);

           data[0] = (tr_dh->dh_type >> 8) & 0xff;
           data[1] = (tr_dh->dh_type) & 0xff;

           ikev2_payload_add_notify(chain, IKEV2_NOTIFY_MSG_INVALID_KE_PAYLOAD, data);
           vec_free(data);
           ikev2_set_state(sa, IKEV2_STATE_NOTIFY_AND_DELETE);
        }
      else if (sa->state == IKEV2_STATE_NOTIFY_AND_DELETE)
        {
           u8 * data = vec_new(u8, 1);

           data[0] = sa->unsupported_cp;
           ikev2_payload_add_notify(chain,
                                    IKEV2_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
                                    data);
           vec_free(data);
        }
      else
        {
          ike->rspi = clib_host_to_net_u64(sa->rspi);
          ikev2_payload_add_sa(chain, sa->r_proposals);
          ikev2_payload_add_ke(chain, sa->dh_group, sa->r_dh_data);
          ikev2_payload_add_nonce(chain, sa->r_nonce);
        }
    }
  else if (ike->exchange == IKEV2_EXCHANGE_IKE_AUTH)
    {
      if (sa->state == IKEV2_STATE_AUTHENTICATED)
        {
          ikev2_payload_add_id(chain, &sa->r_id, IKEV2_PAYLOAD_IDR);
          ikev2_payload_add_auth(chain, &sa->r_auth);
          ikev2_payload_add_sa(chain, sa->childs[0].r_proposals);
          ikev2_payload_add_ts(chain, sa->childs[0].tsi, IKEV2_PAYLOAD_TSI);
          ikev2_payload_add_ts(chain, sa->childs[0].tsr, IKEV2_PAYLOAD_TSR);
        }
      else if (sa->state == IKEV2_STATE_AUTH_FAILED)
        {
          ikev2_payload_add_notify(chain, IKEV2_NOTIFY_MSG_AUTHENTICATION_FAILED, 0);
          ikev2_set_state(sa, IKEV2_STATE_NOTIFY_AND_DELETE);
        }
      else if (sa->state == IKEV2_STATE_TS_UNACCEPTABLE)
        {
          ikev2_payload_add_notify(chain, IKEV2_NOTIFY_MSG_TS_UNACCEPTABLE, 0);
          ikev2_payload_add_id(chain, &sa->r_id, IKEV2_PAYLOAD_IDR);
          ikev2_payload_add_auth(chain, &sa->r_auth);
        }
      else if (sa->state == IKEV2_STATE_NO_PROPOSAL_CHOSEN)
        {
          ikev2_payload_add_notify(chain, IKEV2_NOTIFY_MSG_NO_PROPOSAL_CHOSEN, 0);
          ikev2_payload_add_id(chain, &sa->r_id, IKEV2_PAYLOAD_IDR);
          ikev2_payload_add_auth(chain, &sa->r_auth);
          ikev2_payload_add_ts(chain, sa->childs[0].tsi, IKEV2_PAYLOAD_TSI);
          ikev2_payload_add_ts(chain, sa->childs[0].tsr, IKEV2_PAYLOAD_TSR);
        }
      else if (sa->state == IKEV2_STATE_NOTIFY_AND_DELETE)
        {
           u8 * data = vec_new(u8, 1);

           data[0] = sa->unsupported_cp;
           ikev2_payload_add_notify(chain,
                                    IKEV2_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
                                    data);
           vec_free(data);
        }
      else
        {
          ikev2_set_state(sa, IKEV2_STATE_DELETED);
          goto done;
        }
    }
  else if (ike->exchange == IKEV2_EXCHANGE_INFORMATIONAL)
    {
      /* if pending delete */
      if (sa->del)
        {
          /* The response to a request that deletes the IKE SA is an empty
             INFORMATIONAL response. */
          if (sa->del[0].protocol_id == IKEV2_PROTOCOL_IKE)
            {
              ikev2_set_state(sa, IKEV2_STATE_NOTIFY_AND_DELETE);
            }
          /* The response to a request that deletes ESP or AH SAs will contain
             delete payloads for the paired SAs going in the other direction. */
          else
            {
              ikev2_payload_add_delete(chain, sa->del);
            }
          vec_free(sa->del);
          sa->del = 0;
        }
      /* received N(AUTHENTICATION_FAILED) */
      else if (sa->state == IKEV2_STATE_AUTH_FAILED)
        {
          ikev2_set_state(sa, IKEV2_STATE_DELETED);
          goto done;
        }
      /* received unsupported critical payload */
      else if (sa->unsupported_cp)
        {
           u8 * data = vec_new(u8, 1);

           data[0] = sa->unsupported_cp;
           ikev2_payload_add_notify(chain,
                                    IKEV2_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
                                    data);
           vec_free(data);
           sa->unsupported_cp = 0;
        }
      /* else send empty response */
    }
  else if (ike->exchange == IKEV2_EXCHANGE_CREATE_CHILD_SA)
    {
      if (sa->rekey)
        {
          ikev2_payload_add_sa(chain, sa->rekey[0].r_proposal);
          ikev2_payload_add_nonce(chain, sa->r_nonce);
          ikev2_payload_add_ts(chain, sa->rekey[0].tsi, IKEV2_PAYLOAD_TSI);
          ikev2_payload_add_ts(chain, sa->rekey[0].tsr, IKEV2_PAYLOAD_TSR);
          vec_del1(sa->rekey, 0);
        }
      else if (sa->unsupported_cp)
        {
           u8 * data = vec_new(u8, 1);

           data[0] = sa->unsupported_cp;
           ikev2_payload_add_notify(chain,
                                    IKEV2_NOTIFY_MSG_UNSUPPORTED_CRITICAL_PAYLOAD,
                                    data);
           vec_free(data);
           sa->unsupported_cp = 0;
        }
      else
        {
           ikev2_payload_add_notify(chain, IKEV2_NOTIFY_MSG_NO_ADDITIONAL_SAS, 0);
        }
    }

  /* IKEv2 header */
  ike->version = IKE_VERSION_2;
  ike->flags = IKEV2_HDR_FLAG_RESPONSE;
  ike->nextpayload = IKEV2_PAYLOAD_SK;
  tlen = sizeof(*ike);


  if (ike->exchange == IKEV2_EXCHANGE_SA_INIT)
    {
      tlen += vec_len(chain->data);
      ike->nextpayload = chain->first_payload_type;
      ike->length = clib_host_to_net_u32(tlen);
      memcpy(ike->payload, chain->data, vec_len(chain->data));

      /* store whole IKE payload - needed for PSK auth */
      vec_free(sa->last_sa_init_res_packet_data);
      vec_add(sa->last_sa_init_res_packet_data, ike, tlen);
    }
  else
    {

      ikev2_payload_chain_add_padding(chain, tr_encr->block_size);

      /* SK payload */
      plen = sizeof(*ph);
      ph = (ike_payload_header_t *) &ike->payload[0];
      ph->nextpayload = chain->first_payload_type;
      ph->flags = 0;
      int enc_len = ikev2_encrypt_data(sa, chain->data, ph->payload);
      plen += enc_len;

      /* add space for hmac */
      plen += tr_integ->key_trunc;
      tlen += plen;

      /* payload and total length */
      ph->length = clib_host_to_net_u16(plen);
      ike->length = clib_host_to_net_u32(tlen);

      /* calc integrity data for whole packet except hash itself */
      integ = ikev2_calc_integr(tr_integ, sa->sk_ar, (u8 *) ike,
                                tlen - tr_integ->key_trunc);

      memcpy(ike->payload + tlen - tr_integ->key_trunc - sizeof(*ike),
             integ, tr_integ->key_trunc);

      /* store whole IKE payload - needed for retransmit */
      vec_free(sa->last_res_packet_data);
      vec_add(sa->last_res_packet_data, ike, tlen);
    }

done:
  ikev2_payload_destroy_chain (chain);
  vec_free(integ);
  return tlen;
}

static int
ikev2_retransmit_sa_init (ike_header_t * ike,
                          ip4_address_t iaddr,
                          ip4_address_t raddr)
{
  ikev2_main_t * km = &ikev2_main;
  ikev2_sa_t * sa;

  pool_foreach (sa, km->sas, ({
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
                      memcpy(ike->payload, tmp->payload,
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

  /* req is not retransmit */
  return 0;
}

static int
ikev2_retransmit_resp (ikev2_sa_t * sa, ike_header_t * ike)
{
  u32 msg_id = clib_net_to_host_u32(ike->msgid);

  /* new req */
  if (msg_id > sa->last_msg_id)
    {
      sa->last_msg_id = msg_id;
      return 0;
    }
  /* retransmitted req */
  else if (msg_id == sa->last_msg_id)
    {
      ike_header_t * tmp;
      tmp = (ike_header_t*)sa->last_res_packet_data;
      ike->ispi = tmp->ispi;
      ike->rspi = tmp->rspi;
      ike->nextpayload = tmp->nextpayload;
      ike->version = tmp->version;
      ike->exchange = tmp->exchange;
      ike->flags = tmp->flags;
      ike->msgid = tmp->msgid;
      ike->length = tmp->length;
      memcpy(ike->payload, tmp->payload,
             clib_net_to_host_u32(tmp->length) - sizeof(*ike));
      clib_warning("IKE msgid %u retransmit from %U to %U",
                   msg_id,
                   format_ip4_address, &sa->raddr,
                   format_ip4_address, &sa->iaddr);
      return 1;
    }
  /* old req ignore */
  else
    {
      clib_warning("IKE msgid %u req ignore from %U to %U",
                   msg_id,
                   format_ip4_address, &sa->raddr,
                   format_ip4_address, &sa->iaddr);
      return -1;
    }
}

static uword
ikev2_node_fn (vlib_main_t * vm,
      vlib_node_runtime_t * node,
      vlib_frame_t * frame)
{
  u32 n_left_from, * from, * to_next;
  ikev2_next_t next_index;
  ikev2_main_t * km = &ikev2_main;

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
          vlib_buffer_t * b0;
          u32 next0 = IKEV2_NEXT_ERROR_DROP;
          u32 sw_if_index0;
          ip4_header_t * ip40;
          udp_header_t * udp0;
          ike_header_t * ike0;
          ikev2_sa_t * sa0 = 0;
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
          vlib_buffer_advance(b0, - sizeof(*udp0));
          udp0 = vlib_buffer_get_current (b0);
          vlib_buffer_advance(b0, - sizeof(*ip40));
          ip40 = vlib_buffer_get_current (b0);

          if (ike0->version != IKE_VERSION_2)
            {
              vlib_node_increment_counter(vm, ikev2_node.index,
                                        IKEV2_ERROR_NOT_IKEV2, 1);
              goto dispatch0;
            }

          if (ike0->exchange == IKEV2_EXCHANGE_SA_INIT)
            {
              ikev2_sa_t sa; /* temporary store for SA */
              sa0 = &sa;
              memset (sa0, 0, sizeof (*sa0));

              if (ike0->rspi == 0)
                {
                  sa0->raddr.as_u32 = ip40->dst_address.as_u32;
                  sa0->iaddr.as_u32 = ip40->src_address.as_u32;

                  r = ikev2_retransmit_sa_init(ike0, sa0->iaddr, sa0->raddr);
                  if (r == 1)
                    {
                      vlib_node_increment_counter(vm, ikev2_node.index,
                                                  IKEV2_ERROR_IKE_SA_INIT_RETRANSMIT,
                                                  1);
                      len = clib_net_to_host_u32(ike0->length);
                      goto dispatch0;
                    }
                  else if (r == -1)
                    {
                      vlib_node_increment_counter(vm, ikev2_node.index,
                                                  IKEV2_ERROR_IKE_SA_INIT_IGNORE,
                                                  1);
                      goto dispatch0;
                    }

                  ikev2_process_sa_init_req(vm, sa0, ike0);

                  if (sa0->state == IKEV2_STATE_SA_INIT)
                    {
                      ikev2_sa_free_proposal_vector(&sa0->r_proposals);
                      sa0->r_proposals = ikev2_select_proposal(sa0->i_proposals,
                                                              IKEV2_PROTOCOL_IKE);
                      ikev2_generate_sa_init_data(sa0);
                    }

                  if (sa0->state == IKEV2_STATE_SA_INIT ||
                      sa0->state == IKEV2_STATE_NOTIFY_AND_DELETE)
                    {
                      len = ikev2_generate_resp(sa0, ike0);
                    }

                  if (sa0->state == IKEV2_STATE_SA_INIT)
                    {
                      /* add SA to the pool */
                      pool_get (km->sas, sa0);
                      memcpy(sa0, &sa, sizeof(*sa0));
                      hash_set (km->sa_by_rspi, sa0->rspi, sa0 - km->sas);
                    }
                  else
                    {
                      ikev2_sa_free_all_vec(sa0);
                    }
                }
            }
          else if (ike0->exchange == IKEV2_EXCHANGE_IKE_AUTH)
            {
              uword * p;
              p = hash_get(km->sa_by_rspi, clib_net_to_host_u64(ike0->rspi));
              if (p)
                {
                  sa0 = pool_elt_at_index (km->sas, p[0]);

                  r = ikev2_retransmit_resp(sa0, ike0);
                  if (r == 1)
                    {
                      vlib_node_increment_counter(vm, ikev2_node.index,
                                                  IKEV2_ERROR_IKE_REQ_RETRANSMIT,
                                                  1);
                      len = clib_net_to_host_u32(ike0->length);
                      goto dispatch0;
                    }
                  else if (r == -1)
                    {
                      vlib_node_increment_counter(vm, ikev2_node.index,
                                                  IKEV2_ERROR_IKE_REQ_IGNORE,
                                                  1);
                      goto dispatch0;
                    }

                  ikev2_process_auth_req(vm, sa0, ike0);
                  ikev2_sa_auth(sa0);
                  if (sa0->state == IKEV2_STATE_AUTHENTICATED)
                    {
                      ikev2_initial_contact_cleanup(sa0);
                      ikev2_sa_match_ts(sa0);
                      if (sa0->state != IKEV2_STATE_TS_UNACCEPTABLE)
                        ikev2_create_tunnel_interface(km->vnet_main, sa0,
                                                      &sa0->childs[0]);
                    }
                  len = ikev2_generate_resp(sa0, ike0);
                }
            }
          else if (ike0->exchange == IKEV2_EXCHANGE_INFORMATIONAL)
            {
              uword * p;
              p = hash_get(km->sa_by_rspi, clib_net_to_host_u64(ike0->rspi));
              if (p)
                {
                  sa0 = pool_elt_at_index (km->sas, p[0]);

                  r = ikev2_retransmit_resp(sa0, ike0);
                  if (r == 1)
                    {
                      vlib_node_increment_counter(vm, ikev2_node.index,
                                                  IKEV2_ERROR_IKE_REQ_RETRANSMIT,
                                                  1);
                      len = clib_net_to_host_u32(ike0->length);
                      goto dispatch0;
                    }
                  else if (r == -1)
                    {
                      vlib_node_increment_counter(vm, ikev2_node.index,
                                                  IKEV2_ERROR_IKE_REQ_IGNORE,
                                                  1);
                      goto dispatch0;
                    }

                  ikev2_process_informational_req(vm, sa0, ike0);
                  if (sa0->del)
                    {
                      if (sa0->del[0].protocol_id != IKEV2_PROTOCOL_IKE)
                        {
                          ikev2_delete_t * d, * tmp, * resp = 0;
                          vec_foreach(d, sa0->del)
                            {
                              ikev2_child_sa_t * ch_sa;
                              ch_sa = ikev2_sa_get_child(sa0, d->spi,
                                                         d->protocol_id);
                              if (ch_sa)
                                {
                                  ikev2_delete_tunnel_interface(km->vnet_main,
                                                                sa0, ch_sa);
                                  vec_add2(resp, tmp, 1);
                                  tmp->protocol_id = d->protocol_id;
                                  tmp->spi = ch_sa->r_proposals[0].spi;
                                  ikev2_sa_del_child_sa(sa0, ch_sa);
                                }
                            }
                          vec_free(sa0->del);
                          sa0->del = resp;
                        }
                    }
                  len = ikev2_generate_resp(sa0, ike0);
                }
            }
          else if (ike0->exchange == IKEV2_EXCHANGE_CREATE_CHILD_SA)
            {
              uword * p;
              p = hash_get(km->sa_by_rspi, clib_net_to_host_u64(ike0->rspi));
              if (p)
                {
                  sa0 = pool_elt_at_index (km->sas, p[0]);

                  r = ikev2_retransmit_resp(sa0, ike0);
                  if (r == 1)
                    {
                      vlib_node_increment_counter(vm, ikev2_node.index,
                                                  IKEV2_ERROR_IKE_REQ_RETRANSMIT,
                                                  1);
                      len = clib_net_to_host_u32(ike0->length);
                      goto dispatch0;
                    }
                  else if (r == -1)
                    {
                      vlib_node_increment_counter(vm, ikev2_node.index,
                                                  IKEV2_ERROR_IKE_REQ_IGNORE,
                                                  1);
                      goto dispatch0;
                    }

                  ikev2_process_create_child_sa_req(vm, sa0, ike0);
                  if (sa0->rekey)
                    {
                      if (sa0->rekey[0].protocol_id != IKEV2_PROTOCOL_IKE)
                        {
                          ikev2_child_sa_t * child;
                          vec_add2(sa0->childs, child, 1);
                          child->r_proposals = sa0->rekey[0].r_proposal;
                          child->i_proposals = sa0->rekey[0].i_proposal;
                          child->tsi = sa0->rekey[0].tsi;
                          child->tsr = sa0->rekey[0].tsr;
                          ikev2_create_tunnel_interface(km->vnet_main, sa0,
                                                        child);
                        }
                      len = ikev2_generate_resp(sa0, ike0);
                    }
                }
            }
          else
            {
              clib_warning("IKEv2 exchange %u packet received from %U to %U",
                           ike0->exchange,
                           format_ip4_address, ip40->src_address.as_u8,
                           format_ip4_address, ip40->dst_address.as_u8);
            }

dispatch0:
          /* if we are sending packet back, rewrite headers */
          if (len)
            {
                next0 = IKEV2_NEXT_IP4_LOOKUP;
                ip40->dst_address.as_u32 = sa0->iaddr.as_u32;
                ip40->src_address.as_u32 = sa0->raddr.as_u32;
                udp0->length = clib_host_to_net_u16(len + sizeof(udp_header_t));
                udp0->checksum = 0;
                b0->current_length = len + sizeof(ip4_header_t) + sizeof(udp_header_t);
                ip40->length = clib_host_to_net_u16(b0->current_length);
                ip40->checksum = ip4_header_checksum (ip40);
            }
          /* delete sa */
          if (sa0 && (sa0->state == IKEV2_STATE_DELETED ||
              sa0->state == IKEV2_STATE_NOTIFY_AND_DELETE))
            {
              ikev2_child_sa_t * c;

              vec_foreach(c, sa0->childs)
                ikev2_delete_tunnel_interface(km->vnet_main, sa0, c);

              ikev2_delete_sa(sa0);
            }
          sw_if_index0 = vnet_buffer(b0)->sw_if_index[VLIB_RX];

          if (PREDICT_FALSE((node->flags & VLIB_NODE_FLAG_TRACE)
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

VLIB_REGISTER_NODE (ikev2_node) = {
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


static ikev2_profile_t *
ikev2_profile_index_by_name(u8 * name)
{
  ikev2_main_t * km = &ikev2_main;
  uword * p;

  p = mhash_get (&km->profile_index_by_name, name);
  if (!p)
    return 0;

  return pool_elt_at_index(km->profiles, p[0]);
}

clib_error_t *
ikev2_set_local_key(vlib_main_t * vm, u8 * file)
{
  ikev2_main_t * km = &ikev2_main;

  km->pkey = ikev2_load_key_file(file);
  if (km->pkey == NULL)
    return clib_error_return(0, "load key '%s' failed", file);

  return 0;
}

clib_error_t *
ikev2_add_del_profile(vlib_main_t * vm, u8 * name, int is_add)
{
  ikev2_main_t * km = &ikev2_main;
  ikev2_profile_t * p;

  if (is_add)
    {
      if (ikev2_profile_index_by_name(name))
        return clib_error_return(0, "policy %v already exists", name);

      pool_get (km->profiles, p);
      memset(p, 0, sizeof(*p));
      p->name = vec_dup(name);
      uword index = p - km->profiles;
      mhash_set_mem (&km->profile_index_by_name, name, &index, 0);
    }
  else
    {
      p = ikev2_profile_index_by_name(name);
      if (!p)
        return clib_error_return(0, "policy %v does not exists", name);

      vec_free (p->name);
      pool_put (km->profiles, p);
      mhash_unset (&km->profile_index_by_name, name, 0);
    }
  return 0;
}

clib_error_t *
ikev2_set_profile_auth(vlib_main_t * vm, u8 * name, u8 auth_method,
                       u8 * auth_data, u8 data_hex_format)
{
  ikev2_profile_t * p;
  clib_error_t * r;

  p = ikev2_profile_index_by_name(name);

  if (!p) {
    r = clib_error_return(0, "unknown profile %v", name);
    return r;
  }
  vec_free(p->auth.data);
  p->auth.method = auth_method;
  p->auth.data = vec_dup(auth_data);
  p->auth.hex = data_hex_format;

  if (auth_method == IKEV2_AUTH_METHOD_RSA_SIG)
    {
      if (p->auth.key)
        EVP_PKEY_free(p->auth.key);
      p->auth.key = ikev2_load_cert_file(auth_data);
      if (p->auth.key == NULL)
        return clib_error_return(0, "load cert '%s' failed", auth_data);
    }

  return 0;
}

clib_error_t *
ikev2_set_profile_id(vlib_main_t * vm, u8 * name, u8 id_type, u8 * data,
                     int is_local)
{
  ikev2_profile_t * p;
  clib_error_t * r;

  if (id_type > IKEV2_ID_TYPE_ID_RFC822_ADDR && id_type < IKEV2_ID_TYPE_ID_KEY_ID)
    {
      r = clib_error_return(0, "unsupported identity type %U",
                            format_ikev2_id_type, id_type);
      return r;
    }

  p = ikev2_profile_index_by_name(name);

  if (!p) {
    r = clib_error_return(0, "unknown profile %v", name);
    return r;
  }

  if (is_local)
    {
      vec_free(p->loc_id.data);
      p->loc_id.type = id_type;
      p->loc_id.data = vec_dup(data);
    }
  else
    {
      vec_free(p->rem_id.data);
      p->rem_id.type = id_type;
      p->rem_id.data = vec_dup(data);
    }

  return 0;
}

clib_error_t *
ikev2_set_profile_ts(vlib_main_t * vm, u8 * name, u8 protocol_id,
                     u16 start_port, u16 end_port, ip4_address_t start_addr,
                     ip4_address_t end_addr, int is_local)
{
  ikev2_profile_t * p;
  clib_error_t * r;

  p = ikev2_profile_index_by_name(name);

  if (!p) {
    r = clib_error_return(0, "unknown profile %v", name);
    return r;
  }

  if (is_local)
    {
      p->loc_ts.start_addr.as_u32= start_addr.as_u32;
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
ikev2_init (vlib_main_t * vm)
{
  ikev2_main_t * km = &ikev2_main;
  clib_error_t * error;

  memset (km, 0, sizeof (ikev2_main_t));
  km->vnet_main = vnet_get_main();
  km->vlib_main = vm;

  ikev2_crypto_init(km);

  km->sa_by_rspi = hash_create (0, sizeof (uword));
  mhash_init_vec_string (&km->profile_index_by_name, sizeof (uword));

  if ((error = vlib_call_init_function (vm, ikev2_cli_init)))
    return error;

  udp_register_dst_port (vm, 500, ikev2_node.index, 1);

  return 0;
}


