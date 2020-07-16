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

#include <ctype.h>

#include <vnet/vnet.h>
#include <vnet/api_errno.h>
#include <vnet/ip/ip.h>
#include <vnet/interface.h>

#include <vnet/ipsec/ipsec.h>
#include <plugins/ikev2/ikev2.h>
#include <plugins/ikev2/ikev2_priv.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 nextpayload;
  u8 flags;
  u16 length;
  u8 protocol_id;
  u8 spi_size;
  u16 msg_type;
  u8 payload[0];
}) ike_notify_payload_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 ts_type;
  u8 protocol_id;
  u16 selector_len;
  u16 start_port;
  u16 end_port;
  ip4_address_t start_addr;
  ip4_address_t end_addr;
}) ikev2_ts_payload_entry_t;
/* *INDENT-OFF* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 nextpayload;
  u8 flags;
  u16 length;
  u8 num_ts;
  u8 reserved[3];
  ikev2_ts_payload_entry_t ts[0];
}) ike_ts_payload_header_t;
/* *INDENT-OFF* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 last_or_more;
  u8 reserved;
  u16 proposal_len;
  u8 proposal_num;
  u8 protocol_id;
  u8 spi_size;
  u8 num_transforms; u32 spi[0];
}) ike_sa_proposal_data_t;
/* *INDENT-OFF* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 last_or_more;
  u8 reserved;
  u16 transform_len;
  u8 transform_type;
  u8 reserved2;
  u16 transform_id;
  u8 attributes[0];
}) ike_sa_transform_data_t;
/* *INDENT-OFF* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  u8 nextpayload;
  u8 flags;
  u16 length;
  u8 protocol_id;
  u8 spi_size;
  u16 num_of_spi;
  u32 spi[0];
}) ike_delete_payload_header_t;
/* *INDENT-OFF* */

static ike_payload_header_t *
ikev2_payload_add_hdr (ikev2_payload_chain_t * c, u8 payload_type, int len)
{
  ike_payload_header_t *hdr =
    (ike_payload_header_t *) & c->data[c->last_hdr_off];
  u8 *tmp;

  if (c->data)
    hdr->nextpayload = payload_type;
  else
    c->first_payload_type = payload_type;

  c->last_hdr_off = vec_len (c->data);
  vec_add2 (c->data, tmp, len);
  hdr = (ike_payload_header_t *) tmp;
  clib_memset (hdr, 0, len);

  hdr->length = clib_host_to_net_u16 (len);

  return hdr;
}

static void
ikev2_payload_add_data (ikev2_payload_chain_t * c, u8 * data)
{
  u16 len;
  ike_payload_header_t *hdr;

  vec_append (c->data, data);
  hdr = (ike_payload_header_t *) & c->data[c->last_hdr_off];
  len = clib_net_to_host_u16 (hdr->length);
  hdr->length = clib_host_to_net_u16 (len + vec_len (data));
}

void
ikev2_payload_add_notify (ikev2_payload_chain_t * c, u16 msg_type, u8 * data)
{
  ikev2_payload_add_notify_2(c, msg_type, data, 0);
}

void
ikev2_payload_add_notify_2 (ikev2_payload_chain_t * c, u16 msg_type,
                               u8 * data, ikev2_notify_t * notify)
{
  ike_notify_payload_header_t *n;

  n =
    (ike_notify_payload_header_t *) ikev2_payload_add_hdr (c,
                                                           IKEV2_PAYLOAD_NOTIFY,
                                                           sizeof (*n));
  n->msg_type = clib_host_to_net_u16 (msg_type);
  if (notify)
    {
      n->protocol_id = notify->protocol_id;
      if (notify->spi)
        {
          n->spi_size = 4;
        }
    }
  ikev2_payload_add_data (c, data);
}

void
ikev2_payload_add_sa (ikev2_payload_chain_t * c,
		      ikev2_sa_proposal_t * proposals)
{
  ike_payload_header_t *ph;
  ike_sa_proposal_data_t *prop;
  ike_sa_transform_data_t *tr;
  ikev2_sa_proposal_t *p;
  ikev2_sa_transform_t *t;

  u8 *tmp;
  u8 *pr_data = 0;
  u8 *tr_data = 0;

  ikev2_payload_add_hdr (c, IKEV2_PAYLOAD_SA, sizeof (*ph));

  vec_foreach (p, proposals)
  {
    int spi_size = (p->protocol_id == IKEV2_PROTOCOL_ESP) ? 4 : 0;
    pr_data = vec_new (u8, sizeof (ike_sa_proposal_data_t) + spi_size);
    prop = (ike_sa_proposal_data_t *) pr_data;
    prop->last_or_more = proposals - p + 1 < vec_len (proposals) ? 2 : 0;
    prop->protocol_id = p->protocol_id;
    prop->proposal_num = p->proposal_num;
    prop->spi_size = spi_size;
    prop->num_transforms = vec_len (p->transforms);

    if (spi_size)
      prop->spi[0] = clib_host_to_net_u32 (p->spi);

    vec_foreach (t, p->transforms)
    {
      vec_add2 (tr_data, tmp, sizeof (*tr) + vec_len (t->attrs));
      tr = (ike_sa_transform_data_t *) tmp;
      tr->last_or_more =
	((t - p->transforms) + 1 < vec_len (p->transforms)) ? 3 : 0;
      tr->transform_type = t->type;
      tr->transform_id = clib_host_to_net_u16 (t->transform_id);
      tr->transform_len =
	clib_host_to_net_u16 (sizeof (*tr) + vec_len (t->attrs));

      if (vec_len (t->attrs) > 0)
	clib_memcpy_fast (tr->attributes, t->attrs, vec_len (t->attrs));
    }

    prop->proposal_len =
      clib_host_to_net_u16 (vec_len (tr_data) + vec_len (pr_data));
    ikev2_payload_add_data (c, pr_data);
    ikev2_payload_add_data (c, tr_data);
    vec_free (pr_data);
    vec_free (tr_data);
  }
}

void
ikev2_payload_add_ke (ikev2_payload_chain_t * c, u16 dh_group, u8 * dh_data)
{
  ike_ke_payload_header_t *ke;
  ke = (ike_ke_payload_header_t *) ikev2_payload_add_hdr (c, IKEV2_PAYLOAD_KE,
							  sizeof (*ke));

  ke->dh_group = clib_host_to_net_u16 (dh_group);
  ikev2_payload_add_data (c, dh_data);
}

void
ikev2_payload_add_nonce (ikev2_payload_chain_t * c, u8 * nonce)
{
  ikev2_payload_add_hdr (c, IKEV2_PAYLOAD_NONCE,
			 sizeof (ike_payload_header_t));
  ikev2_payload_add_data (c, nonce);
}

void
ikev2_payload_add_id (ikev2_payload_chain_t * c, ikev2_id_t * id, u8 type)
{
  ike_id_payload_header_t *idp;
  idp =
    (ike_id_payload_header_t *) ikev2_payload_add_hdr (c, type,
						       sizeof (*idp));

  idp->id_type = id->type;
  ikev2_payload_add_data (c, id->data);
}

void
ikev2_payload_add_delete (ikev2_payload_chain_t * c, ikev2_delete_t * d)
{
  ike_delete_payload_header_t *dp;
  u16 num_of_spi = vec_len (d);
  ikev2_delete_t *d2;
  dp =
    (ike_delete_payload_header_t *) ikev2_payload_add_hdr (c,
							   IKEV2_PAYLOAD_DELETE,
							   sizeof (*dp));

  if (d[0].protocol_id == IKEV2_PROTOCOL_IKE)
    {
      dp->protocol_id = 1;
    }
  else
    {
      dp->protocol_id = d[0].protocol_id;
      dp->spi_size = 4;
      dp->num_of_spi = clib_host_to_net_u16 (num_of_spi);
      vec_foreach (d2, d)
      {
	u8 *data = vec_new (u8, 4);
	u32 spi = clib_host_to_net_u32 (d2->spi);
	clib_memcpy (data, &spi, 4);
	ikev2_payload_add_data (c, data);
	vec_free (data);
      }
    }
}

void
ikev2_payload_add_auth (ikev2_payload_chain_t * c, ikev2_auth_t * auth)
{
  ike_auth_payload_header_t *ap;
  ap =
    (ike_auth_payload_header_t *) ikev2_payload_add_hdr (c,
							 IKEV2_PAYLOAD_AUTH,
							 sizeof (*ap));

  ap->auth_method = auth->method;
  ikev2_payload_add_data (c, auth->data);
}

void
ikev2_payload_add_ts (ikev2_payload_chain_t * c, ikev2_ts_t * ts, u8 type)
{
  ike_ts_payload_header_t *tsh;
  ikev2_ts_t *ts2;
  u8 *data = 0, *tmp;

  tsh =
    (ike_ts_payload_header_t *) ikev2_payload_add_hdr (c, type,
						       sizeof (*tsh));
  tsh->num_ts = vec_len (ts);

  vec_foreach (ts2, ts)
  {
    ASSERT (ts2->ts_type == 7);	/*TS_IPV4_ADDR_RANGE */
    ikev2_ts_payload_entry_t *entry;
    vec_add2 (data, tmp, sizeof (*entry));
    entry = (ikev2_ts_payload_entry_t *) tmp;
    entry->ts_type = ts2->ts_type;
    entry->protocol_id = ts2->protocol_id;
    entry->selector_len = clib_host_to_net_u16 (16);
    entry->start_port = clib_host_to_net_u16 (ts2->start_port);
    entry->end_port = clib_host_to_net_u16 (ts2->end_port);
    entry->start_addr.as_u32 = ts2->start_addr.as_u32;
    entry->end_addr.as_u32 = ts2->end_addr.as_u32;
  }

  ikev2_payload_add_data (c, data);
  vec_free (data);
}

void
ikev2_payload_chain_add_padding (ikev2_payload_chain_t * c, int bs)
{
  u8 *tmp __attribute__ ((unused));
  u8 pad_len = (vec_len (c->data) / bs + 1) * bs - vec_len (c->data);
  vec_add2 (c->data, tmp, pad_len);
  c->data[vec_len (c->data) - 1] = pad_len - 1;
}

ikev2_sa_proposal_t *
ikev2_parse_sa_payload (ike_payload_header_t * ikep, u32 rlen)
{
  ikev2_sa_proposal_t *v = 0;
  ikev2_sa_proposal_t *proposal;
  ikev2_sa_transform_t *transform;

  u32 plen = clib_net_to_host_u16 (ikep->length);
  ike_sa_proposal_data_t *sap;
  int proposal_ptr = 0;

  if (sizeof (*ikep) > rlen)
    return 0;

  rlen -= sizeof (*ikep);
  do
    {
      if (proposal_ptr + sizeof (*sap) > rlen)
        goto data_corrupted;

      sap = (ike_sa_proposal_data_t *) & ikep->payload[proposal_ptr];
      int i, transform_ptr;

      /* IKE proposal should not have SPI */
      if (sap->protocol_id == IKEV2_PROTOCOL_IKE && sap->spi_size != 0)
	goto data_corrupted;

      /* IKE proposal should not have SPI */
      if (sap->protocol_id == IKEV2_PROTOCOL_ESP && sap->spi_size != 4)
	goto data_corrupted;

      transform_ptr = proposal_ptr + sizeof (*sap) + sap->spi_size;
      if (transform_ptr > rlen)
        goto data_corrupted;

      vec_add2 (v, proposal, 1);
      proposal->proposal_num = sap->proposal_num;
      proposal->protocol_id = sap->protocol_id;

      if (sap->spi_size == 4)
	{
	  proposal->spi = clib_net_to_host_u32 (sap->spi[0]);
	}

      for (i = 0; i < sap->num_transforms; i++)
	{
	  ike_sa_transform_data_t *tr =
            (ike_sa_transform_data_t *) & ikep->payload[transform_ptr];
          if (transform_ptr + sizeof (*tr) > rlen)
            goto data_corrupted;
	  u16 tlen = clib_net_to_host_u16 (tr->transform_len);

	  if (tlen < sizeof (*tr))
	    goto data_corrupted;

	  vec_add2 (proposal->transforms, transform, 1);

	  transform->type = tr->transform_type;
	  transform->transform_id = clib_net_to_host_u16 (tr->transform_id);
          if (transform_ptr + tlen > rlen)
            goto data_corrupted;
	  if (tlen > sizeof (*tr))
	    vec_add (transform->attrs, tr->attributes, tlen - sizeof (*tr));
          transform_ptr += tlen;
	}

      proposal_ptr += clib_net_to_host_u16 (sap->proposal_len);
    }
  while (proposal_ptr < (plen - sizeof (*ikep)) && sap->last_or_more == 2);

  /* data validation */
  if (proposal_ptr != (plen - sizeof (*ikep)) || sap->last_or_more)
    goto data_corrupted;

  return v;

data_corrupted:
  ikev2_elog_detail ("SA payload data corrupted");
  ikev2_sa_free_proposal_vector (&v);
  return 0;
}

ikev2_ts_t *
ikev2_parse_ts_payload (ike_payload_header_t * ikep, u32 rlen)
{
  ike_ts_payload_header_t *tsp = (ike_ts_payload_header_t *) ikep;
  ikev2_ts_t *r = 0, *ts;
  u8 i;

  if (sizeof (*tsp) > rlen)
    return 0;

  if (sizeof (*tsp) + tsp->num_ts * sizeof (ikev2_ts_payload_entry_t) > rlen)
    return 0;

  for (i = 0; i < tsp->num_ts; i++)
    {
      if (tsp->ts[i].ts_type != 7)	/*  TS_IPV4_ADDR_RANGE */
        {
          ikev2_elog_uint (IKEV2_LOG_ERROR,
              "unsupported TS type received (%u)", tsp->ts[i].ts_type);
          continue;
        }

      vec_add2 (r, ts, 1);
      ts->ts_type = tsp->ts[i].ts_type;
      ts->protocol_id = tsp->ts[i].protocol_id;
      ts->start_port = tsp->ts[i].start_port;
      ts->end_port = tsp->ts[i].end_port;
      ts->start_addr.as_u32 = tsp->ts[i].start_addr.as_u32;
      ts->end_addr.as_u32 = tsp->ts[i].end_addr.as_u32;
    }
  return r;
}

ikev2_notify_t *
ikev2_parse_notify_payload (ike_payload_header_t * ikep, u32 rlen)
{
  ike_notify_payload_header_t *n = (ike_notify_payload_header_t *) ikep;
  u32 plen = clib_net_to_host_u16 (n->length);
  ikev2_notify_t *r = 0;
  u32 spi;

  if (sizeof (*n) > rlen)
    return 0;

  r = vec_new (ikev2_notify_t, 1);
  r->msg_type = clib_net_to_host_u16 (n->msg_type);
  r->protocol_id = n->protocol_id;

  if (n->spi_size == 4)
    {
      if (sizeof (spi) + sizeof (*n) > rlen)
        goto cleanup;

      clib_memcpy (&spi, n->payload, n->spi_size);
      r->spi = clib_net_to_host_u32 (spi);
    }
  else if (n->spi_size == 0)
    {
      r->spi = 0;
    }
  else
    {
      clib_warning ("invalid SPI Size %d", n->spi_size);
      goto cleanup;
    }

  if (plen > (sizeof (*n) + n->spi_size))
    {
      if (plen <= sizeof (*n) + n->spi_size)
        goto cleanup;

      u32 data_len = plen - sizeof (*n) - n->spi_size;
      vec_add (r->data, n->payload + n->spi_size, data_len);
    }
  return r;

cleanup:
  vec_free (r);
  return 0;
}

void
ikev2_parse_vendor_payload (ike_payload_header_t * ikep)
{
  u32 plen = clib_net_to_host_u16 (ikep->length);
  ikev2_elog_uint (IKEV2_LOG_DEBUG, "vendor payload skipped, len %d", plen);
}

ikev2_delete_t *
ikev2_parse_delete_payload (ike_payload_header_t * ikep, u32 rlen)
{
  ike_delete_payload_header_t * d = (ike_delete_payload_header_t *) ikep;
  ikev2_delete_t *r = 0, *del;
  u16 i, num_of_spi;

  if (rlen < sizeof (*d))
    return 0;

  num_of_spi = clib_net_to_host_u16 (d->num_of_spi);
  if (d->protocol_id == IKEV2_PROTOCOL_IKE)
    {
      r = vec_new (ikev2_delete_t, 1);
      r->protocol_id = 1;
    }
  else
    {
      if (sizeof (*d) + num_of_spi * sizeof (u32) > rlen)
        return 0;

      for (i = 0; i < num_of_spi; i++)
      {
        vec_add2 (r, del, 1);
        del->protocol_id = d->protocol_id;
	del->spi = clib_net_to_host_u32 (d->spi[i]);
      }
    }

  return r;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
