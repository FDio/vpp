/*
 *------------------------------------------------------------------
 * Copyright (c) 2021 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <vpp/api/types.h>

#define __plugin_msg_base sr_mpls_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <vnet/format_fns.h>
#include <vnet/srmpls/sr_mpls.api_enum.h>
#include <vnet/srmpls/sr_mpls.api_types.h>

#define vl_endianfun /* define message structures */
#include <vnet/srmpls/sr_mpls.api.h>
#undef vl_endianfun

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  u32 ping_id;
  vat_main_t *vat_main;
} sr_mpls_test_main_t;

static sr_mpls_test_main_t sr_mpls_test_main;

static int
api_sr_mpls_policy_mod (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_mpls_steering_add_del (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_mpls_policy_assign_endpoint_color (vat_main_t *vam)
{
  return -1;
}

static int
api_sr_mpls_policy_add (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sr_mpls_policy_add_t *mp;
  u32 bsid = 0;
  u32 weight = 1;
  u8 type = 0;
  u8 n_segments = 0;
  u32 sid;
  u32 *segments = NULL;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bsid %d", &bsid))
	;
      else if (unformat (i, "weight %d", &weight))
	;
      else if (unformat (i, "spray"))
	type = 1;
      else if (unformat (i, "next %d", &sid))
	{
	  n_segments += 1;
	  vec_add1 (segments, htonl (sid));
	}
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (bsid == 0)
    {
      errmsg ("bsid not set");
      return -99;
    }

  if (n_segments == 0)
    {
      errmsg ("no sid in segment stack");
      return -99;
    }

  /* Construct the API message */
  M2 (SR_MPLS_POLICY_ADD, mp, sizeof (u32) * n_segments);

  mp->bsid = htonl (bsid);
  mp->weight = htonl (weight);
  mp->is_spray = type;
  mp->n_segments = n_segments;
  memcpy (mp->segments, segments, sizeof (u32) * n_segments);
  vec_free (segments);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

static int
api_sr_mpls_policy_del (vat_main_t *vam)
{
  unformat_input_t *i = vam->input;
  vl_api_sr_mpls_policy_del_t *mp;
  u32 bsid = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (i) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (i, "bsid %d", &bsid))
	;
      else
	{
	  clib_warning ("parse error '%U'", format_unformat_error, i);
	  return -99;
	}
    }

  if (bsid == 0)
    {
      errmsg ("bsid not set");
      return -99;
    }

  /* Construct the API message */
  M (SR_MPLS_POLICY_DEL, mp);

  mp->bsid = htonl (bsid);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#include <vnet/srmpls/sr_mpls.api_test.c>

VAT_REGISTER_FEATURE_FUNCTION (vat_sr_mpls_plugin_register);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
