/*
 * tls_openssl_test.c - skeleton vpp-api-test plug-in
 *
 * Copyright (c) 2019 Intel Corporation
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
#include <vat/vat.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vppinfra/error.h>
#include <ctype.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <tlsopenssl/tls_openssl.api_enum.h>
#include <tlsopenssl/tls_openssl.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} tls_openssl_test_main_t;

tls_openssl_test_main_t tls_openssl_test_main;

#define __plugin_msg_base tls_openssl_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

static int
api_tls_openssl_set_engine (vat_main_t * vam)
{
  unformat_input_t *line_input = vam->input;
  vl_api_tls_openssl_set_engine_t *mp;
  u8 *engine_name = 0;
  u8 *engine_alg = 0;
  u8 *ciphers = 0;
  u32 async = 0;
  int ret;

  /* Parse args required to build the message */
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "engine %s", &engine_name))
	;
      else if (unformat (line_input, "async"))
	{
	  async = 1;
	}
      else if (unformat (line_input, "alg %s", &engine_alg))
	;
      else if (unformat (line_input, "ciphers %s", &ciphers))
	;
      else
	{
	  errmsg ("unknown input `%U'", format_unformat_error, line_input);
	  return -99;
	}
    }

  if (engine_name == 0)
    {
      errmsg ("Must specify engine name");
      return -99;
    }

  if (engine_alg == 0)
    engine_alg = format (0, "ALL");
  else
    {
      for (int i = 0; i < strnlen ((char *) engine_alg, 63); i++)
	engine_alg[i] = toupper (engine_alg[i]);
    }


  /* Construct the API message */
  M (TLS_OPENSSL_SET_ENGINE, mp);
  mp->async_enable = async;

  clib_memcpy_fast (mp->engine, engine_name,
		    strnlen ((const char *) engine_name, 63));

  clib_memcpy_fast (mp->algorithm, engine_alg,
		    strnlen ((const char *) engine_alg, 63));

  if (ciphers)
    clib_memcpy_fast (mp->ciphers, ciphers,
		      strnlen ((const char *) ciphers, 63));

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#include <tlsopenssl/tls_openssl.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
