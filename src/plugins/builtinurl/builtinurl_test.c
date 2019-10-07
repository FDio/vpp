/*
 * builtinurl.c - skeleton vpp-api-test plug-in
 *
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <stdbool.h>

uword unformat_sw_if_index (unformat_input_t * input, va_list * args);

/* Declare message IDs */
#include <builtinurl/builtinurl.api_enum.h>
#include <builtinurl/builtinurl.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} builtinurl_test_main_t;

builtinurl_test_main_t builtinurl_test_main;

#define __plugin_msg_base builtinurl_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

static int
api_builtinurl_enable (vat_main_t * vam)
{
  vl_api_builtinurl_enable_t *mp;
  int ret;

  /* Construct the API message */
  M (BUILTINURL_ENABLE, mp);

  /* send it... */
  S (mp);

  /* Wait for a reply... */
  W (ret);
  return ret;
}

#include <builtinurl/builtinurl.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
