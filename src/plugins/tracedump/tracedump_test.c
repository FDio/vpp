/*
 * tracedump.c - tracedump vpp-api-test plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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

#define __plugin_msg_base tracedump_test_main.msg_id_base
#include <vlibapi/vat_helper_macros.h>

/* Declare message IDs */
#include <tracedump/tracedump.api_enum.h>
#include <tracedump/tracedump.api_types.h>

typedef struct
{
  /* API message ID base */
  u16 msg_id_base;
  vat_main_t *vat_main;
} tracedump_test_main_t;

tracedump_test_main_t tracedump_test_main;

/*
 * List of messages that the tracedump test plugin sends,
 * and that the data plane plugin processes
 */
#include <tracedump/tracedump.api_test.c>

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
