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

#include <stdio.h>
#include <assert.h>
#include <vlibapi/api.h>
#include "vat2/test/vat2_test.api_types.h"
#include "vat2/test/vat2_test.api_tojson.h"
#include "vat2/test/vat2_test.api_fromjson.h"

typedef cJSON *(* tojson_fn_t)(void *);
typedef void *(* fromjson_fn_t)(cJSON *o, int *len);

static void
test (tojson_fn_t tojson, fromjson_fn_t fromjson, cJSON *o, bool should_fail)
{
  // convert JSON object to API
  int len = 0;
  void *mp = (fromjson)(o, &len);
  assert(mp);

  // convert API to JSON
  cJSON *o2 = (tojson)(mp);
  assert(o2);

  if (should_fail)
    assert(!cJSON_Compare(o, o2, 1));
  else
    assert(cJSON_Compare(o, o2, 1));
  char *s2 = cJSON_Print(o2);
  assert(s2);

  char *in = cJSON_Print(o);
  printf("%s\n%s\n", in, s2);

  free(in);
  free(mp);
  cJSON_Delete(o2);
  free(s2);
}

struct msgs {
  char *name;
  tojson_fn_t tojson;
  fromjson_fn_t fromjson;
};
struct tests {
  char *s;
  bool should_fail;
};

uword *function_by_name_tojson;
uword *function_by_name_fromjson;
static void
register_functions(struct msgs msgs[], int n)
{
  int i;
  function_by_name_tojson = hash_create_string (0, sizeof (uword));
  function_by_name_fromjson = hash_create_string (0, sizeof (uword));
  for (i = 0; i < n; i++) {
    hash_set_mem(function_by_name_tojson, msgs[i].name, msgs[i].tojson);
    hash_set_mem(function_by_name_fromjson, msgs[i].name, msgs[i].fromjson);
  }
}

static void
runtest (char *s, bool should_fail)
{
  cJSON *o = cJSON_Parse(s);
  assert(o);
  char *name = cJSON_GetStringValue(cJSON_GetObjectItem(o, "_msgname"));
  assert(name);

  uword *p = hash_get_mem(function_by_name_tojson, name);
  printf ("Message name: %s\n", name);
  assert(p);
  tojson_fn_t tojson = (tojson_fn_t)p[0];

  p = hash_get_mem(function_by_name_fromjson, name);
  assert(p);
  fromjson_fn_t fromjson = (fromjson_fn_t)p[0];

  test(tojson, fromjson, o, should_fail);
  cJSON_Delete(o);
}

struct msgs msgs[] = {
  {
    .name = "test_prefix",
    .tojson = (tojson_fn_t) vl_api_test_prefix_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_prefix_t_fromjson,
  },
  {
    .name = "test_enum",
    .tojson = (tojson_fn_t) vl_api_test_enum_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_enum_t_fromjson,
  },
  {
    .name = "test_string",
    .tojson = (tojson_fn_t) vl_api_test_string_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_string_t_fromjson,
  },
  {
    .name = "test_string2",
    .tojson = (tojson_fn_t) vl_api_test_string2_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_string2_t_fromjson,
  },
  {
    .name = "test_vla",
    .tojson = (tojson_fn_t) vl_api_test_vla_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_vla_t_fromjson,
  },
  {
    .name = "test_vla2",
    .tojson = (tojson_fn_t) vl_api_test_vla2_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_vla2_t_fromjson,
  },
  {
    .name = "test_vla3",
    .tojson = (tojson_fn_t) vl_api_test_vla3_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_vla3_t_fromjson,
  },
  {
    .name = "test_vla4",
    .tojson = (tojson_fn_t) vl_api_test_vla4_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_vla4_t_fromjson,
  },
  {
    .name = "test_vla5",
    .tojson = (tojson_fn_t) vl_api_test_vla5_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_vla5_t_fromjson,
  },
  {
    .name = "test_addresses",
    .tojson = (tojson_fn_t) vl_api_test_addresses_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_addresses_t_fromjson,
  },
  {
    .name = "test_addresses2",
    .tojson = (tojson_fn_t) vl_api_test_addresses2_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_addresses2_t_fromjson,
  },
  {
    .name = "test_addresses3",
    .tojson = (tojson_fn_t) vl_api_test_addresses3_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_addresses3_t_fromjson,
  },
  {
    .name = "test_empty",
    .tojson = (tojson_fn_t) vl_api_test_empty_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_empty_t_fromjson,
  },
  {
    .name = "test_interface",
    .tojson = (tojson_fn_t) vl_api_test_interface_t_tojson,
    .fromjson = (fromjson_fn_t) vl_api_test_interface_t_fromjson,
  },
};

struct tests tests[] = {
  { .s = "{\"_msgname\": \"test_prefix\", \"pref\": \"2001:db8::/64\"}" },
  { .s = "{\"_msgname\": \"test_prefix\", \"pref\": \"192.168.10.0/24\"}" },
  { .s = "{\"_msgname\": \"test_enum\", \"flags\": [\"RED\", \"BLUE\"]}" },
  { .s = "{\"_msgname\": \"test_enum\", \"flags\": [\"BLACK\", \"BLUE\"]}",
    .should_fail = 1 },
  { .s = "{\"_msgname\": \"test_string\", \"str\": {\"str\": \"Test string "
	 "type\"}}" },
  { .s =
      "{\"_msgname\": \"test_string2\", \"str\": \"Test string toplevel\"}" },
  { .s = "{\"_msgname\": \"test_vla\", \"count\": 5, \"vla\": [1,2,3,4,5]}" },
  { .s = "{\"_msgname\": \"test_vla2\", \"count\": 5, \"vla\": "
	 "\"0xaabbccddee\"}" },
  { .s = "{\"_msgname\": \"test_vla3\", \"count\": 2, \"vla\": [{\"data\": 1} "
	 ", {\"data\": 2} ] }" },
  { .s = "{\"_msgname\": \"test_vla4\", \"data\": { \"count\": 5, \"vla\": "
	 "[1,2,3,4,5] }}" },
  { .s = "{\"_msgname\": \"test_vla5\", \"data\": { \"count\": 5, \"vla\": "
	 "\"0xaabbccddee\" }}" },
  { .s = "{\"_msgname\": \"test_addresses\", \"a\": \"1.2.3.4\" }" },
  { .s = "{\"_msgname\": \"test_addresses\", \"a\": \"2001:db8::23\" }" },
  { .s = "{\"_msgname\": \"test_addresses2\", \"a\": [\"2001:db8::23\", "
	 "\"2001:db8::23\"] }" },
  { .s = "{\"_msgname\": \"test_addresses3\", \"n\": 2, \"a\": "
	 "[\"2001:db8::23\", \"2001:db8::23\"] }" },
  { .s = "{\"_msgname\": \"test_empty\"}" },
  { .s = "{\"_msgname\": \"test_interface\", \"sw_if_index\": 100 }" },
  { .s = "{\"_msgname\": \"test_interface\", \"sw_if_index\": 4294967295 }" },
};

int main (int argc, char **argv)
{
  clib_mem_init (0, 64 << 20);
  int n = sizeof(msgs)/sizeof(msgs[0]);
  register_functions(msgs, n);

  int i;
  n = sizeof(tests)/sizeof(tests[0]);
  for (i = 0; i < n; i++) {
    runtest(tests[i].s, tests[i].should_fail);
  }
}
