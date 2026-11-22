/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <stdio.h>
#include <assert.h>
#include <vlibapi/api.h>
#include "vat2/test/vat2_test.api_types.h"
#include <vlibapi/api_desc.h>
#include <vat2/vat2_json.h>

/* the API descriptors of the file */
#include "vat2/test/vat2_test.api_desc.c"

struct tests
{
  char *s;
  bool should_fail;
};

static void
runtest (char *s, bool should_fail)
{
  cJSON *o = cJSON_Parse (s);
  assert (o);
  char *name = cJSON_GetStringValue (cJSON_GetObjectItem (o, "_msgname"));
  assert (name);
  printf ("Message name: %s\n", name);

  // convert JSON object to API
  int len = 0;
  void *mp = vat2_json_to_msg (&vat2_test_api_desc, name, o, &len);
  assert(mp);

  // convert API to JSON
  cJSON *o2 = vat2_msg_to_json (&vat2_test_api_desc, name, mp);
  assert(o2);
  // the test messages do not have the CRC
  cJSON_DeleteItemFromObject (o2, "_crc");

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
  cJSON_Delete(o);
}

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
  int i, n;
  n = sizeof(tests)/sizeof(tests[0]);
  for (i = 0; i < n; i++) {
    runtest(tests[i].s, tests[i].should_fail);
  }
}
