/*
 *------------------------------------------------------------------
 * json_test.c
 *
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
 *------------------------------------------------------------------
 */
#include <vppinfra/clib.h>
#include <vppinfra/vec.h>
#include <vat/vat.h>
#include <vat/json_format.h>

static void
print_json_test (void)
{
  vat_json_node_t node;

  vat_json_init_object (&node);
  vat_json_object_add_string_copy (&node, "str", (u8 *) "string-value");
  vat_json_object_add_uint (&node, "ab", 127);
  vat_json_object_add_real (&node, "pi", 3.14159f);
  vat_json_print (stdout, &node);
  vat_json_free (&node);

  vat_json_init_object (&node);
  vat_json_node_t *a1 = vat_json_object_add (&node, "a1");
  vat_json_init_object (a1);
  vat_json_object_add_uint (a1, "b1", 512);
  vat_json_object_add_string_copy (a1, "b2", (u8 *) "string");

  vat_json_object_add_int (&node, "a2", 2);

  vat_json_node_t *a3 = vat_json_object_add_list (&node, "a3");
  vat_json_init_array (a3);
  vat_json_array_add_uint (a3, 1);
  vat_json_array_add_int (a3, -2);
  vat_json_array_add_uint (a3, 3);

  vat_json_init_object (vat_json_object_add (&node, "a4"));

  struct in_addr ipv4 = { 0 };
  struct in6_addr ipv6 = { {{0}} };

  vat_json_object_add_ip4 (&node, "ipv4", ipv4);
  vat_json_object_add_ip6 (&node, "ipv6", ipv6);

  vat_json_print (stdout, &node);
  vat_json_free (&node);
}

int
main (void)
{
  print_json_test ();
  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
