/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

/*
 * json_test.c
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
