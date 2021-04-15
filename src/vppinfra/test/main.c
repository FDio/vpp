/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/test/test.h>

test_registration_t *test_registrations = 0;

int
main (int argc, char *argv[])
{
  test_registration_t *r = test_registrations;
  clib_mem_init (0, 64ULL << 20);

  while (r)
    {
      clib_error_t *err;
      fformat (stdout, "\ntest %s (%U)", r->name, format_march_variant,
	       r->march_variant);
      err = (r->fn) (0);
      if (err)
	clib_error_report (err);

      r = r->next;
    }

  return 0;
}
