/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/vector/test/test.h>

test_registration_t *test_registrations[CLIB_MARCH_TYPE_N_VARIANTS] = {};

int
test_march_supported (clib_march_variant_type_t type)
{
#define _(s, n)                                                               \
  if (CLIB_MARCH_VARIANT_TYPE_##s == type)                                    \
    return clib_cpu_march_priority_##s ();
  foreach_march_variant
#undef _
    return 0;
}

int
main (int argc, char *argv[])
{
  clib_mem_init (0, 64ULL << 20);

  for (int i = 0; i < CLIB_MARCH_TYPE_N_VARIANTS; i++)
    {
      test_registration_t *r = test_registrations[i];

      if (r == 0 || test_march_supported (i) < 0)
	continue;

      fformat (stdout, "\nMultiarch Variant: %U\n", format_march_variant, i);
      fformat (stdout,
	       "-------------------------------------------------------\n");
      while (r)
	{
	  clib_error_t *err;
	  err = (r->fn) (0);
	  fformat (stdout, "%-50s %s\n", r->name, err ? "FAIL" : "PASS");
	  if (err)
	    {
	      clib_error_report (err);
	      fformat (stdout, "\n");
	    }

	  r = r->next;
	}
    }

  fformat (stdout, "\n");
  return 0;
}
