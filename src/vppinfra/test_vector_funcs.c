/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2021 Cisco Systems, Inc.
 */

#include <vppinfra/format.h>
#include <vppinfra/test_vector_funcs.h>

test_registration_t *test_registrations[CLIB_MARCH_TYPE_N_VARIANTS] = {};

int
main (int argc, char *argv[])
{
  clib_mem_init (0, 64ULL << 20);

  for (int i = 0; i < CLIB_MARCH_TYPE_N_VARIANTS; i++)
    {
      test_registration_t *r = test_registrations[i];

      if (r == 0)
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
