/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2005 Eliot Dresselhaus
 */

#include <vppinfra/format.h>
#include <vppinfra/time.h>
#include <vppinfra/math.h>	/* for sqrt */

static int verbose;
#define if_verbose(format,args...) \
  if (verbose) { clib_warning(format, ## args); }

static int
test_time_main (unformat_input_t * input)
{
  f64 wait, error;
  f64 t, tu[3], ave, rms;
  clib_time_t c;
  int i, n, j;

  clib_time_init (&c);
  wait = 1e-3;
  n = 1000;
  unformat (input, "%f %d", &wait, &n);
  ave = rms = 0;
  tu[0] = unix_time_now ();
  tu[1] = unix_time_now ();
  for (i = 0; i < n; i++)
    {
      j = 0;
      t = clib_time_now (&c);
      while (clib_time_now (&c) < t + wait)
	j++;
      t = j;
      ave += t;
      rms += t * t;
    }
  tu[2] = unix_time_now ();
  ave /= n;
  rms = sqrt (rms / n - ave * ave);

  error = ((tu[2] - tu[1]) - 2 * (tu[1] - tu[0]) - n * wait) / n;
  if_verbose ("tested %d x %.6e sec waits, error %.6e loops %.6e +- %.6e\n",
	      n, wait, error, ave, rms);

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  unformat_input_t i;
  int ret;

  clib_mem_init (0, 64ULL << 20);

  verbose = (argc > 1);
  unformat_init_command_line (&i, argv);
  ret = test_time_main (&i);
  unformat_free (&i);

  return ret;
}
#endif /* CLIB_UNIX */
