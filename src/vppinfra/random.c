/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2001, 2002, 2003 Eliot Dresselhaus
 */

#include <vppinfra/random.h>

/** \file random.c
    Random number support
 */

/** \brief Default random seed for standalone version of library.
   Value can be overridden by platform code from e.g.
   machine's clock count register. */
u32 standalone_random_default_seed = 1;

/**
 * \brief Compute the X2 test statistic for a vector of counts.
 * Each value element corresponds to a histogram bucket.
 *
 * Typical use-case: test the hypothesis that a set of octets
 * are uniformly distributed (aka random).
 *
 * In a 1-dimensional use-case, the result should be compared
 * with the critical value from chi square tables with
 * vec_len(values) - 1 degrees of freedom.
 *
 * @param[in] values vector of histogram bucket values
 * @return    d - Pearson's X2 test statistic
 */

__clib_export f64
clib_chisquare (u64 *values)
{
  u32 i, len;
  f64 d, delta_d, actual_frequency, expected_frequency;
  u64 n_observations = 0;

  len = vec_len (values);
  /*
   * Shut up coverity. Return a huge number which should always exceed
   * the X2 critical value.
   */
  if (len == 0)
    return (f64) 1e70;

  for (i = 0; i < len; i++)
    n_observations += values[i];

  expected_frequency = (1.0 / (f64) len) * (f64) n_observations;

  d = 0.0;

  for (i = 0; i < len; i++)
    {
      actual_frequency = ((f64) values[i]);
      delta_d = ((actual_frequency - expected_frequency)
		 * (actual_frequency - expected_frequency))
	/ expected_frequency;
      d += delta_d;
    }
  return d;
}
