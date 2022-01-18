/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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
/*
 * PCG Random Number Generation for C.
 *
 * Copyright 2014-2019 Melissa O'Neill <oneill@pcg-random.org>,
 *                     and the PCG Project contributors.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 *
 * Licensed under the Apache License, Version 2.0 (provided in
 * LICENSE-APACHE.txt and at http://www.apache.org/licenses/LICENSE-2.0)
 * or under the MIT license (provided in LICENSE-MIT.txt and at
 * http://opensource.org/licenses/MIT), at your option. This file may not
 * be copied, modified, or distributed except according to those terms.
 *
 * Distributed on an "AS IS" BASIS, WITHOUT WARRANTY OF ANY KIND, either
 * express or implied.  See your chosen license for details.
 *
 * For additional information about the PCG random number generation scheme,
 * visit http://www.pcg-random.org/.
 */

/* This implements the pcg64i_random_t PCG specialized generator:
 * https://www.pcg-random.org/using-pcg-c.html#specialized-generators
 * This generator produces each 64-bits output exactly once, which is
 * perfectly suited to generated non-repeating IVs. However, because of this
 * property the entire internal state is revealed with each output.
 * It has a 2^64 period and supports 2^63 non-overlaping streams */

#define CLIB_PCG_DEFAULT_MULTIPLIER_64 6364136223846793005ULL
#define clib_pcg64i_random_r	       clib_pcg_setseq_64_rxs_m_xs_64_random_r
#define clib_pcg64i_srandom_r	       clib_pcg_setseq_64_srandom_r

typedef struct
{
  u64 state;
  u64 inc;
} clib_pcg_state_setseq_64_t;

typedef clib_pcg_state_setseq_64_t clib_pcg64i_random_t;

static_always_inline void
clib_pcg_setseq_64_step_r (clib_pcg_state_setseq_64_t *rng)
{
  rng->state = rng->state * CLIB_PCG_DEFAULT_MULTIPLIER_64 + rng->inc;
}

static_always_inline u64
clib_pcg_output_rxs_m_xs_64_64 (u64 state)
{
  u64 word =
    ((state >> ((state >> 59u) + 5u)) ^ state) * 12605985483714917081ull;
  return (word >> 43u) ^ word;
}

static_always_inline u64
clib_pcg_setseq_64_rxs_m_xs_64_random_r (clib_pcg_state_setseq_64_t *rng)
{
  u64 oldstate = rng->state;
  clib_pcg_setseq_64_step_r (rng);
  return clib_pcg_output_rxs_m_xs_64_64 (oldstate);
}

static_always_inline void
clib_pcg_setseq_64_srandom_r (clib_pcg_state_setseq_64_t *rng, u64 initstate,
			      u64 initseq)
{
  rng->state = 0U;
  rng->inc = (initseq << 1u) | 1u;
  clib_pcg_setseq_64_step_r (rng);
  rng->state += initstate;
  clib_pcg_setseq_64_step_r (rng);
}
