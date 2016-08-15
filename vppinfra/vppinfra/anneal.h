/*
  Copyright (c) 2011 Cisco and/or its affiliates.

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

#ifndef __included_anneal_h__
#define __included_anneal_h__

#include <vppinfra/clib.h>
#include <vppinfra/format.h>
#include <vppinfra/random.h>
#include <math.h>

typedef struct
{
  /* Initial temperature */
  f64 initial_temperature;

  /* Temperature fraction at each step, 0.95 is reasonable */
  f64 temperature_step;

  /* Number of temperatures used */
  u32 number_of_temperatures;

  /* Number of configurations tried at each temperature */
  u32 number_of_configurations_per_temperature;

  u32 flags;
#define CLIB_ANNEAL_VERBOSE (1<<0)
#define CLIB_ANNEAL_MINIMIZE (1<<1)	/* mutually exclusive */
#define CLIB_ANNEAL_MAXIMIZE (1<<2)	/* mutually exclusive */

  /* Random number seed, set to ensure repeatable results */
  u32 random_seed;

  /* Opaque data passed to callbacks */
  void *opaque;

  /* Final temperature (output) */
  f64 final_temperature;

  /* Final metric (output) */
  f64 final_metric;

  /* Suggested initial temperature (output) */
  f64 suggested_initial_temperature;


  /*--- Callbacks ---*/

  /* objective function to minimize */
    f64 (*anneal_metric) (void *opaque);

  /* Generate a new configuration */
  void (*anneal_new_configuration) (void *opaque);

  /* Restore the previous configuration */
  void (*anneal_restore_previous_configuration) (void *opaque);

  /* Save best configuration found e.g at a certain temperature */
  void (*anneal_save_best_configuration) (void *opaque);

  /* restore best configuration found e.g at a certain temperature */
  void (*anneal_restore_best_configuration) (void *opaque);

} clib_anneal_param_t;

void clib_anneal (clib_anneal_param_t * p);

#endif /* __included_anneal_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
