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

#include <vppinfra/anneal.h>

/*
 * Optimize an objective function by simulated annealing
 *
 * Here are a couple of short, easily-understood
 * descriptions of simulated annealing:
 *
 * http://www.cs.sandia.gov/opt/survey/sa.html
 * Numerical Recipes in C, 2nd ed., 444ff
 *
 * The description in the Wikipedia is not helpful.
 *
 * The algorithm tries to produce a decent answer to combinatorially
 * explosive optimization problems by analogy to slow cooling
 * of hot metal, aka annealing.
 *
 * There are (at least) three problem-dependent annealing parameters
 * to consider:
 *
 * t0, the initial "temperature. Should be set so that the probability
 * of accepting a transition to a higher cost configuration is
 * initially about 0.8.
 *
 * ntemps, the number of temperatures to use. Each successive temperature
 * is some fraction of the previous temperature.
 *
 * nmoves_per_temp, the number of configurations to try at each temperature
 *
 * It is a black art to set ntemps, nmoves_per_temp, and the rate
 * at which the temperature drops. Go too fast with too few iterations,
 * and the computation falls into a local minimum instead of the
 * (desired) global minimum.
 */

void
clib_anneal (clib_anneal_param_t * p)
{
  f64 t;
  f64 cost, prev_cost, delta_cost, initial_cost, best_cost;
  f64 random_accept, delta_cost_over_t;
  f64 total_increase = 0.0, average_increase;
  u32 i, j;
  u32 number_of_increases = 0;
  u32 accepted_this_temperature;
  u32 best_saves_this_temperature;
  int accept;

  t = p->initial_temperature;
  best_cost = initial_cost = prev_cost = p->anneal_metric (p->opaque);
  p->anneal_save_best_configuration (p->opaque);

  if (p->flags & CLIB_ANNEAL_VERBOSE)
    fformat (stdout, "Initial cost %.2f\n", initial_cost);

  for (i = 0; i < p->number_of_temperatures; i++)
    {
      accepted_this_temperature = 0;
      best_saves_this_temperature = 0;

      p->anneal_restore_best_configuration (p->opaque);
      cost = best_cost;

      for (j = 0; j < p->number_of_configurations_per_temperature; j++)
	{
	  p->anneal_new_configuration (p->opaque);
	  cost = p->anneal_metric (p->opaque);

	  delta_cost = cost - prev_cost;

	  /* cost function looks better, accept this move */
	  if (p->flags & CLIB_ANNEAL_MINIMIZE)
	    accept = delta_cost < 0.0;
	  else
	    accept = delta_cost > 0.0;

	  if (accept)
	    {
	      if (p->flags & CLIB_ANNEAL_MINIMIZE)
		if (cost < best_cost)
		  {
		    if (p->flags & CLIB_ANNEAL_VERBOSE)
		      fformat (stdout, "New best cost %.2f\n", cost);
		    best_cost = cost;
		    p->anneal_save_best_configuration (p->opaque);
		    best_saves_this_temperature++;
		  }

	      accepted_this_temperature++;
	      prev_cost = cost;
	      continue;
	    }

	  /* cost function worse, keep stats to suggest t0 */
	  total_increase += (p->flags & CLIB_ANNEAL_MINIMIZE) ?
	    delta_cost : -delta_cost;

	  number_of_increases++;

	  /*
	   * Accept a higher cost with Pr { e^(-(delta_cost / T)) },
	   * equivalent to rnd[0,1] < e^(-(delta_cost / T))
	   *
	   * AKA, the Boltzmann factor.
	   */
	  random_accept = random_f64 (&p->random_seed);

	  delta_cost_over_t = delta_cost / t;

	  if (random_accept < exp (-delta_cost_over_t))
	    {
	      accepted_this_temperature++;
	      prev_cost = cost;
	      continue;
	    }
	  p->anneal_restore_previous_configuration (p->opaque);
	}

      if (p->flags & CLIB_ANNEAL_VERBOSE)
	{
	  fformat (stdout, "Temp %.2f, cost %.2f, accepted %d, bests %d\n", t,
		   prev_cost, accepted_this_temperature,
		   best_saves_this_temperature);
	  fformat (stdout, "Improvement %.2f\n", initial_cost - prev_cost);
	  fformat (stdout, "-------------\n");
	}

      t = t * p->temperature_step;
    }

  /*
   * Empirically, one wants the probability of accepting a move
   * at the initial temperature to be about 0.8.
   */
  average_increase = total_increase / (f64) number_of_increases;
  p->suggested_initial_temperature = average_increase / 0.22;	/* 0.22 = -ln (0.8) */

  p->final_temperature = t;
  p->final_metric = p->anneal_metric (p->opaque);

  if (p->flags & CLIB_ANNEAL_VERBOSE)
    {
      fformat (stdout, "Average cost increase from a bad move: %.2f\n",
	       average_increase);
      fformat (stdout, "Suggested t0 = %.2f\n",
	       p->suggested_initial_temperature);
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
