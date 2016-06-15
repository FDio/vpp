/* 
 * pot_util.h -- Proof Of Transit Utility Header
 *
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef include_vnet_pot_util_h
#define include_vnet_pot_util_h

#include <vnet/ip/ip6_hop_by_hop.h>
#define debug_ioam debug_ioam_fn
/* Dont change this size 256. This is there across multiple components */
#define PATH_NAME_SIZE  256

/* Ring size. this should be same as the one in ODL. Do not change this
   without change in ODL. */
#define MAX_POT_PROFILES 2

/**
 * Usage:
 * 
 * On any node that participates in Proof of Transit:
 *
 * Step 1: Initialize this library by calling pot_init()
 * Step 2: Setup a proof of transit  profile that contains all the parameters needed to compute cumulative:
 *         Call these functions:
 *         pot_profile_find
 *         pot_profile_create
 *         pot_profile_set_bit_mask - To setup how large we want the numbers used in the computation and random number <= 64 bits
 * Step 2a: For validator do this:
 *          pot_set_validator
 * Step 2b: On initial node enable the profile to be used:
 *          pot_profile_set_active / pot_profile_get_active will return the profile
 * Step 3a: At the initial node to generate Random number that will be read by all other nodes:
 *          pot_generate_random
 * Step 3b: At all nodes including initial and verifier call this to compute cumulative:
 *          pot_update_cumulative
 * Step 4: At the verifier:
 *         pot_validate
 * 
 */

typedef struct pot_profile_
{
    u8 id : 1;
    u8 valid : 1;
    u8 in_use : 1;
    u64 random;
    u8 validator;
    u64 secret_key;
    u64 secret_share;
    u64 prime;
    u64 lpc;
    u64 poly_pre_eval;
    u64 bit_mask;
    u64 limit;
    double primeinv;
    u64 total_pkts_using_this_profile;
} pot_profile;

typedef struct {
    /* Name of the default profile list in use*/
    u8 *profile_list_name;
    pot_profile profile_list[MAX_POT_PROFILES];
    /* number of profiles in the list */
    u8 active_profile_id : 1;

    /* API message ID base */
    u16 msg_id_base;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
} pot_main_t;

extern pot_main_t pot_main;

/* 
 * Initialize proof of transit
 */
int pot_util_init(void);
void pot_profile_list_init(u8 * name);


/* 
 * Find a pot profile by ID
 */
pot_profile *pot_profile_find(u8 id);

static inline u16 pot_profile_get_id(pot_profile * profile)
{
    if (profile)
    {
        return (profile->id);
    }
    return (0);
}

/* setup and clean up profile */
int pot_profile_create(pot_profile * profile, u64 prime,
    u64 poly2, u64 lpc, u64 secret_share);
/* 
 * Setup profile as a validator
 */
int pot_set_validator(pot_profile * profile, u64 key);

/* 
 * Setup max bits to be used for random number generation
 */
#define MAX_BITS 64
int pot_profile_set_bit_mask(pot_profile * profile, u16 bits);

/* 
 * Given a random and cumulative compute the new cumulative for a given profile
 */
u64 pot_update_cumulative(pot_profile * profile, u64 cumulative, u64 random);

/* 
 * return True if the cumulative matches secret from a profile
 */
u8 pot_validate(pot_profile * profile, u64 cumulative, u64 random);

/* 
 * Utility function to get random number per pack
 */
u64 pot_generate_random(pot_profile * profile);


extern void clear_pot_profiles();
extern int pot_profile_list_is_enabled(u8 *name);

static inline u8 pot_is_decap(pot_profile * p)
{
    return (p->validator == 1);
}

static inline int pot_profile_set_active (u8 id)
{
    pot_main_t *sm = &pot_main;
    pot_profile *profile = NULL;
    pot_profile *current_active_prof = NULL;

    current_active_prof = pot_profile_find(sm->active_profile_id);
    profile = pot_profile_find(id);
    if (profile && profile->valid) {
        sm->active_profile_id = id;
	current_active_prof->in_use = 0;
	profile->in_use = 1;
	return(0);
    }
    return(-1);
}
static inline u8 pot_profile_get_active_id (void)
{
    pot_main_t *sm = &pot_main;
    return (sm->active_profile_id);
}

static inline pot_profile * pot_profile_get_active (void)
{
    pot_main_t *sm = &pot_main;
    pot_profile *profile = NULL;
    profile = pot_profile_find(sm->active_profile_id);
    if (profile && profile->in_use)
        return(profile);
    return (NULL);
}

static inline void pot_profile_reset_usage_stats (pot_profile *pow)
{
  if (pow) {
    pow->total_pkts_using_this_profile = 0;
  }
}

static inline void pot_profile_incr_usage_stats (pot_profile *pow)
{
  if (pow) {
    pow->total_pkts_using_this_profile++;
  }
}


#endif
