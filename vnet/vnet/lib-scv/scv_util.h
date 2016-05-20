/* 
 * scv_util.h -- Service chain validation/Proof Of Transit Utility Header
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

#ifndef include_vnet_scv_util_h
#define include_vnet_scv_util_h

#include <vnet/ip/ip6_hop_by_hop.h>
#define MAXDEGREE 1024
#define MAXTOKENLEN 128
#define debug_ioam debug_ioam_fn
#define MAX_SERVICE_NODES 10
/* Dont change this size 256. This is there across multiple components */
#define PATH_NAME_SIZE  256

/* Ring size. this should be same as the one in ODL. Do not change this
   without change in ODL. */
#define MAX_SERVICE_PROFILES 16

/**
 * Usage:
 * 
 * On any [service] node that participates in Service / Path verfication:
 *
 * Step 1: Initialize this library by calling scv_init()
 * Step 2: Setup a Service chain validation profile that contains all the parameters needed to compute cumulative:
 *         Call these functions:
 *         scv_profile_find
 *         scv_profile_create
 *         scv_profile_set_bit_mask - To setup how large we want the numbers used in the computation and random number <= 64 bits
 * Step 2a: For validator do this:
 *          scv_set_validator
 * Step 3a: At the initial Service node to generate Random number that will be read by all other nodes:
 *          scv_generate_random
 * Step 3b: At all service nodes including initial and verifier call this to compute cumulative:
 *          scv_update_cumulative
 * Step 4: At the verifier:
 *         scv_validate
 * 
 */

typedef struct scv_profile_
{
    u16 id;
    u64 random;
    u8 validator;
    u64 secret_key;
    u64 secret_share;
    u64 prime;
    u64 lpc;
    u64 poly_pre_eval;
    u64 bit_mask;
    u64 limit;
    u64 validity;
    double primeinv;
    u64 total_pkts_using_this_profile;

    // struct hlist_node my_hash_list; when this gets added to hashtbale
} scv_profile;

typedef struct {
    /* Name of the profile list in use*/
    u8 *profile_list_name;
    scv_profile profile_list[MAX_SERVICE_PROFILES];
    /* number of profiles in the list */
    u8 no_of_profiles;
    u8 sc_init_done;
    
    /* The current profile from the list  in use */
    scv_profile *pow_profile;
    /* Index of the profile within the list */
    u16 pow_profile_index;
  
    /* Profile error stats */
    u16 invalid_profile_start_index;
    u8 number_of_invalid_profiles;
  
    /* Profile renewal */
    u64 profile_renew_request_failed;
    u64 profile_renew_request;
    f64 next_time_to_send;
    u32 time_exponent;
    u32 unix_time_0;
    f64 vlib_time_0;

    /* convenience */
    vlib_main_t * vlib_main;
    vnet_main_t * vnet_main;
} scv_main_t;

extern scv_main_t scv_main;

/* 
 * Initialize Service chain
 */
void scv_init(u8 * path_name, u8 max, u8 indx);

/* 
 * Get maximum number of profiles configured for this chain.
 */
u8 scv_get_no_of_profiles(void);

/* 
 * Find a SC profile by ID
 */
scv_profile *scv_profile_find(u16 id);

static inline u16 scv_profile_get_id(scv_profile * profile)
{
    if (profile)
    {
        return (profile->id);
    }
    return (0);
}

/* setup and clean up profile */
void scv_profile_create(scv_profile * profile, u64 prime,
    u64 poly2, u64 lpc, u64 secret_share, u64 validity);
/* 
 * Setup profile as a validator
 */
void scv_set_validator(scv_profile * profile, u64 key);
void scv_profile_cleanup(scv_profile * profile);

/* 
 * Setup max bits to be used for random number generation
 */
#define MAX_BITS 64
void scv_profile_set_bit_mask(scv_profile * profile, u16 bits);

/* 
 * Given a random and cumulative compute the new cumulative for a given profile
 */
u64 scv_update_cumulative(scv_profile * profile, u64 cumulative, u64 random);

/* 
 * return True if the cumulative matches secret from a profile
 */
u8 scv_validate(scv_profile * profile, u64 cumulative, u64 random);

/* 
 * Utility function to get random number per pack
 */
u64 scv_generate_random(scv_profile * profile);

int scv_profile_to_str(scv_profile * profile, char *buf, int n);

extern void clear_scv_profiles();

static inline u8 scv_get_profile_in_use(void)
{
    scv_main_t *sm = &scv_main;
    return (sm->pow_profile_index);
}

static inline
void scv_notification_reset(u16 start_index_recvd, u8 num_profiles_recvd)
{
    scv_main_t *sm = &scv_main;
    /* Profiles recevied w/o notn. Nothing to do. */
    if (sm->number_of_invalid_profiles == 0)
        return;

    /* Most likely case. Got all requested profiles */
    if (PREDICT_TRUE(num_profiles_recvd == sm->number_of_invalid_profiles &&
            start_index_recvd == sm->invalid_profile_start_index))
    {
        sm->number_of_invalid_profiles = 0;
        sm->invalid_profile_start_index = 0;
        return;
    }

    /* Received partial list */
    if (num_profiles_recvd < sm->number_of_invalid_profiles)
    {
        ASSERT(start_index_recvd == sm->invalid_profile_start_index);
        sm->invalid_profile_start_index = (start_index_recvd + num_profiles_recvd)
            % scv_get_no_of_profiles();
        sm->number_of_invalid_profiles -= num_profiles_recvd;
    }

    return;
}

int __attribute__ ((weak)) scv_profile_renew(u8 * path_name,
					     u8 start_index, u8 num_profiles,
					     u8 broadcast);

static inline u8 scv_is_decap(scv_profile * p)
{
    return (p->validator == 1);
}

static inline u16 scv_get_next_profile_id (u16 id)
{
    int next_id,num_profiles = 0;
    scv_profile *p;
    u8 max;

    max = scv_get_no_of_profiles();

    next_id = id;

    /* Check for new profile in the ring buffer until a valid one. Exclude
       checking for the one already in use. */
    for (num_profiles = 0; num_profiles < max - 1; num_profiles++)
    {
        next_id = (next_id + 1) % max;
        p = scv_profile_find(next_id);
        if (p->validity != 0)
        {
	  return (next_id);
        }
    }

    return (id);
}

static inline void scv_profile_set_current (u16 index)
{
    scv_main_t *sm = &scv_main;
    scv_profile *profile = NULL;
    profile = scv_profile_find(index);
    if (profile) {
        sm->pow_profile_index = index;
        sm->pow_profile = profile;
    }
}
static inline u16 scv_profile_get_current_index (void)
{
    scv_main_t *sm = &scv_main;
    return (sm->pow_profile_index);
}

static inline scv_profile * scv_profile_get_current (void)
{
    scv_main_t *sm = &scv_main;
    return (sm->pow_profile);
}

static inline u8 scv_profile_is_valid (scv_profile *profile)
{
    if (profile->total_pkts_using_this_profile >= profile->validity)
    {
      return(0);
    }
    return(1);
}
static inline void scv_profile_reset_usage_stats (scv_profile *pow)
{
  if (pow) {
    pow->total_pkts_using_this_profile = 0;
  }
}

static inline void scv_profile_incr_usage_stats (scv_profile *pow)
{
  if (pow) {
    pow->total_pkts_using_this_profile++;
  }
}

static inline void
scv_profile_invalidate(u16 id, u8 is_encap)
{
    scv_main_t *sm = &scv_main;
    scv_profile *p = scv_profile_find(id);
    int rc;
    u8 max;
    f64 now = 0;

    p->validity = 0;

    /* If there are alredy profiles waiting. If so, use existing start_index. 
     */
    if (!sm->number_of_invalid_profiles)
        sm->invalid_profile_start_index = id;

    max = scv_get_no_of_profiles();

    /* Check whether the id is already included in existing list */
    if (!(id >= sm->invalid_profile_start_index &&
            id <= (sm->invalid_profile_start_index +
                sm->number_of_invalid_profiles - 1) % max))
    {
        sm->number_of_invalid_profiles++;
    }

    if (sm->number_of_invalid_profiles > scv_get_no_of_profiles())
        sm->number_of_invalid_profiles = scv_get_no_of_profiles();

    now = (f64) (((f64) sm->unix_time_0) +
        (vlib_time_now(sm->vlib_main) - sm->vlib_time_0));
    if (now <= sm->next_time_to_send)
        return;

    if (is_encap)
    {
        rc = scv_profile_renew(sm->profile_list_name,
			       (u8) sm->invalid_profile_start_index,
			       sm->number_of_invalid_profiles,
			       1);
	if (rc != 0)
	  sm->profile_renew_request_failed++;
	else
	  sm->profile_renew_request++;
    }
    else
    {
        /* Non encap node. Send refresh notification for now. Later set a
           timer and if there is no profile even after the timeout send
           refresh notification. */
        rc = scv_profile_renew(sm->profile_list_name,
				 (u8) sm->invalid_profile_start_index,
			         sm->number_of_invalid_profiles,
				 0);
	if (rc != 0)
	  sm->profile_renew_request_failed++;
	else
	  sm->profile_renew_request++;
    }
    sm->next_time_to_send = now + sm->time_exponent;
    sm->time_exponent <<= 1;        /* backoff time is power of 2 seconds */

    return;
}

#endif
