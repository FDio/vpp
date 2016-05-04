/* 
 * scv_util.h -- Service chain validation/Proof Of Transit Utility Header
 *
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
    // struct hlist_node my_hash_list; when this gets added to hashtbale
} scv_profile;

extern scv_profile *pow_profile;
extern u16 pow_profile_index;
extern u64 total_pkts_using_this_profile;
extern u8 chain_path_name[PATH_NAME_SIZE];
extern u16 invalid_profile_start_index;
extern u8 number_of_invalid_profiles;
extern f64 next_time_to_send;
extern u32 time_exponent;

/* 
 * Initialize Service chain
 */
void scv_init(u8 * path_name, u8 max, u8 indx);

/* 
 * Get maximum number of profiles configured for this chain.
 */
u8 scv_get_max_profiles(void);

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

extern void clear_ioam_scv_profiles();

static inline u8 scv_get_profile_in_use(void)
{
    return pow_profile_index;
}

static inline
    void scv_notification_reset(u16 start_index_recvd, u8 num_profiles_recvd)
{
    /* Profiles recevied w/o notn. Nothing to do. */
    if (number_of_invalid_profiles == 0)
        return;

    /* Most likely case. Got all requested profiles */
    if (PREDICT_TRUE(num_profiles_recvd == number_of_invalid_profiles &&
            start_index_recvd == invalid_profile_start_index))
    {
        number_of_invalid_profiles = 0;
        invalid_profile_start_index = 0;
        return;
    }

    /* Received partial list */
    if (num_profiles_recvd < number_of_invalid_profiles)
    {
        ASSERT(start_index_recvd == invalid_profile_start_index);
        invalid_profile_start_index = (start_index_recvd + num_profiles_recvd)
            % scv_get_max_profiles();
        number_of_invalid_profiles -= num_profiles_recvd;
    }

    return;
}

int __attribute__ ((weak)) scv_profile_renew(u8 * path_name,
    u8 start_index, u8 num_profiles);
int __attribute__ ((weak)) scv_profile_refresh(u8 * path_name,
    u8 start_index, u8 num_profiles);

static inline u8 scv_is_decap(scv_profile * p)
{
    return (p->validator == 1);
}

static inline u16 scv_get_next_profile_id(vlib_main_t * vm, u16 id)
{
    int next_id, num_profiles = 0;
    scv_profile *p;
    u8 max;

    max = scv_get_max_profiles();

    next_id = id;

    /* Check for new profile in the ring buffer until a valid one. Exclude
       checking for the one already in use. */
    for (num_profiles = 0; num_profiles < max - 1; num_profiles++)
    {
        next_id = (next_id + 1) % max;
        p = scv_profile_find(next_id);
        if (p->validity != 0)
        {
            vlib_cli_output(vm, "Current id: %d, New id: %d\n", id, next_id);
            return (next_id);
        }
    }

    return (id);
}

static inline void
scv_profile_invalidate(vlib_main_t * vm, ip6_hop_by_hop_main_t * hm,
    u16 id, u8 is_encap)
{
    scv_profile *p = scv_profile_find(id);
    int rc;
    u8 max;
    f64 now = 0;

    p->validity = 0;

    /* If there are alredy profiles waiting. If so, use existing start_index. 
     */
    if (!number_of_invalid_profiles)
        invalid_profile_start_index = id;

    max = scv_get_max_profiles();

    /* Check whether the id is already included in existing list */
    if (!(id >= invalid_profile_start_index &&
            id <= (invalid_profile_start_index +
                number_of_invalid_profiles - 1) % max))
    {
        number_of_invalid_profiles++;
    }

    if (number_of_invalid_profiles > scv_get_max_profiles())
        number_of_invalid_profiles = scv_get_max_profiles();

    now = (f64) (((f64) hm->unix_time_0) +
        (vlib_time_now(hm->vlib_main) - hm->vlib_time_0));
    if (now <= next_time_to_send)
        return;

    if (is_encap)
    {
        rc = scv_profile_renew(chain_path_name,
            (u8) invalid_profile_start_index, number_of_invalid_profiles);
        if (rc != 0)
            vlib_cli_output(vm,
                "Renew notification- id start:%d,  num %d failed. rc: %d\n",
                invalid_profile_start_index, number_of_invalid_profiles, rc);
        else
            vlib_cli_output(vm,
                "Renew notification- id start:%d num %d sent. \n",
                invalid_profile_start_index, number_of_invalid_profiles);

    }
    else
    {
        /* Non encap node. Send refresh notification for now. Later set a
           timer and if there is no profile even after the timeout send
           refresh notification. */
        rc = scv_profile_refresh(chain_path_name,
            (u8) invalid_profile_start_index, number_of_invalid_profiles);
        if (rc != 0)
            vlib_cli_output(vm,
                "Refresh notification- id start:%d,  num %d failed. rc: %d\n",
                invalid_profile_start_index, number_of_invalid_profiles, rc);
        else
            vlib_cli_output(vm,
                "Refresh notification- id start:%d num %d sent. \n",
                invalid_profile_start_index, number_of_invalid_profiles);
    }
    next_time_to_send = now + time_exponent;
    time_exponent <<= 1;        /* backoff time is power of 2 seconds */

    return;
}

#endif
