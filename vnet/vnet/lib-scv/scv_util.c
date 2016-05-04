/* 
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
#include <vnet/vnet.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <vppinfra/mem.h>
#include "math64.h"
#include "scv_util.h"

scv_profile *pow_profile = NULL;
u16 pow_profile_index = 0;
u64 total_pkts_using_this_profile = 0;
u8 chain_path_name[PATH_NAME_SIZE];
scv_profile profile_list[MAX_SERVICE_PROFILES];
u8 max_profiles = 0;
u16 invalid_profile_start_index = 0;
u8 number_of_invalid_profiles = 0;
f64 next_time_to_send = 0;
u32 time_exponent = 1;
vlib_main_t *gvm = 0;

static void scv_profile_init(scv_profile * new, u16 id)
{
    if (new)
    {
        memset(new, 0, sizeof(scv_profile));
        new->id = id;
    }
}

/* 
 * Get maximum number of profiles configured for this chain.
 */
u8 scv_get_max_profiles(void)
{
    return max_profiles;
}

scv_profile *scv_profile_find(u16 id)
{
    u8 max = scv_get_max_profiles();

    if (id >= 0 && id < max)
    {
        return (&profile_list[id]);
    }
    return (NULL);
}

u8 sc_init_done = 0;
void scv_init(u8 * path_name, u8 max, u8 indx)
{
    int i = 0;

    if (sc_init_done)
    {
        return;
    }
    memcpy(chain_path_name, path_name, strlen((const char *)path_name) + 1);
    max_profiles = max;
    pow_profile_index = indx;

    for (i = 0; i < max_profiles; i++)
    {
        scv_profile_init(&profile_list[i], i);
    }

    sc_init_done = 1;
}

void scv_profile_cleanup(scv_profile * profile)
{
    u16 id = profile->id;

    memset(profile, 0, sizeof(scv_profile));
    profile->id = id;           /* Restore id alone */
}

void scv_profile_create(scv_profile * profile, u64 prime,
    u64 poly2, u64 lpc, u64 secret_share, u64 validity)
{
    if (profile)
    {
        scv_profile_cleanup(profile);
        profile->prime = prime;
        profile->primeinv = 1.0 / prime;
        profile->lpc = lpc;
        profile->poly_pre_eval = poly2;
        profile->secret_share = secret_share;
        profile->validity = validity;
        time_exponent = 1;      /* Got a new profile. Reset backoff */
        next_time_to_send = 0;  /* and send next request with no delay */
    }
}

void scv_set_validator(scv_profile * profile, u64 key)
{
    if (profile)
    {
        profile->validator = 1;
        profile->secret_key = key;
    }
}

static inline u64 sc_update_cumulative(u64 cumulative, u64 random,
    u64 secret_share, u64 prime, u64 lpc, u64 pre_split, double prime_inv)
{
    u64 share_random = 0;
    u64 cumulative_new = 0;

    /* 
     * calculate split share for random
     */
    share_random = add64_mod(pre_split, random, prime, prime_inv);

    /* 
     * lpc * (share_secret + share_random)
     */
    share_random = add64_mod(share_random, secret_share, prime, prime_inv);
    share_random = mul64_mod(share_random, lpc, prime, prime_inv);

    cumulative_new = add64_mod(cumulative, share_random, prime, prime_inv);

    return (cumulative_new);
}

u64 scv_update_cumulative(scv_profile * profile, u64 cumulative, u64 random)
{
    if (profile && profile->validity != 0)
    {
        return (sc_update_cumulative(cumulative, random, profile->secret_share,
                profile->prime, profile->lpc, profile->poly_pre_eval,
                profile->primeinv));
    }
    return (0);
}

static u8 sc_validate(u64 secret, u64 prime, double prime_inv,
    u64 cumulative, u64 random)
{
    if (cumulative == (random + secret))
    {
        return (1);
    }
    else if (cumulative == add64_mod(random, secret, prime, prime_inv))
    {
        return (1);
    }
    return (0);
}

/* 
 * return True if the cumulative matches secret from a profile
 */
u8 scv_validate(scv_profile * profile, u64 cumulative, u64 random)
{
    if (profile && profile->validator)
    {
        return (sc_validate(profile->secret_key, profile->prime,
                profile->primeinv, cumulative, random));
    }
    return (0);
}

/* 
 * Utility function to get random number per pack
 */
u64 scv_generate_random(scv_profile * profile)
{
    u64 random = 0;
    int32_t second_half;
    static u32 seed = 0;

    if (PREDICT_FALSE(!seed))
        seed = random_default_seed();

    /* 
     * Upper 4 bytes seconds
     */
    random = (u64) time(NULL);

    random &= 0xffffffff;
    random = random << 32;
    /* 
     * Lower 4 bytes random number
     */
    second_half = random_u32(&seed);

    random |= second_half;

    if (PREDICT_TRUE(profile != NULL))
    {
        random &= profile->bit_mask;
    }
    return (random);
}

void scv_profile_set_bit_mask(scv_profile * profile, u16 bits)
{
    int sizeInBits;

    if (profile)
    {
        sizeInBits = sizeof(profile->bit_mask) * 8;
        profile->bit_mask =
            (bits >=
            sizeInBits ? (u64) - 1 : (u64) ((u64) 1 << (u64) bits) - 1);
    }
}

/* 
 * TODO: Use vector buffers and hash tables
 */
#define MAX_SERVICES 16

clib_error_t *clear_scv_profile_command_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
    int i = 0;

    if (!sc_init_done)
        return 0;

    for (i = 0; i < max_profiles; i++)
    {
        scv_profile_cleanup(&profile_list[i]);
    }
    pow_profile = NULL;
    pow_profile_index = 0;
    total_pkts_using_this_profile = 0;
    memset(chain_path_name, 0, PATH_NAME_SIZE);
    max_profiles = 0;
    invalid_profile_start_index = 0;
    number_of_invalid_profiles = 0;
    next_time_to_send = 0;
    time_exponent = 1;
    sc_init_done = 0;

    return 0;
}

void clear_scv_profiles()
{
    clear_scv_profile_command_fn(0, 0, 0);
}

VLIB_CLI_COMMAND(clear_scv_profile_command) =
{
.path = "clear scv profile",
.short_help = "clear scv profile [<index>|all]",
.function = clear_scv_profile_command_fn,
};

static clib_error_t *set_scv_profile_command_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
    u64 prime;
    u64 secret_share, validity;
    u64 secret_key;
    u8 validator = 0;
    u16 profile_id;
    u32 bits;
    u64 lpc = 0, poly2 = 0;
    scv_profile *profile = NULL;

    bits = MAX_BITS;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "id %d", &profile_id))
            ;
        else if (unformat(input, "validate-key 0x%Lx", &secret_key))
            validator = 1;
        else if (unformat(input, "prime-number 0x%Lx", &prime))
            ;
        else if (unformat(input, "secret_share 0x%Lx", &secret_share))
            ;
        else if (unformat(input, "polynomial2 0x%Lx", &poly2))
            ;
        else if (unformat(input, "lpc 0x%Lx", &lpc))
            ;
        else if (unformat(input, "validity 0x%Lx", &validity))
            ;
        else if (unformat(input, "bits-in-random %d", &bits))
        {
            if (bits > MAX_BITS)
                bits = MAX_BITS;
        }
        else
            return clib_error_return(0, "unknown input `%U'",
                format_unformat_error, input);
    }

    scv_init((u8 *) "TEST", MAX_SERVICE_PROFILES, 0 /* start index */ );
    profile = scv_profile_find(profile_id);

    if (profile)
    {
        scv_profile_create(profile, prime, poly2, lpc, secret_share, validity);
        if (validator)
            scv_set_validator(profile, secret_key);
        scv_profile_set_bit_mask(profile, bits);
    }

    return 0;
}

VLIB_CLI_COMMAND(set_scv_profile_command) =
{
.path = "set scv profile",
.short_help = "set scv profile id [0-16] [validator-key 0xu64] \
                  prime-number 0xu64 secret_share 0xu64 lpc 0xu64 \
                  polynomial2 0xu64 bits-in-random [0-64] ",
.function = set_scv_profile_command_fn,
};

static clib_error_t *show_scv_profile_command_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
    scv_profile *p = NULL;
    u16 i;
    u8 *s = 0;

    if (sc_init_done == 0)
    {
        s = format(s, "SCV Profiles not configured\n");
        vlib_cli_output(vm, "%v", s);
        return 0;
    }

    for (i = 0; i < max_profiles; i++)
    {
        p = scv_profile_find(i);
        if (p->validity == 0)
            continue;
        s = format(s, "SCV Profile at index: %d\n", i);
        s = format(s, "                 Id : %d\n", p->id);
        s = format(s, "          Validator : %s (%d)\n",
            (p->validator) ? "True" : "False", p->validator);
        if (p->validator == 1)
            s = format(s, "         Secret key : 0x%Lx (%Ld)\n",
                p->secret_key, p->secret_key);
        s = format(s, "       Secret share : 0x%Lx (%Ld)\n",
            p->secret_share, p->secret_share);
        s = format(s, "       Prime number : 0x%Lx (%Ld)\n",
            p->prime, p->prime);
        s = format(s, "2nd polynomial(eval) : 0x%Lx (%Ld)\n",
            p->poly_pre_eval, p->poly_pre_eval);
        s = format(s, "                 LPC : 0x%Lx (%Ld)\n", p->lpc, p->lpc);

        s = format(s, "           Bit mask : 0x%Lx (%Ld)\n",
            p->bit_mask, p->bit_mask);
        s = format(s, "           Validity : 0x%Lx (%Ld)\n",
            p->validity, p->validity);
    }

    if (max_profiles)
    {
        p = scv_profile_find(pow_profile_index);

        s = format(s, "\nInvalid profiles start : %d Number : %d\n",
            invalid_profile_start_index, number_of_invalid_profiles);

        if (next_time_to_send)
            s = format(s, "\nNext time to send : %U, time_exponent:%ld\n",
                format_time_interval, "d:h:m:s:f:u",
                next_time_to_send, time_exponent);
        else
            s = format(s, "\nNext time to send : Immediate\n");
        s = format(s, "\nPath name : %s\n", chain_path_name);
        s = format(s, "\nProfile index in use: %d\n", pow_profile_index);
        s = format(s, "Pkts passed : 0x%Lx (validity:0x%Lx)\n",
            total_pkts_using_this_profile, p->validity);
        if (scv_is_decap(p))
            s = format(s, "  This is Decap node.  \n");
        vlib_cli_output(vm, "%v", s);
    }
    vec_free(s);

    return 0;
}

VLIB_CLI_COMMAND(show_scv_profile_command) =
{
.path = "show scv profile",
.short_help = "show scv profile",
.function = show_scv_profile_command_fn,
};

static clib_error_t *test_profile_renew_refresh_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
    u8 renew_or_refresh = 0;

#define TEST_PROFILE_RENEW 1
#define TEST_PROFILE_REFRESH 2
    u8 *path_name = 0;
    u32 start_index = 0, num_profiles = 0;
    int rc = 0;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "path-name %s start-index %d num-profiles %d",
                &path_name, &start_index, &num_profiles))
            ;
        else if (unformat(input, "renew"))
            renew_or_refresh = TEST_PROFILE_RENEW;
        else if (unformat(input, "refresh"))
            renew_or_refresh = TEST_PROFILE_REFRESH;
        else
            break;
    }

    if (renew_or_refresh == TEST_PROFILE_RENEW)
    {
	
        rc = scv_profile_renew(path_name, (u8) start_index, (u8) num_profiles);
    }
    else if (renew_or_refresh == TEST_PROFILE_REFRESH)
    {
	
        rc = scv_profile_refresh(path_name, (u8) start_index,
            (u8) num_profiles);
    }
    else
    {
        vec_free(path_name);
        return clib_error_return(0, "Enter renew or refresh");
    }

    vlib_cli_output(vm, "%s notification %s. rc = %d\n",
        (renew_or_refresh == TEST_PROFILE_RENEW) ? "Renew" : "Refresh",
        (rc != 0) ? "failed" : "sent", (u32) rc);

    vec_free(path_name);

    return 0;
}

VLIB_CLI_COMMAND(test_ioam_profile_renew_refresh_cmd, static) =
{
.path = "test ioam profile-notification  ",
.short_help =
        "test ioam profile-notification path-name <string> start-index <index> num-profiles <number> <renew|refresh>",
.function = test_profile_renew_refresh_fn,
};

static clib_error_t *set_scv_init_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
    u8 *path_name = 0;
    u32 start_index = 0, num_profiles = 0;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "path-name %s start-index %d num-profiles %d",
                &path_name, &start_index, &num_profiles))
            scv_init(path_name, num_profiles, start_index);
        else
            return clib_error_return(0, "unknown input `%U'",
                format_unformat_error, input);
    }
    vec_free(path_name);
    return 0;
}

VLIB_CLI_COMMAND(set_ioam_sc_init_command, static) =
{
.path = "set scv-init ",
.short_help =
        "set scv-init path-name <string> start-index <index> num-profiles <number>",
.function = set_scv_init_fn,
};
