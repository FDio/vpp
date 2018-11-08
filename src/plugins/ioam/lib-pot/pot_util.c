/* 
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
#include <vnet/vnet.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <vppinfra/mem.h>
#include "math64.h"
#include "pot_util.h"

pot_main_t pot_main;

static void pot_profile_cleanup(pot_profile *profile);

static void pot_main_profiles_reset (void)
{
    pot_main_t *sm = &pot_main;
    int i = 0;

    for (i = 0; i < MAX_POT_PROFILES; i++)
    {
      pot_profile_cleanup(&(sm->profile_list[i]));
    }
    sm->active_profile_id = 0;
    if (sm->profile_list_name)
	vec_free(sm->profile_list_name);
    sm->profile_list_name = NULL;
}

int pot_util_init (void)
{
    pot_main_profiles_reset();
    
    return(0);
}

static void pot_profile_init(pot_profile * new, u8 id)
{
    if (new)
    {
        clib_memset(new, 0, sizeof(pot_profile));
        new->id = id;
    }
}

pot_profile *pot_profile_find(u8 id)
{
    pot_main_t *sm = &pot_main;

    if (id < MAX_POT_PROFILES)
    {
        return (&(sm->profile_list[id]));
    }
    return (NULL);
}
static int pot_profile_name_equal (u8 *name0, u8 *name1)
{
    int len0, len1;

    len0 = vec_len (name0);
    len1 = vec_len (name1);
    if (len0 != len1)
        return(0);
    return (0==strncmp ((char *) name0, (char *)name1, len0));
}

int pot_profile_list_is_enabled (u8 *name)
{
    pot_main_t *sm = &pot_main;
    return (pot_profile_name_equal(sm->profile_list_name, name));
}

void pot_profile_list_init(u8 * profile_list_name)
{
    pot_main_t *sm = &pot_main;
    int i = 0;

    /* If it is the same profile list skip reset */
    if (pot_profile_name_equal(sm->profile_list_name, profile_list_name))
    {
      return;
    }

    pot_main_profiles_reset();
    if (vec_len(profile_list_name))
      sm->profile_list_name = (u8 *)vec_dup(profile_list_name);
    else
      sm->profile_list_name = 0;
    sm->active_profile_id = 0;
    
    for (i = 0; i < MAX_POT_PROFILES; i++)
    {
      pot_profile_init(&(sm->profile_list[i]), i);
    }
}

static void pot_profile_cleanup(pot_profile * profile)
{
    u16 id = profile->id;

    clib_memset(profile, 0, sizeof(pot_profile));
    profile->id = id;           /* Restore id alone */
}

int pot_profile_create(pot_profile * profile, u64 prime,
    u64 poly2, u64 lpc, u64 secret_share)
{
    if (profile && !profile->in_use)
    {
        pot_profile_cleanup(profile);
        profile->prime = prime;
        profile->primeinv = 1.0 / prime;
        profile->lpc = lpc;
        profile->poly_pre_eval = poly2;
        profile->secret_share = secret_share;
	profile->total_pkts_using_this_profile = 0;
        profile->valid = 1;
	return(0);
    }
    
    return(-1);
}

int pot_set_validator(pot_profile * profile, u64 key)
{
    if (profile && !profile->in_use)
    {
        profile->validator = 1;
        profile->secret_key = key;
	return(0);
    }
    return(-1);
}

always_inline u64 pot_update_cumulative_inline(u64 cumulative, u64 random,
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

u64 pot_update_cumulative(pot_profile * profile, u64 cumulative, u64 random)
{
    if (profile && profile->valid != 0)
    {
        return (pot_update_cumulative_inline(cumulative, random, profile->secret_share,
                profile->prime, profile->lpc, profile->poly_pre_eval,
                profile->primeinv));
    }
    return (0);
}

always_inline u8 pot_validate_inline(u64 secret, u64 prime, double prime_inv,
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
u8 pot_validate(pot_profile * profile, u64 cumulative, u64 random)
{
    if (profile && profile->validator)
    {
        return (pot_validate_inline(profile->secret_key, profile->prime,
                profile->primeinv, cumulative, random));
    }
    return (0);
}

/* 
 * Utility function to get random number per pack
 */
u64 pot_generate_random(pot_profile * profile)
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

int pot_profile_set_bit_mask(pot_profile * profile, u16 bits)
{
    int sizeInBits;

    if (profile && !profile->in_use)
    {
        sizeInBits = sizeof(profile->bit_mask) * 8;
        profile->bit_mask =
            (bits >=
            sizeInBits ? (u64) - 1 : (u64) ((u64) 1 << (u64) bits) - 1);
	return(0);
    }
    return(-1);
}

clib_error_t *clear_pot_profile_command_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{

    pot_main_profiles_reset();
    
    return 0;
}

void clear_pot_profiles()
{
    clear_pot_profile_command_fn(0, 0, 0);
}

VLIB_CLI_COMMAND(clear_pot_profile_command) =
{
.path = "clear pot profile",
.short_help = "clear pot profile [<index>|all]",
.function = clear_pot_profile_command_fn,
};

static clib_error_t *set_pot_profile_command_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
    u64 prime;
    u64 secret_share;
    u64 secret_key;
    u8 validator = 0;
    u32 profile_id = ~0;
    u32 bits;
    u64 lpc = 0, poly2 = 0;
    pot_profile *profile = NULL;
    u8 *profile_list_name = NULL;
    
    bits = MAX_BITS;

    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "name %s",
		     &profile_list_name));
        else if (unformat(input, "id %d", &profile_id))
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
        else if (unformat(input, "bits-in-random %d", &bits))
        {
            if (bits > MAX_BITS)
                bits = MAX_BITS;
        }
        else
	  break;
    }
    if (profile_list_name == 0)
    {
        return clib_error_return(0, "Name cannot be null");
    }	
    pot_profile_list_init(profile_list_name);
    profile = pot_profile_find(profile_id);

    if (profile)
    {
        pot_profile_create(profile, prime, poly2, lpc, secret_share);
        if (validator)
            pot_set_validator(profile, secret_key);
        pot_profile_set_bit_mask(profile, bits);
    }
    vec_free(profile_list_name);
    return 0;
}

VLIB_CLI_COMMAND(set_pot_profile_command) =
{
.path = "set pot profile",
.short_help = "set pot profile name <string> id [0-1] [validator-key 0xu64] \
                  prime-number 0xu64 secret_share 0xu64 lpc 0xu64 \
                  polynomial2 0xu64 bits-in-random [0-64] ",
.function = set_pot_profile_command_fn,
};

static clib_error_t *set_pot_profile_activate_command_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
    pot_main_t *sm = &pot_main;
    u8 *profile_list_name = NULL;
    u32 id = 0;
    clib_error_t *result = NULL;
    
    while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat(input, "name %s",
		     &profile_list_name));
        else if (unformat(input, "id %d", &id))
            ;
        else
            return clib_error_return(0, "unknown input `%U'",
                format_unformat_error, input);
    }
    if (profile_list_name == 0)
    {
        return clib_error_return(0, "Name cannot be null");
    }

    if (!pot_profile_list_is_enabled(profile_list_name)) {
        result = clib_error_return(0, "%s list is not enabled, profile in use %s",
				 profile_list_name, sm->profile_list_name);
    } else if (0 != pot_profile_set_active((u8)id)) {
        result = clib_error_return(0, "Profile %d not defined in %s",
				 id, sm->profile_list_name);
    }
    vec_free(profile_list_name);
    return result;
}

VLIB_CLI_COMMAND(set_pot_profile_activate_command) =
{
.path = "set pot profile-active",
.short_help = "set pot profile-active name <string> id [0-1]",
.function = set_pot_profile_activate_command_fn,
};

static clib_error_t *show_pot_profile_command_fn(vlib_main_t * vm,
    unformat_input_t * input, vlib_cli_command_t * cmd)
{
    pot_main_t *sm = &pot_main;
    pot_profile *p = NULL;
    u16 i;
    u8 *s = 0;

    if (vec_len(sm->profile_list_name) == 0)
    {
        s = format(s, "POT Profiles not configured\n");
        vlib_cli_output(vm, "%v", s);
        return 0;
    }
    s = format(s, "Profile list in use  : %s\n",sm->profile_list_name);
    for (i = 0; i < MAX_POT_PROFILES; i++)
    {
        p = pot_profile_find(i);
        if (p->valid == 0)
            continue;
        s = format(s, "POT Profile at index: %d\n", i);
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
    }

    p = pot_profile_find(sm->active_profile_id);

    if (p && p->valid && p->in_use) {
        s = format(s, "\nProfile index in use: %d\n", sm->active_profile_id);
        s = format(s, "Pkts passed : 0x%Lx (%Ld)\n",
		   p->total_pkts_using_this_profile,
		   p->total_pkts_using_this_profile);
        if (pot_is_decap(p))
            s = format(s, "  This is Decap node.  \n");
    } else {
        s = format(s, "\nProfile index in use: None\n");
    }
    vlib_cli_output(vm, "%v", s);
    vec_free(s);

    return 0;
}

VLIB_CLI_COMMAND(show_pot_profile_command) =
{
.path = "show pot profile",
.short_help = "show pot profile",
.function = show_pot_profile_command_fn,
};
