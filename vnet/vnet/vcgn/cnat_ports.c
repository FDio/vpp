/* 
 *------------------------------------------------------------------
 * cnat_ports.c - port allocator
 *
 * Copyright (c) 2008-2014 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */
#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/vec.h>
#include <vppinfra/hash.h>
#include <vppinfra/pool.h>
#include <vppinfra/clib.h>
#include <vppinfra/bitmap.h>

#include "cnat_db.h"
#include "cnat_config.h"
#include "cnat_global.h"
#include "cnat_logging.h"
#include "spp_timers.h"
#include "platform_common.h"
#include "cgn_bitmap.h"
#include "spp_platform_trace_log.h"
#include "cnat_ports.h"

#if 1 /* TOBE_PORTED */
/* Following is defined elsewhere. */
#define msg_spp_err(s)                          \
do {                                            \
    fprintf(stderr,(i8 *)s);                    \
    fputs("\n", stderr);                        \
} while(0);
#endif


#define PM_90_PERCENT_USE 58980
/*
 * instance number provisioned from HW
 */
u8 my_instance_number = 0;

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_ports_main_t;

cnat_ports_main_t cnat_ports_main;

static u32 rseed_port;          /* random number generator seed */

void
cnat_db_dump_portmap_for_vrf (u32 vrfmap_index)
{
    u32 i, pm_len;
    cnat_vrfmap_t *my_vrfmap = cnat_map_by_vrf + vrfmap_index;
    cnat_portmap_v2_t *pm, *my_pm __attribute__((unused));

    pm = my_vrfmap->portmap_list; 
    pm_len = vec_len(pm);

    for (i = 0; i < pm_len; i++) {
        my_pm = pm + i;

        PLATFORM_DEBUG_PRINT("pm %d: IPv4 Addr 0x%x - in use %d private_ip_users_count %d\n",
               i, my_pm->ipv4_address, my_pm->inuse, 
	       my_pm->private_ip_users_count);

	PLATFORM_DEBUG_PRINT("pm %d: IPv4 Addr 0x%x - in use %d "
			     "private_ip_users_count %d\n",
			     i, my_pm->ipv4_address, my_pm->inuse, 
			     my_pm->private_ip_users_count);
    }
}

void
cnat_db_dump_portmaps ()
{
    u32 i, vrfmap_index;

    for (i = 0; i < CNAT_MAX_VRFMAP_ENTRIES; i++) {
        vrfmap_index = vrf_map_array[i];

        if (vrfmap_index == VRF_MAP_ENTRY_EMPTY) {
            continue;
        }

        PLATFORM_DEBUG_PRINT("\n\nDumping the port map for uidb_index %d\n", i);
        cnat_db_dump_portmap_for_vrf(vrfmap_index);
    }
}

#ifndef NO_BULK_LOGGING
static int check_if_stat_alloc_ok_for_bulk(cnat_portmap_v2_t *pm,
            u16 i_port, bulk_alloc_size_t bulk_size,
            u16 static_port_range)
{
    uword bit_test_result;
    if(BULK_ALLOC_SIZE_NONE == bulk_size) return 1; /* No issues */

    if(i_port < static_port_range) return 1; /* we don't want bulk */

    i_port = (i_port/bulk_size) * bulk_size;
    bit_test_result = cgn_clib_bitmap_check_if_all(pm->bm, i_port, bulk_size);
    return(bit_test_result);
}
#else /* dummy */
inline static int check_if_stat_alloc_ok_for_bulk(cnat_portmap_v2_t *pm,
            u16 i_port, bulk_alloc_size_t bulk_size, 
            u16 static_port_range)
{   
    return 1;
}
#endif /* NO_BULK_LOGGING */
/*
 * cnat_port_alloc_static_v2
 * public ipv4 address/port allocator for Static Port commands
 * tries to allocate same outside port as inside port
 */
cnat_errno_t
cnat_static_port_alloc_v2 (
                 cnat_portmap_v2_t    *pm,
                 port_alloc_t          atype,
                 port_pair_t           pair_type,
                 u32                   i_ipv4_address,
                 u16                   i_port,
                 u32                  *index,
                 u32                  *o_ipv4_address,
                 u16                  *o_port,
                 u16                   static_port_range
#ifndef NO_BULK_LOGGING
                 , bulk_alloc_size_t    bulk_size,
                 int *nfv9_log_req
#endif 
		 , u16                   ip_n_to_1
                 )
{
    u32 i, hash_value, my_index, found, max_attempts;
    u16 start_bit, new_port;
    cnat_portmap_v2_t *my_pm = 0;
    u32 pm_len = vec_len(pm);
    uword bit_test_result;

#ifndef NO_BULK_LOGGING
    *nfv9_log_req = BULK_ALLOC_NOT_ATTEMPTED;
#endif 

    if (PREDICT_FALSE(pm_len == 0)) {
        return (CNAT_NO_POOL_ANY);
    }

    switch (atype) {

    case PORT_ALLOC_ANY:

        found = 0;

        /*
         * Try to hash the IPv4 address to get an index value to select the pm
         */
        hash_value = (i_ipv4_address & 0xffff) ^
	                ((i_ipv4_address > 16) & 0xffff);

        /*
         * If pm_len <= 256, compact the hash to 8 bits
         */
        if (PREDICT_TRUE(pm_len <= 256)) {
            hash_value = (hash_value & 0xff) ^ ((hash_value > 8) & 0xff);
        }

        /*
         * Ensure that the hash value is in the range 0 .. (pm_len-1)
         */
        my_index = hash_value % pm_len;

        for (i = 0; i < PORT_PROBE_LIMIT; i++) {
            my_pm = pm + my_index;
	    if(PREDICT_TRUE(ip_n_to_1)) {
		if(PREDICT_TRUE(my_pm->private_ip_users_count < ip_n_to_1)) {
		    /*
		     * Try to find a PM with atlest 33% free and my_port free
		     */
		    if (PREDICT_TRUE((my_pm->inuse < ((BITS_PER_INST*2)/3)) &&
				     clib_bitmap_get_no_check(my_pm->bm, 
							      i_port) == 1) 
#ifndef NO_BULK_LOGGING
			&& check_if_stat_alloc_ok_for_bulk(my_pm, i_port,
							   bulk_size, 
							   static_port_range)
#endif 
			) {
			found = 1;
			break;
		    }
		}
		
	    } else {
		/*
		 * Try to find a PM with atlest 33% free and my_port free
		 */
		if (PREDICT_TRUE((my_pm->inuse < ((BITS_PER_INST*2)/3)) &&
				 clib_bitmap_get_no_check(my_pm->bm, 
							  i_port) == 1) 
#ifndef NO_BULK_LOGGING
		    && check_if_stat_alloc_ok_for_bulk(my_pm, i_port,
						       bulk_size, 
						       static_port_range)
#endif 
                    ) {
		    found = 1;
		    break;
		}
	    }
            my_index = (my_index + 1) % pm_len;
        }

        /*
         * If not found do it the hard way .
         * "hard" way, best-fit.
         */
        if (!found) {
            u32 min_inuse_any, min_inuse_myport;
            u32 min_index_any, min_index_myport;

            min_inuse_any = min_inuse_myport = PORTS_PER_ADDR + 1;
            min_index_any = min_index_myport = ~0;
            for (i = 0; i < pm_len; i++) {
                my_pm = pm + i;
		if(PREDICT_TRUE(ip_n_to_1)) {
		    if(PREDICT_TRUE(my_pm->private_ip_users_count < ip_n_to_1))                     {
			if (PREDICT_FALSE(my_pm->inuse < min_inuse_any)) {
			    min_inuse_any = my_pm->inuse;
			    min_index_any = my_pm - pm;
			}
			if (PREDICT_FALSE(my_pm->inuse < min_inuse_myport)) {
			    if (PREDICT_TRUE(clib_bitmap_get_no_check(
					     my_pm->bm,i_port) == 1) 
#ifndef NO_BULK_LOGGING
				&& check_if_stat_alloc_ok_for_bulk(my_pm, 
					    i_port,bulk_size,static_port_range)
#endif 
				) {
				min_inuse_myport = my_pm->inuse;
				min_index_myport = my_pm - pm;
			    }
			}
			
		    } 
		    
		} else {
		    if (PREDICT_FALSE(my_pm->inuse < min_inuse_any)) {
			min_inuse_any = my_pm->inuse;
			min_index_any = my_pm - pm;
		    }
		    if (PREDICT_FALSE(my_pm->inuse < min_inuse_myport)) {
			if (PREDICT_TRUE(clib_bitmap_get_no_check(
					 my_pm->bm, i_port) == 1) 
#ifndef NO_BULK_LOGGING
			    && check_if_stat_alloc_ok_for_bulk(my_pm, i_port,
						 bulk_size, static_port_range)
#endif 
			    ) {
			    min_inuse_myport = my_pm->inuse;
			    min_index_myport = my_pm - pm;
			}
		    }
		}
            }

            /*
             * Check if we have an exactly matching PM that has
             * myport free.  If so use it.  If no such PM is
             * available, use any PM
             */
            if (PREDICT_TRUE(min_inuse_myport < PORTS_PER_ADDR)) {
                my_pm = pm + min_index_myport;
                my_index = min_index_myport;
                found = 1;
            } else if (PREDICT_TRUE(min_inuse_any < PORTS_PER_ADDR)) {
                my_pm = pm + min_index_any;
                my_index = min_index_any;
                found = 1;
            }
        }

        if (!found) {
            return (CNAT_NO_PORT_ANY);
        }
        break;

    case PORT_ALLOC_DIRECTED:
        my_index = *index;
        if (PREDICT_FALSE(my_index > pm_len)) {
            return (CNAT_INV_PORT_DIRECT);
        }
        my_pm = pm + my_index;
        break;

    default:
        return (CNAT_ERR_PARSER);
    }

    /* Allocate a matching port if possible */
    start_bit = i_port;
    found = 0;
    max_attempts = BITS_PER_INST;
#ifndef NO_BULK_LOGGING
    if((BULK_ALLOC_SIZE_NONE != bulk_size) && 
        (i_port >= static_port_range)) {
        start_bit =  (start_bit/bulk_size) * bulk_size;
        max_attempts = BITS_PER_INST/bulk_size;
    }
#endif /* NO_BULK_LOGGING */

    for (i = 0; i < max_attempts; i++) {
#ifndef NO_BULK_LOGGING
        if((BULK_ALLOC_SIZE_NONE != bulk_size) &&
            (i_port >= static_port_range)) {
            bit_test_result = cgn_clib_bitmap_check_if_all(my_pm->bm, 
                        start_bit, bulk_size);
        }
        else
#endif /* #ifndef NO_BULK_LOGGING */
        bit_test_result = clib_bitmap_get_no_check(my_pm->bm, start_bit);

        if (PREDICT_TRUE(bit_test_result)) {
#ifndef NO_BULK_LOGGING
        if((BULK_ALLOC_SIZE_NONE != bulk_size) && 
            (i_port >= static_port_range)) {
            *nfv9_log_req = start_bit;
            if(i==0) new_port = i_port; /* First go */
            else {
                new_port = bit2port(start_bit);
                if (pair_type == PORT_S_ODD &&  (new_port & 0x1) == 0)
                    new_port++;                    
            }
            found = 1;
            break;
        }
        else {
#endif  /* NO_BULK_LOGGING */
            new_port = bit2port(start_bit);
            if (pair_type == PORT_S_ODD) {
                if ((new_port & 0x1) == 1) {
                    found = 1;
                    break;
                }
            } else if (pair_type == PORT_S_EVEN) {
                if ((new_port & 0x1) == 0) {
                    found = 1;
                    break;
                }
            } else {
                found = 1;
                break;
            }
#ifndef NO_BULK_LOGGING
        }
#endif 
        }
#ifndef NO_BULK_LOGGING
        if((BULK_ALLOC_SIZE_NONE != bulk_size) &&
                (i_port >= static_port_range))
            start_bit = (start_bit + bulk_size) % BITS_PER_INST;
        else {
#endif /* NO_BULK_LOGGING */
            start_bit = (start_bit + 1) % BITS_PER_INST;
            if(PREDICT_FALSE(start_bit == 0)) {
                start_bit = 1; /* Port 0 is invalid, so start from 1 */
            }
#ifndef NO_BULK_LOGGING
        }
#endif 
    } /* End of for loop */

    if (!found) {
        /* Port allocation failure */
        if (atype == PORT_ALLOC_DIRECTED) {
            return (CNAT_NOT_FOUND_DIRECT);
        } else {
            return (CNAT_NOT_FOUND_ANY);
        }
    }

    /* Accounting */
    cgn_clib_bitmap_clear_no_check(my_pm->bm, new_port);
    (my_pm->inuse)++;

    *index = my_pm - pm;
    *o_ipv4_address = my_pm->ipv4_address;

    *o_port = new_port;

    return (CNAT_SUCCESS);
}

/*
 * Try to allocate a portmap structure based on atype field
 */
cnat_portmap_v2_t *
cnat_dynamic_addr_alloc_from_pm (
                 cnat_portmap_v2_t    *pm,
                 port_alloc_t          atype,
                 u32                  *index,
                 cnat_errno_t         *err,
                 u16                   ip_n_to_1,
                 u32                  *rseed_ip)
{
    u32 i, pm_len;
    int my_index;
    int min_inuse, min_index;

    cnat_portmap_v2_t *my_pm = 0;
    *err = CNAT_NO_POOL_ANY;

    pm_len = vec_len(pm);

    switch(atype) {
    case PORT_ALLOC_ANY:
        if (PREDICT_FALSE(pm_len == 0)) {
	    my_pm = 0;
            *err = CNAT_NO_POOL_ANY;
            goto done;
        }

        /* "Easy" way, first address with at least 200 free ports */
        for (i = 0; i < PORT_PROBE_LIMIT; i++) {
            *rseed_ip = randq1(*rseed_ip);
            my_index = (*rseed_ip) % pm_len;
            my_pm = pm + my_index;
            if (PREDICT_FALSE(ip_n_to_1)) {
		if(PREDICT_TRUE(ip_n_to_1 == 1)) {
		    if (PREDICT_FALSE(0 == my_pm->inuse)) {	
			goto done;		
		    }					    
		} else {
		    if(PREDICT_TRUE(my_pm->private_ip_users_count < ip_n_to_1))                     {
			if (PREDICT_FALSE(my_pm->inuse < ((BITS_PER_INST*2)/3)))                        {
			    goto done;
			}
		    } 
		}
            } else {
                if (PREDICT_FALSE(my_pm->inuse < ((BITS_PER_INST*2)/3))) {
                    goto done;
                }
            }
        }  

        /* "hard" way, best-fit. $$$$ Throttle complaint */
        min_inuse = PORTS_PER_ADDR + 1;
        min_index = ~0;
        for (i = 0; i < pm_len; i++) {
            my_pm = pm + i;
            if (PREDICT_FALSE(ip_n_to_1)) {
	       if(PREDICT_TRUE(ip_n_to_1 == 1)) {
		   if (PREDICT_FALSE(!my_pm->inuse)) {
		       min_inuse = my_pm->inuse;
		       min_index = my_pm - pm;
		   } 
	       } else {
		   if(PREDICT_TRUE(my_pm->private_ip_users_count < ip_n_to_1)) {
		       if (PREDICT_TRUE(my_pm->inuse < min_inuse)) {
			   min_inuse = my_pm->inuse;
			   min_index = my_pm - pm;
		       }

		   } 
	       }

            } else {
                if (PREDICT_TRUE(my_pm->inuse < min_inuse)) {
                    min_inuse = my_pm->inuse;
                    min_index = my_pm - pm;
                }
            }
        }

        if (PREDICT_TRUE(min_inuse < PORTS_PER_ADDR)) {
            my_pm = pm + min_index;
            my_index = min_index;
            goto done;
        }

        /* Completely out of ports */
#ifdef DEBUG_PRINTF_ENABLED
        PLATFORM_DEBUG_PRINT("%s out of ports\n", __FUNCTION__);
#endif

	my_pm = 0;
        *err = CNAT_NO_PORT_ANY;
        break;


    case PORT_ALLOC_DIRECTED:
        //ASSERT(*index < pm_len);
        if (PREDICT_FALSE(*index > pm_len)) {
	    my_pm = 0;
            *err = CNAT_INV_PORT_DIRECT;
            goto done;
        }
        my_pm = pm + *index;
        my_index = *index;
        break;

    default:
        msg_spp_err("bad allocation type in cnat_port_alloc");
        my_pm = 0;
        *err = CNAT_ERR_PARSER;
        break;
    }

 done:
    if (PREDICT_FALSE(my_pm == NULL)) {
        return (my_pm);
    }

    if (PREDICT_FALSE(my_pm->inuse >= BITS_PER_INST)) {
        my_pm = 0;
        if (atype == PORT_ALLOC_DIRECTED) {
            *err = CNAT_BAD_INUSE_DIRECT;
        } else {
            *err = CNAT_BAD_INUSE_ANY;
        }
    }

    return (my_pm);
}


/*
 * cnat_port_alloc_v2
 * public ipv4 address/port allocator for dynamic ports
 *
 * 200K users / 20M translations means vec_len(cnat_portmap) will be
 * around 300.
 *
 */
cnat_errno_t
cnat_dynamic_port_alloc_v2 (
                 cnat_portmap_v2_t    *pm,
                 port_alloc_t          atype,
                 port_pair_t           pair_type,
                 u32                  *index,
                 u32                  *o_ipv4_address,
                 u16                  *o_port,
                 u16                  static_port_range
#ifndef NO_BULK_LOGGING
                 , bulk_alloc_size_t    bulk_size,
                  int *nfv9_log_req
#endif
                 , u16                   ip_n_to_1,
                  u32                  *rseed_ip
                 )
{
    int i;
    cnat_errno_t       my_err = CNAT_NO_POOL_ANY;
    cnat_portmap_v2_t *my_pm = 0;
    u16 start_bit;
    u16 new_port;
    uword bit_test_result;
    uword max_trys_to_find_port;

    ASSERT(index);
    ASSERT(o_ipv4_address);
    ASSERT(o_port);

    my_pm = cnat_dynamic_addr_alloc_from_pm(pm, atype, index, &my_err, ip_n_to_1, 
            rseed_ip);

    if (PREDICT_FALSE(my_pm == NULL)) {
        return (my_err);
    }
    if(PREDICT_FALSE(my_pm->dyn_full == 1)) {
        if (atype == PORT_ALLOC_DIRECTED) {
            return (CNAT_NOT_FOUND_DIRECT);
        } else {
            return (CNAT_NOT_FOUND_ANY);
        }
    }

#if DEBUG > 1
    PLATFORM_DEBUG_PRINT("ALLOC_PORT_V2: My_Instance_Number %d: IP addr 0x%x, Inuse %d\n",
           my_instance_number, my_pm->ipv4_address, my_pm->inuse);
#endif

    rseed_port = randq1(rseed_port);

    /*
     * Exclude the static port range for allocating dynamic ports
     */
    start_bit = (rseed_port) % (BITS_PER_INST - static_port_range);
    start_bit = start_bit + static_port_range;

#ifndef NO_BULK_LOGGING
    *nfv9_log_req = BULK_ALLOC_NOT_ATTEMPTED;
    if(BULK_ALLOC_SIZE_NONE != bulk_size)
    {
        /* We need the start port of the range to be alined on integer multiple
         * of bulk_size */
        max_trys_to_find_port = BITS_PER_INST/bulk_size;
        start_bit= ((start_bit + bulk_size -1)/bulk_size) * bulk_size;
    }
    else
#endif /* #ifndef NO_BULK_LOGGING */
    max_trys_to_find_port = BITS_PER_INST;

    /* Allocate a random port / port-pair */
    for (i = 0; i < max_trys_to_find_port;  i++) {

    /* start_bit is only a u16.. so it can rollover and become zero */
    if (PREDICT_FALSE( /* (start_bit >= BITS_PER_INST) || FIXME u16 cannot be >= 65536 */
                    (start_bit < static_port_range))) {
                    start_bit = static_port_range;
#ifndef NO_BULK_LOGGING
        if(BULK_ALLOC_SIZE_NONE != bulk_size) {
            start_bit= ((start_bit + bulk_size -1)/bulk_size) * bulk_size;
        }
#endif /* #ifndef NO_BULK_LOGGING */
    }
        /* Scan forward from random position */
#ifndef NO_BULK_LOGGING
        if(BULK_ALLOC_SIZE_NONE != bulk_size) {
            bit_test_result = cgn_clib_bitmap_check_if_all(my_pm->bm,
            start_bit, bulk_size);
        }
        else
#endif /* #ifndef NO_BULK_LOGGING */
        bit_test_result = clib_bitmap_get_no_check(my_pm->bm, start_bit);
        
        if (PREDICT_TRUE(bit_test_result)) {
            new_port = bit2port(start_bit);
#ifndef NO_BULK_LOGGING
            if(BULK_ALLOC_SIZE_NONE != bulk_size)
                *nfv9_log_req = new_port;
#endif
            if ((pair_type == PORT_S_ODD) &&
                       (!(new_port & 0x1))) {
#ifndef NO_BULK_LOGGING
                if(BULK_ALLOC_SIZE_NONE != bulk_size) {
                    start_bit++; /* Just use the next one in the bulk range */
                    new_port++;
                    goto found2;
                }
#endif /* #ifndef NO_BULK_LOGGING */
                        goto notfound;
            } else if ((pair_type == PORT_S_EVEN) &&
                       (new_port & 0x1)) {
                        goto notfound;
            }

            /* OK we got one or two suitable ports */
            goto found2;
        }

    notfound:
#ifndef NO_BULK_LOGGING
    if(BULK_ALLOC_SIZE_NONE != bulk_size)
        start_bit += bulk_size;
    else
#endif /* #ifndef NO_BULK_LOGGING */
    start_bit++;

    } /* end of for loop */

    /* Completely out of ports */

    /* Port allocation failure */
    /* set dyn_full flag. This would be used to verify
     * for further dyn session before searching for port
     */
    if (atype == PORT_ALLOC_DIRECTED) {
        my_pm->dyn_full = 1;
        return (CNAT_NOT_FOUND_DIRECT);
    } else {
        my_pm->dyn_full = 1;
        return (CNAT_NOT_FOUND_ANY);
    }
  

 found2:

    /* Accounting */
    cgn_clib_bitmap_clear_no_check (my_pm->bm, start_bit);
    (my_pm->inuse)++;

    *index = my_pm - pm;
    *o_ipv4_address = my_pm->ipv4_address;

    *o_port = new_port;
    return (CNAT_SUCCESS);
}

#ifdef TOBE_PORTED
/*
 * cnat_alloc_port_from_pm
 * Given a portmap structure find port/port_pair that are free
 *
 * The assumption in this function is that bit in bm corresponds
 * to a port number.   This is TRUE and hence there is no call
 * to the function bit2port here, though it is done in other 
 * places in this file.
 *
 */
static u32
cnat_alloc_port_from_pm (
    u32 start_port,
    u32 end_port,
    cnat_portmap_v2_t *my_pm,
    port_pair_t       pair_type
#ifndef NO_BULK_LOGGING
    , bulk_alloc_size_t    bulk_size,
    int                  *nfv9_log_req
#endif /* #ifnded NO_BULK_ALLOCATION */
    )
{
    u32 i;
    u32 start_bit;
    u32 total_ports = end_port - start_port + 1;
    uword bit_test_result;
    uword max_trys_to_find_port;

    rseed_port = randq1(rseed_port);

    start_bit = rseed_port % total_ports;
    start_bit = start_bit + start_port;
#ifndef NO_BULK_LOGGING
    *nfv9_log_req = BULK_ALLOC_NOT_ATTEMPTED;
    if(BULK_ALLOC_SIZE_NONE != bulk_size)
    {
        /* We need the start port of the range to be alined on integer multiple
         * of bulk_size */
        max_trys_to_find_port = total_ports/bulk_size;
        start_bit= ((start_bit + bulk_size -1)/bulk_size) * bulk_size;
    }
    else
#endif /* #ifndef NO_BULK_LOGGING */
    max_trys_to_find_port = total_ports;

    /* Allocate a random port / port-pair */
    for (i = 0; i < max_trys_to_find_port; i++) {
        /* start_bit is only a u16.. so it can rollover and become zero */
        if (PREDICT_FALSE((start_bit >= end_port) ||
                    (start_bit < start_port))) {
                    start_bit = start_port;
#ifndef NO_BULK_LOGGING
            if(BULK_ALLOC_SIZE_NONE != bulk_size) {
                start_bit= ((start_bit + bulk_size -1)/bulk_size) * bulk_size;
            }
#endif /* #ifndef NO_BULK_LOGGING */
        }

        /* Scan forward from random position */
#ifndef NO_BULK_LOGGING
        if(BULK_ALLOC_SIZE_NONE != bulk_size) {
            bit_test_result = cgn_clib_bitmap_check_if_all(my_pm->bm,
            start_bit, bulk_size);
        }
        else
#endif /* #ifndef NO_BULK_LOGGING */
            bit_test_result = clib_bitmap_get_no_check(my_pm->bm, start_bit);
        
            if (PREDICT_TRUE(bit_test_result)) {
#ifndef NO_BULK_LOGGING
                if(BULK_ALLOC_SIZE_NONE != bulk_size) {
                    /* Got the entire bulk range */
                    *nfv9_log_req = bit2port(start_bit);
                    return start_bit;
                } else { 
#endif /* #ifndef NO_BULK_LOGGING */
		        /*
		         * For PORT_PAIR, first port has to be Even
		         * subsequent port <= end_port
		         * subsequent port should be unallocated
		         */
                if ((start_bit & 0x1) ||
                    ((start_bit + 1) > end_port) ||
		            (clib_bitmap_get_no_check(my_pm->bm,
		                    (start_bit + 1)) == 0)) {
                        goto notfound;
                }
                return (start_bit);
#ifndef NO_BULK_LOGGING
            }
#endif /* #ifndef NO_BULK_LOGGING */
        } /* if( free port found ) */

notfound:
#ifndef NO_BULK_LOGGING
        if(BULK_ALLOC_SIZE_NONE != bulk_size) {
            start_bit += bulk_size;
        } else
#endif /* #ifndef NO_BULK_LOGGING */
            start_bit++;

    }
    return (BITS_PER_INST);
}

/*
 * cnat_dynamic_port_alloc_rtsp
 * public ipv4 address/port allocator for dynamic ports
 *
 * 200K users / 20M translations means vec_len(cnat_portmap) will be
 * around 300.
 *
 */

cnat_errno_t
cnat_dynamic_port_alloc_rtsp (
                            cnat_portmap_v2_t *pm,
                            port_alloc_t       atype,
                            port_pair_t        pair_type,
                            u16                start_range,
                            u16                end_range,
                            u32               *index,
                            u32               *o_ipv4_address,
                            u16               *o_port
#ifndef NO_BULK_LOGGING
                            , bulk_alloc_size_t bulk_size,
                            int *nfv9_log_req
#endif
                            , u32               *rseed_ip
            )
{

    u32 current_timestamp;
    cnat_errno_t       my_err = CNAT_NO_POOL_ANY;
    cnat_portmap_v2_t *my_pm = 0;
    u32 alloc_bit;

    ASSERT(index);
    ASSERT(o_ipv4_address);
    ASSERT(o_port);

    my_pm = cnat_dynamic_addr_alloc_from_pm(pm, atype, index, &my_err, 0,rseed_ip);

    if (PREDICT_FALSE(my_pm == NULL)) {
        return (my_err);
    }

#if DEBUG > 1
    PLATFORM_DEBUG_PRINT("ALLOC_PORT_V2: My_Instance_Number %d: IP addr 0x%x, Inuse %d\n",
           my_instance_number, my_pm->ipv4_address, my_pm->inuse);
#endif

    alloc_bit = 
	cnat_alloc_port_from_pm(start_range, end_range, my_pm, pair_type
#ifndef NO_BULK_LOGGING
         , bulk_size, nfv9_log_req
#endif /* #ifndef NO_BULK_LOGGING */
        );

    if (alloc_bit < BITS_PER_INST) {
	if (pair_type == PORT_PAIR) {
	    /* Accounting */
	    cgn_clib_bitmap_clear_no_check (my_pm->bm, alloc_bit);
	    cgn_clib_bitmap_clear_no_check (my_pm->bm, alloc_bit+1);
	    (my_pm->inuse) += 2;
	} else {
	    /* Accounting */
	    cgn_clib_bitmap_clear_no_check (my_pm->bm, alloc_bit);
	    (my_pm->inuse)++;
	}

	*index = my_pm - pm;
	*o_ipv4_address = my_pm->ipv4_address;

	*o_port = bit2port(alloc_bit);;

	return (CNAT_SUCCESS);
    }

    /* Completely out of ports */
    current_timestamp = spp_trace_log_get_unix_time_in_seconds();
    if (PREDICT_FALSE((current_timestamp - my_pm->last_sent_timestamp) >
                1000)) {
        spp_printf(CNAT_NO_EXT_PORT_AVAILABLE, 0, NULL);
        my_pm->last_sent_timestamp = current_timestamp;
    }


    /* Port allocation failure */
    if (atype == PORT_ALLOC_DIRECTED) {
        return (CNAT_NOT_FOUND_DIRECT);
    } else {
        return (CNAT_NOT_FOUND_ANY);
    }
}
#else
cnat_errno_t
cnat_dynamic_port_alloc_rtsp (
                            cnat_portmap_v2_t *pm,
                            port_alloc_t       atype,
                            port_pair_t        pair_type,
                            u16                start_range,
                            u16                end_range,
                            u32               *index,
                            u32               *o_ipv4_address,
                            u16               *o_port
#ifndef NO_BULK_LOGGING
                            , bulk_alloc_size_t bulk_size,
                            int *nfv9_log_req
#endif
                            , u32               *rseed_ip
            )
{
    return (CNAT_NOT_FOUND_ANY);
}
#endif


/*
 * cnat_mapped_static_port_alloc_v2
 * /
 */
cnat_errno_t
cnat_mapped_static_port_alloc_v2 (
             cnat_portmap_v2_t    *pm, 
		     port_alloc_t         atype, 
		     u32                  *index,
		     u32                   ipv4_address,
		     u16                   port
#ifndef NO_BULK_LOGGING
            , int *nfv9_log_req,
            bulk_alloc_size_t bulk_size
#endif
	    , u16                   ip_n_to_1
                )
{
    int i;
    u32 pm_len;
    u16 bm_bit;
    cnat_portmap_v2_t *my_pm = 0;
    u32 my_index;

    ASSERT(index);

    /*
     * Map the port to the bit in the pm bitmap structure.
     * Note that we use ports from 1024..65535, so 
     * port number x corresponds to (x-1024) position in bitmap
     */
    bm_bit = port2bit(port);

    pm_len = vec_len(pm);

    switch(atype) {
    case PORT_ALLOC_ANY:
        if (PREDICT_FALSE(pm_len == 0)) {
            return (CNAT_NO_POOL_ANY);
        }

	    /*
	     * Find the pm that is allocated for this translated IP address
	     */
	    my_index = pm_len;

        for (i = 0; i < pm_len; i++) {
	        my_pm = pm + i;
	        if (PREDICT_FALSE(my_pm->ipv4_address == ipv4_address)) {
		        my_index = i;
		        break;
	        }
	    }

	    if ((PREDICT_FALSE(my_index >= pm_len)) || 
		((PREDICT_FALSE(ip_n_to_1)) && (PREDICT_TRUE(my_pm->private_ip_users_count >= ip_n_to_1)))) {
		return (CNAT_NO_POOL_ANY);
	    }

	    break;

    case PORT_ALLOC_DIRECTED:
        if (PREDICT_FALSE(*index > pm_len)) {
            return (CNAT_INV_PORT_DIRECT);
        }

        my_index = *index;
        my_pm = pm + my_index;
        if (PREDICT_FALSE(my_pm->ipv4_address != ipv4_address)) {
            if (PREDICT_FALSE(global_debug_flag && CNAT_DEBUG_GLOBAL_ALL)) { 
                PLATFORM_DEBUG_PRINT("Delete all main db entry for that particular in ipv4 address\n");
            }
            return (CNAT_INV_PORT_DIRECT);
        }
        
        break;

    default:
        msg_spp_err("bad allocation type in cnat_port_alloc");
        return (CNAT_ERR_PARSER);
    }


    if (PREDICT_FALSE(my_pm == NULL)) {
	    return (CNAT_NO_POOL_ANY);
    }

    /*
     * Check if the port is already allocated to some other mapping
     */
    if (PREDICT_FALSE(clib_bitmap_get_no_check (my_pm->bm, bm_bit) == 0)) {
	    return (CNAT_NO_POOL_ANY);
    }

#if DEBUG > 1
    PLATFORM_DEBUG_PRINT("ALLOC_PORT_V2: My_Instance_Number %d: IP addr 0x%x, Inuse %d\n",
           my_instance_number, my_pm->ipv4_address, my_pm->inuse);
#endif

    /*
     * Indicate that the port is already allocated
     */
    cgn_clib_bitmap_clear_no_check (my_pm->bm, bm_bit);
    (my_pm->inuse)++;

    *index = my_index;

    return (CNAT_SUCCESS);
}

void cnat_port_free_v2 (
         cnat_portmap_v2_t *pm,
    	 int                index,
         port_pair_t        pair_type,
         u16                base_port,
         u16                static_port_range)
{
    cnat_portmap_v2_t *my_pm;
    uword bit;

    /* check for valid portmap */   
    if (PREDICT_FALSE(index > vec_len(pm))) {
        spp_printf(CNAT_INVALID_INDEX_TO_FREE_PORT, 0, 0);
        return;
    }

    my_pm = pm + index;
    bit = port2bit(base_port);

#if DEBUG > 0
    if(clib_bitmap_get_no_check(my_pm->bm, bit))
        ASSERT(clib_bitmap_get_no_check(my_pm->bm, bit) == 0); 
#endif

    cgn_clib_bitmap_set_no_check(my_pm->bm, bit);

    my_pm->inuse -= 1;
    if(base_port >= static_port_range) {
        /* Clear the full flag. we can have a new dynamic session now */
        my_pm->dyn_full = 0;
    }

    return;
}

void cnat_portmap_dump_v2 (cnat_portmap_v2_t *pm, u16 print_limit)
{
    int i;
    u32 inuse =0;

    ASSERT(pm);

    for (i = 0; i < BITS_PER_INST; i++) {
        if (PREDICT_FALSE(clib_bitmap_get_no_check (pm->bm, i) == 0)) {
            if (PREDICT_TRUE(inuse++ < print_limit))
                PLATFORM_DEBUG_PRINT(" %d", bit2port(i));
        }
    }
    if (PREDICT_FALSE(inuse >= print_limit)) {
        PLATFORM_DEBUG_PRINT("%d printed, print limit is %d\n",
                inuse, print_limit);
    }
    PLATFORM_DEBUG_PRINT("\n");
}


/*
 * cnat_ports_init
 */
clib_error_t *cnat_ports_init(vlib_main_t *vm)
{
    cnat_ports_main_t *mp = &cnat_ports_main;

    mp->vlib_main = vm;
    mp->vnet_main = vnet_get_main();

    /* suppress crypto-random port numbering */
#ifdef SOON
    if (spp_get_int_prop("no_crypto_random_ports") == 0)
        crypto_random32(&seed);
#endif

    return 0;
}

VLIB_INIT_FUNCTION(cnat_ports_init);

