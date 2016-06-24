/*
 *---------------------------------------------------------------------------
 * cnat_db_scanner.c - cnat_db_scanner dispatch function and initialization
 *
 * Copyright (c) 2009-2014 Cisco and/or its affiliates.
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
 *---------------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/buffer.h>
#include <vppinfra/string.h>
#include <vppinfra/random.h>
#include <vppinfra/fifo.h>
#include <vppinfra/hash.h>
#include <vppinfra/format.h>


#include "cnat_db.h"
#include "cnat_logging.h"
#include "cnat_global.h"
#include "cnat_ipv4_udp.h"
#include "cnat_common_api.h"

u32 translation_create_count, translation_delete_count;
u32 translation_create_rate, translation_delete_rate;

u32 in2out_forwarding_count, out2in_forwarding_count;
u32 in2out_forwarding_rate,  out2in_forwarding_rate;

u32 nat44_active_translations;
u32 num_entries;
uword check_these_pool_indices[2*MAX_DB_ENTRY_SELECTED_PER_SCAN];

#define   CNAT_DB_SCANNER_TURN_ON   5  /* just an arbitary number for easier debugging */

//extern u32 pcp_throttle_count;

typedef struct {
  u32 cached_next_index;
  /* $$$$ add data here */

  /* convenience variables */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} cnat_db_scanner_main_t;

cnat_db_scanner_main_t cnat_db_scanner_main;


static inline void check_session_for_expiry(
    	cnat_session_entry_t * sdb, u8 timeout_dirty
	/*,dslite_table_entry_t *dslite_entry_ptr*/)
{
    void cnat_delete_session_db_entry (cnat_session_entry_t *ep, u8 log);
    /* Tasks -
     * 1. Check for expiry for this entry
     * 2. Delete if expired
     */
    u32 timeout = 0;

    switch(sdb->v4_dest_key.k.vrf & CNAT_PRO_MASK) {
        case CNAT_TCP:
            if (sdb->flags & CNAT_DB_FLAG_TCP_ACTIVE) {    
                timeout = sdb->timeout;
                if(PREDICT_FALSE(timeout_dirty)) {
                    timeout = query_and_update_db_timeout(
                        (void *)sdb, SESSION_DB_TYPE);
                }
                if(PREDICT_TRUE(timeout == 0)) {
                    timeout = tcp_active_timeout;
                    //dslite_entry_ptr->timeout_info.tcp_active_timeout;
                }
            } else {
                timeout = tcp_initial_setup_timeout;
                //dslite_entry_ptr->timeout_info.tcp_initial_setup_timeout;
            }
            break;
        case CNAT_UDP:
            if (sdb->flags & CNAT_DB_FLAG_UDP_ACTIVE) {
                timeout = sdb->timeout;
                if(PREDICT_FALSE(timeout_dirty)) {
                    timeout = query_and_update_db_timeout(
                        (void *)sdb, SESSION_DB_TYPE);
                }

                if(PREDICT_TRUE(timeout == 0)) {
                    timeout = udp_act_session_timeout;
                    //dslite_entry_ptr->timeout_info.udp_act_session_timeout;
                }
            } else {
                timeout = udp_init_session_timeout;
                //dslite_entry_ptr->timeout_info.udp_init_session_timeout;
            }
            break;
        case CNAT_ICMP:
            timeout = icmp_session_timeout;
                //dslite_entry_ptr->timeout_info.icmp_session_timeout;
            break;
        case CNAT_PPTP:
            timeout = pptp_cfg.timeout;
            break;
        default:
            return;
    }
    /* Changes required for clearing sessions */
    if (PREDICT_FALSE((sdb->entry_expires == 0) ||
                        (sdb->entry_expires + timeout < cnat_current_time))) {
        cnat_delete_session_db_entry(sdb, TRUE);
    }
}

static u8 handle_db_scan_for_sessions(
    	cnat_main_db_entry_t *db, int *dirty_index, uword db_index
    	/* ,dslite_table_entry_t *dslite_entry_ptr */)
{
    /* Tasks -
     * 1. Traverse through the sessions and check for timeouts
     * 2. Delete sessions that have exipred
     * 3. Check if the db has only one session remaining.. if so,
     *    the details of the session has to be moved to main db
     *    and session db entry needs to be freed
     * 4. If db does not have any sessions left, the db itself
     *    needs to be deleted.
     */
    u32 nsessions, session_index_head, session_index;
    cnat_session_entry_t *sdb;
    u8 timeout_dirty = FALSE;

    if(PREDICT_FALSE(*dirty_index == db_index)) {
        *dirty_index = -1;
    }
    if(PREDICT_FALSE(timeout_dirty_flag == 1)) {
        timeout_dirty_flag = 0;
        *dirty_index = db_index;
        timeout_dirty = TRUE;
    }

    session_index_head = session_index = db->session_head_index;
    nsessions = db->nsessions;

    do {
        sdb = cnat_session_db + session_index;
        if(PREDICT_FALSE(!sdb)) {
            //TO DO: Debug msg?
            return FALSE;
        }
        session_index = sdb->main_list.next;
        check_session_for_expiry(sdb, timeout_dirty /*,dslite_entry_ptr*/);
        nsessions--; /* To ensure that we do not get in to an infinite loop */
      } while(session_index != session_index_head
          && db->session_head_index != EMPTY &&
          nsessions);

    /* Note.. the code below assumes that while deleting the
     * sessions, we do not delete the main db entry if it does
     * not have any sessions anymore
     */
    if(PREDICT_FALSE((!db->nsessions) &&
        (!(db->flags & CNAT_DB_FLAG_STATIC_PORT)))) {
         cnat_delete_main_db_entry_v2(db);
         return TRUE; /* to indicate that main db was deleted */
    }
    return FALSE;
}

static void cnat_db_scanner(void)
{
    cnat_main_db_entry_t * db;
    u32 timeout;
    cnat_vrfmap_t *my_vrfmap __attribute__((unused)) = 0;
    static int dirty_index = -1;
    u16 instance __attribute__((unused));
    //dslite_table_entry_t *dslite_entry_ptr;
    u32 i;
    uword db_index;
    //pcp_throttle_count = 0;

    for (i = 0; i < num_entries; i++) {
        db_index = check_these_pool_indices[i];
        db = cnat_main_db + db_index;
        timeout=0;
        my_vrfmap = 0;

#if 0
        if(PREDICT_FALSE(db->flags & CNAT_PCP_FLAG)) {
    
            if(db->proto_data.seq_pcp.pcp_lifetime < cnat_current_time) {
                /* mark as implicit */
                db->flags &= ~CNAT_PCP_FLAG;
            }
            continue;
        }

#endif
        if(PREDICT_FALSE(db->nsessions > 1)) {
            if(PREDICT_FALSE(
                handle_db_scan_for_sessions(db, &dirty_index, db_index /*,dslite_entry_ptr */)))            {
                continue;
            } else if(PREDICT_TRUE(db->nsessions > 1)) {
                continue;
            }
            /* if there is exactly one dest left.. let it fall through
            * and check if that needs to be deleted as well
            */
        }

#if 0 
        if (PREDICT_FALSE(db->flags & CNAT_DB_FLAG_STATIC_PORT)) {
            if (PREDICT_FALSE(db->flags & CNAT_DB_DSLITE_FLAG)) {
	        if(PREDICT_FALSE(
                    ((dslite_entry_ptr->nf_logging_policy != SESSION_LOG_ENABLE) &&
                    (dslite_entry_ptr->syslog_logging_policy != SESSION_LOG_ENABLE))
                    || (db->nsessions !=1))) {
                     continue;
	        }
            } else {
	        my_vrfmap = cnat_map_by_vrf + db->vrfmap_index;
                if(PREDICT_FALSE(
                    ((my_vrfmap->nf_logging_policy != SESSION_LOG_ENABLE) &&
                     (my_vrfmap->syslog_logging_policy != SESSION_LOG_ENABLE)) ||
                    (db->nsessions !=1))) {
                    continue;
                } 	
	    }
        }
#endif

        switch(db->in2out_key.k.vrf & CNAT_PRO_MASK) {
            case CNAT_TCP:
                if (db->flags & CNAT_DB_FLAG_TCP_ACTIVE) {
                    timeout = db->timeout;
                    if(PREDICT_FALSE(dirty_index == db_index)) {
                        dirty_index = -1;
                    }
                    if(PREDICT_FALSE(timeout_dirty_flag == 1)) {
                        timeout_dirty_flag = 0;
                        dirty_index = db_index;
                    }
                    if(PREDICT_FALSE(dirty_index != -1)) {
                        timeout = query_and_update_db_timeout(
                            (void *)db, MAIN_DB_TYPE);
                    }
                    if(PREDICT_TRUE(timeout == 0)) {
                        timeout = tcp_active_timeout;
                    }
                } else {
                    timeout = tcp_initial_setup_timeout;
                }
                break;
            case CNAT_UDP:
                if (db->flags & CNAT_DB_FLAG_UDP_ACTIVE) {
                    timeout = db->timeout;
                    if(PREDICT_FALSE(dirty_index == db_index)) {
                        dirty_index = -1;
                    }
                    if(PREDICT_FALSE(timeout_dirty_flag == 1)) {
                        timeout_dirty_flag = 0;
                        dirty_index = db_index;
                    }
                    if(PREDICT_FALSE(dirty_index != -1)) {
                        timeout = query_and_update_db_timeout(
                            (void *)db, MAIN_DB_TYPE);
                    }
                    if(PREDICT_TRUE(timeout == 0)) {
                        timeout = udp_act_session_timeout;
                    }
                } else {
                    timeout = udp_init_session_timeout;
                }
                break;
            case CNAT_ICMP:
                timeout = icmp_session_timeout;
                break;
            case CNAT_PPTP:
                timeout = pptp_cfg.timeout;
                break;
            default:
                continue;
        }


        /* Ref: CSCtu97536 */
        if (PREDICT_FALSE((db->entry_expires  == 0) || 
                    (db->entry_expires + timeout < cnat_current_time))) {
#if 0
	    if (PREDICT_FALSE(db->flags & CNAT_DB_FLAG_STATIC_PORT)) {
    	        if (PREDICT_FALSE(db->flags & CNAT_DB_DSLITE_FLAG)) {
		    instance = db->dslite_nat44_inst_id;
    	        } else {
		    instance = NAT44_RESERVED_INST_ID;
                    cnat_session_log_nat44_mapping_delete(db, 0, my_vrfmap);
	        }

                /* Reset the session details */
                db->nsessions = 0;
                db->dst_ipv4 = 0;
                db->dst_port = 0;
                db->flags &= ~(CNAT_DB_FLAG_TCP_ACTIVE | CNAT_DB_FLAG_UDP_ACTIVE
                        | CNAT_DB_FLAG_ALG_ENTRY);
                db->timeout = 0;
                db->entry_expires = 0;
                db->alg.delta = 0;
                db->proto_data.seq_pcp.tcp_seq_num = 0;
                continue;
            }
#endif
            //printf("DELETING DB ENTRY FOR 0x%x\n", db->in2out_key.k.ipv4);
            cnat_delete_main_db_entry_v2(db);
        }
        //free(check_these_pool_indices[i]);
    }
}

static void walk_the_db (void)
{
    pool_header_t *h = pool_header(cnat_main_db);
    u32 db_uword_len;
    static u32 base_index = 0, free_bitmap_index = 0;
    int bits_scanned = 0, i;
    uword inuse_bitmap;

    num_entries=0;
    
    /* Across all db entries... */
    db_uword_len = vec_len(cnat_main_db) / NUM_BITS_IN_UWORD;
    if (PREDICT_FALSE(vec_len(cnat_main_db) % NUM_BITS_IN_UWORD)) {
        /*
         * It should not come here as in cnat_db_init_v2()
         * it is made multiple of NUM_BITS_IN_UWORD
         */
        ASSERT(0);
        return ;
    }

    if (PREDICT_FALSE(! db_uword_len))
        return ;

    while (bits_scanned < MAX_DB_ENTRY_PER_SCAN) {

        if (PREDICT_FALSE(free_bitmap_index < vec_len(h->free_bitmap))) {

            /* free_bitmap exists and it is not all 0 */

            inuse_bitmap = ~(h->free_bitmap[free_bitmap_index]);
            i = 0;
            while (inuse_bitmap) {

                /* Check to see if the index is in use */
                if (PREDICT_FALSE((inuse_bitmap >> i) & 1)) {
                    check_these_pool_indices[num_entries] = base_index + i;
                    inuse_bitmap &= ~((uword) 1 << i);
                    num_entries++;
                }
                i++;
            } // while (inuse_bitmap)
        } else {

            /*
             * 64-bit entry is 0, means all 64 entries are allocated.
             * So, simply add all 64 entries here.
             * No need to form inuse_bitmap, check and reset bits
             */
            for (i=0; i<NUM_BITS_IN_UWORD; i++) {

                check_these_pool_indices[num_entries] = base_index + i;
                num_entries++;
            }
        } // if (free_bitmap_index < vec_len(h->free_bitmap))

        /* Update free_bitmap_index and base_index for next run */
        if (PREDICT_FALSE(free_bitmap_index == db_uword_len - 1)) {
            /* wrap-around for next run */
            free_bitmap_index = 0;
            base_index = 0;
        } else {
            free_bitmap_index ++;
            base_index += NUM_BITS_IN_UWORD;
        }

        /* increment # of bits scanned */
        bits_scanned += NUM_BITS_IN_UWORD;

        /* Found enough entries to check ? */
        if (PREDICT_FALSE(num_entries >= MAX_DB_ENTRY_SELECTED_PER_SCAN))
        {
            /* This check is introduced to keep fixed MAX scan entry value */
            /* This is very much required when we do scanning for NAT64 */
            /* please check comments in cnat_db_scanner() & 
             * handler_nat64_db_scanner() */
            if (num_entries >= MAX_COMBINED_DB_ENTRIES_PER_SCAN) {
                num_entries = MAX_COMBINED_DB_ENTRIES_PER_SCAN;
            }
            break;
        }

    } // while (bits_scanned < MAX_DB_ENTRY_PER_SCAN)

    if (PREDICT_FALSE(num_entries > 0)) {
	//printf("%s: num_entries [%d]\n", __func__, num_entries);
        cnat_db_scanner(); 
    }
    return ;
}

static uword cnat_db_scanner_fn (vlib_main_t * vm,
                              vlib_node_runtime_t * node,
                              vlib_frame_t * frame)
{
  f64 timeout = 0.01;  /* timeout value in sec (10 ms) */
  static u8 timeout_count = 0;

  uword event_type;
  uword * event_data = 0;
  /* Wait until vCGN is configured */
  while (1) {
      /* Assigning a huge timeout value, vCGN may or 
       * may not get configured within this timeout  */
      vlib_process_wait_for_event_or_clock (vm, 1e9);  
      event_type = vlib_process_get_events (vm, &event_data);

      /* check whether the process is waken up by correct guy, 
       * otherwise continue waiting for the vCGN config */
      if (event_type == CNAT_DB_SCANNER_TURN_ON) {
          break;
      } 
  }

  while(1) {
    vlib_process_suspend(vm, timeout);
    
    /* Above suspend API should serve the purpose, no need to invoke wait API */
    /* vlib_process_wait_for_event_or_clock (vm, timeout); */

     /* Lets make use of this timeout for netflow packet sent */
     if (timeout_count < 100) { /* 100*10 ms = 1 sec */
         timeout_count++;
     } else {
         if (nfv9_configured) {
             handle_pending_nfv9_pkts();
         }
         timeout_count = 0;
     }
     /* Do we need this ? */
     //event_type = vlib_process_get_events (vm, &event_data);
     cnat_current_time = (u32)vlib_time_now (vm);
     if (cnat_db_init_done) {
        walk_the_db();	
     }
  }

  return 0;
}


VLIB_REGISTER_NODE (cnat_db_scanner_node) = {
    .function = cnat_db_scanner_fn,
    .type = VLIB_NODE_TYPE_PROCESS,
    .name = "cnat-db-scanner",
    .process_log2_n_stack_bytes = 18,
};

clib_error_t *cnat_db_scanner_init (vlib_main_t *vm)
{
  cnat_db_scanner_main_t *mp = &cnat_db_scanner_main;

  mp->vlib_main = vm;
  mp->vnet_main = vnet_get_main();

  return 0;
}

void cnat_scanner_db_process_turn_on(vlib_main_t *vm)
{
    vlib_process_signal_event (vm, cnat_db_scanner_node.index,
                             CNAT_DB_SCANNER_TURN_ON, 0);
    return; 
}

VLIB_INIT_FUNCTION (cnat_db_scanner_init);

