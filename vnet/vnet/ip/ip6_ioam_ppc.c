/*
 *------------------------------------------------------------------
 * ipv6_ioam_ppc.c -- Inband IPv6 OAM PPC Module
 *
 * October 2014, Nina E R, Modified by Rangan
 *
 * Copyright (c) 2014-2015 by Cisco Systems, Inc.
 * All rights reserved.
 *
 *------------------------------------------------------------------
 */

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>

#include <vnet/ip/ip.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <vppinfra/elog.h>

#include <vnet/ip/ip6_hop_by_hop.h>


#define SEQ_CHECK_VALUE 0x80000000 /* for seq number wraparound detection */

void ppc_init_flow (ioam_ipfix_elts_t *ipfix)
{
    ppc_bitmap *bitmap = &ipfix->ppc_rx.bitmap;
    bitmap->window_size = PPC_WINDOW_SIZE;
    bitmap->array_size = PPC_WINDOW_ARRAY_SIZE;
    bitmap->mask = 32 * PPC_WINDOW_ARRAY_SIZE - 1;
    bitmap->array[0] = 0x00000000;/* pretend we haven seen sequence numbers 0*/
    bitmap->highest = 0;

    ipfix->seq_num = 0;
    return ;
}

static inline void BIT_SET (u64 *p, u32 n)
{
    p[ n>>5 ] |= (1 << (n&31));
}

static inline int BIT_TEST (u64 *p, u32 n)
{
    return p[ n>>5 ] & (1 << (n&31));
}

static void BIT_CLEAR (u64 *p, u64 start, int  num_bits, u32 mask)
{
    int n, t;
    int start_index = (start >> 5);
    int mask_index = (mask >> 5);

    start_index &= mask_index;
    if (start & 0x1f) {
        int start_bit = (start & 0x1f);

        n = (1 << start_bit)-1;
        t = start_bit + num_bits;
        if (t < 32) {
            n |= ~((1 << t)-1);
            p[ start_index ] &= n;
            return;
        }
        p[ start_index ] &= n;
        start_index = (start_index + 1) & mask_index;
        num_bits -= (32 - start_bit);
    }
    while (num_bits >= 32) {
        p[ start_index ] = 0;
        start_index = (start_index + 1) & mask_index;
        num_bits -= 32;
    }
    n = ~((1 << num_bits) - 1);
    p[ start_index ] &= n;
}


static inline u8 ppc_check_wraparound(u32 a, u32 b)
{
    if ((a != b) && (a > b) && ((a - b) > SEQ_CHECK_VALUE)) {
        return 1;
    }
    return 0;
}

/* 
 * Function to analyze the PPC value recevied.
 *     - Updates the bitmap with received sequence number 
 *     - counts the received/lost/duplicate/reordered packets
 */
void ioam6_check_ppc(ppc_rx_info *ppc_rx, u64 ppc) 
{

    int diff;
    static int peer_dead_count;
    ppc_bitmap *bitmap = &ppc_rx->bitmap;

    if (!bitmap)
        return;

    fformat(stderr, "IOAM6 PPC:Received packets with PPC %llu, current highest %llu\n", 
            ppc, bitmap->highest);

    ppc_rx->rx_packets++;

    if (ppc > bitmap->highest) {   /* new larger sequence number */
        peer_dead_count = 0;
        diff = ppc - bitmap->highest;
        if (diff < bitmap->window_size) {
            if (diff > 1) { /* diff==1 is *such* a common case it's a win to optimize it */
                BIT_CLEAR(bitmap->array, bitmap->highest+1, diff-1, bitmap->mask);
                ppc_rx->lost_packets += diff -1;
            }
        } else {
            ppc_rx->lost_packets += diff -1;
            memset( bitmap->array, 0, bitmap->array_size * sizeof(u64) );
        }
        BIT_SET(bitmap->array, ppc & bitmap->mask);
        bitmap->highest = ppc;
        return;
    } else {                       /* we've seen a bigger seq number before */
        diff = bitmap->highest - ppc;
        if (diff >= bitmap->window_size) {
            if (ppc_check_wraparound(bitmap->highest, ppc)) {
                memset( bitmap->array, 0, bitmap->array_size * sizeof(u64)); 
                BIT_SET(bitmap->array, ppc & bitmap->mask);
                fformat(stderr,"\nWraparund seq number detected, resetting current highest %lu to %lu",
                        bitmap->highest, ppc);
                bitmap->highest = ppc;
                return;
            } else {
                fformat(stderr,"\nLarge reorder/replay of diff %lu pkts detected ,more than %d,current ppc %lu, monitoring for peer reset",
                        diff, bitmap->window_size, ppc);
                peer_dead_count++;
                if (peer_dead_count > 25) {
                peer_dead_count = 0;
                memset( bitmap->array, 0, bitmap->array_size * sizeof(u64) );
                BIT_SET(bitmap->array, ppc & bitmap->mask);
                fformat(stderr, "\nDeclaring peer reset: resetting the PPC current hightest %lu to %lu",
                        bitmap->highest, ppc);
                bitmap->highest = ppc;
                }
                //ppc_rx->reordered_packets++;
            }
            return;
        }
        if (BIT_TEST(bitmap->array, ppc & bitmap->mask)) {
            fformat(stderr, "IOAM6 PPC:Received Dup PPC %lu", ppc);
            ppc_rx->dup_packets++;
            return;    /* Already seen */
        }
        ppc_rx->reordered_packets++;
        ppc_rx->lost_packets--;
        BIT_SET(bitmap->array, ppc & bitmap->mask);
        return;
   }
}

