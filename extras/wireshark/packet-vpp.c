/* packet-vpp.c
 * 
 * Routines for the disassembly of fd.io vpp project 
 * dispatch captures
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
 * 
 * This version is not to be upstreamed as-is, since it hooks up the
 * vpp dissector to WTAP_ENCAP_USER13, a test encap type.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/in_cksum.h>
#include <epan/nlpid.h>
#include <epan/etypes.h>
#include <stdio.h>
#include <wsutil/ws_printf.h>

void proto_register_vpp(void);
void proto_reg_handoff_vpp(void);

static int proto_vpp = -1;
static int proto_vpp_opaque = -1;
static int proto_vpp_trace = -1;
static int hf_vpp_nodename = -1;
static int hf_vpp_buffer_index = -1;

static int hf_vpp_buffer_current_data = -1;
static int hf_vpp_buffer_current_length = -1;

static int hf_vpp_buffer_flags = -1;
static int hf_vpp_buffer_flag_non_default_freelist = -1;
static int hf_vpp_buffer_flag_traced = -1;
static int hf_vpp_buffer_flag_next_present = -1;
static int hf_vpp_buffer_flag_total_length_valid = -1;
static int hf_vpp_buffer_flag_ext_hdr_valid = -1;       
static int hf_vpp_buffer_flag_l4_checksum_computed = -1;
static int hf_vpp_buffer_flag_l4_checksum_correct = -1;
static int hf_vpp_buffer_flag_vlan_2_deep = -1;
static int hf_vpp_buffer_flag_vlan_1_deep = -1;
static int hf_vpp_buffer_flag_span_clone = -1;
static int hf_vpp_buffer_flag_loop_counter_valid = -1;
static int hf_vpp_buffer_flag_locally_originated = -1;
static int hf_vpp_buffer_flag_is_ip4 = -1;
static int hf_vpp_buffer_flag_is_ip6 = -1;
static int hf_vpp_buffer_flag_offload_ip_checksum = -1;
static int hf_vpp_buffer_flag_offload_tcp_checksum = -1;
static int hf_vpp_buffer_flag_offload_udp_checksum = -1;
static int hf_vpp_buffer_flag_is_natted = -1;
static int hf_vpp_buffer_flag_l2_hdr_offset_valid = -1;
static int hf_vpp_buffer_flag_l3_hdr_offset_valid = -1;
static int hf_vpp_buffer_flag_l4_hdr_offset_valid = -1;
static int hf_vpp_buffer_flag_flow_report = -1;
static int hf_vpp_buffer_flag_is_dvr = -1;
static int hf_vpp_buffer_flag_qos_data_valid = -1;
static int hf_vpp_buffer_flow_id = -1;
static int hf_vpp_buffer_next_buffer = -1;
static int hf_vpp_buffer_current_config_index = -1;
static int hf_vpp_buffer_error_index = -1;
static int hf_vpp_buffer_n_add_refs = -1;
static int hf_vpp_buffer_buffer_pool_index = -1;

static int hf_vpp_buffer_opaque_raw = -1;
static int hf_vpp_buffer_opaque_opaque = -1;

static int hf_vpp_buffer_trace = -1;

static gint ett_vpp = -1;
static gint ett_vpp_opaque = -1;
static gint ett_vpp_trace = -1;

static dissector_handle_t vpp_dissector_handle;
static dissector_handle_t vpp_opaque_dissector_handle;
static dissector_handle_t vpp_trace_dissector_handle;

static dissector_handle_t eth_dissector_handle;
static dissector_handle_t ip4_dissector_handle;
static dissector_handle_t ip6_dissector_handle;
static dissector_handle_t udp_dissector_handle;

#define foreach_node_to_dissector_handle                        \
_("ip6-lookup", "ipv6", ip6_dissector_handle)                   \
_("ip4-input-no-checksum", "ip", ip4_dissector_handle)          \
_("ip4-lookup", "ip", ip4_dissector_handle)                     \
_("ip4-local", "ip", ip4_dissector_handle)                      \
_("ip4-udp-lookup", "ip", udp_dissector_handle)                 \
_("ip4-icmp-error", "ip", ip4_dissector_handle)                 \
_("ip4-glean", "ip", ip4_dissector_handle)                      \
_("ethernet-input", "eth_maybefcs", eth_dissector_handle)

static void
add_multi_line_string_to_tree(proto_tree *tree, tvbuff_t *tvb, gint start,
  gint len, int hf)
{
    gint next;
    int  line_len;
    int  data_len;

    while (len > 0) {
        line_len = tvb_find_line_end(tvb, start, len, &next, FALSE);
        data_len = next - start;
        proto_tree_add_string(tree, hf, tvb, start, data_len, 
                              tvb_format_stringzpad(tvb, start, line_len));
        start += data_len;
        len   -= data_len;
    }
}

static int
dissect_vpp_trace (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, 
                    void* data _U_)
{
    int         offset   = 0;
    proto_item *ti;
    proto_tree *trace_tree;
    gint trace_string_length;
    
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VPP-Trace");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vpp_trace, tvb, offset, -1, ENC_NA);
    trace_tree = proto_item_add_subtree(ti, ett_vpp_trace);

    /* How long is the trace string? */
    (void ) tvb_get_stringz_enc (wmem_packet_scope(), tvb, 0,
                                 &trace_string_length, ENC_ASCII);
    
    add_multi_line_string_to_tree (trace_tree, tvb, 0,
                                   trace_string_length, 
                                   hf_vpp_buffer_trace);
    return tvb_captured_length(tvb);
}

/*
 * BIG FAT WARNING: it's impossible to #include the vpp header files,
 * so this is a private copy of .../src/vnet/buffer.h, with
 * some vpp typedefs thrown in for good measure.
 */

typedef unsigned int u32;
typedef unsigned short int u16;
typedef short int i16;
typedef unsigned char u8;
typedef unsigned long long u64;

typedef struct 
{
    u32 sw_if_index[2];
    i16 l2_hdr_offset;
    i16 l3_hdr_offset;
    i16 l4_hdr_offset;
    u8 feature_arc_index;
    u8 dont_waste_me;

    union
    {
        /* IP4/6 buffer opaque. */
        struct
        {
            /* Adjacency from destination IP address lookup [VLIB_TX].
               Adjacency from source IP address lookup [VLIB_RX].
               This gets set to ~0 until source lookup is performed. */
            u32 adj_index[2];

            union
            {
                struct
                {
                    /* Flow hash value for this packet computed from IP src/dst address
                       protocol and ports. */
                    u32 flow_hash;

                    union
                    {
                        /* next protocol */
                        u32 save_protocol;

                        /* Hint for transport protocols */
                        u32 fib_index;
                    };

                    /* Rewrite length */
                    u32 save_rewrite_length;

                    /* MFIB RPF ID */
                    u32 rpf_id;
                };

                /* ICMP */
                struct
                {
                    u8 type;
                    u8 code;
                    u32 data;
                } icmp;

                /* reassembly */
                union
                {
                    /* in/out variables */
                    struct
                    {
                        u32 next_index;	/* index of next node - ignored if "feature" node */
                        u16 estimated_mtu;	/* estimated MTU calculated during reassembly */
                    };
                    /* internal variables used during reassembly */
                    struct
                    {
                        u16 fragment_first;
                        u16 fragment_last;
                        u16 range_first;
                        u16 range_last;
                        u32 next_range_bi;
                        u16 ip6_frag_hdr_offset;
                    };
                } reass;
            };

        } ip;

        /*
         * MPLS:
         * data copied from the MPLS header that was popped from the packet
         * during the look-up.
         */
        struct
        {
            /* do not overlay w/ ip.adj_index[0,1] nor flow hash */
            u32 pad[3];
            u8 ttl;
            u8 exp;
            u8 first;
            /* Rewrite length */
            u32 save_rewrite_length;
            /*
             * BIER - the number of bytes in the header.
             *  the len field in the header is not authoritative. It's the
             * value in the table that counts.
             */
            struct
            {
                u8 n_bytes;
            } bier;
        } mpls;

        /* l2 bridging path, only valid there */
        struct opaque_l2
        {
            u32 feature_bitmap;
            u16 bd_index;		/* bridge-domain index */
            u8 l2_len;		/* ethernet header length */
            u8 shg;			/* split-horizon group */
            u16 l2fib_sn;		/* l2fib bd/int seq_num */
            u8 bd_age;		/* aging enabled */
        } l2;

        /* l2tpv3 softwire encap, only valid there */
        struct
        {
            u32 pad[4];		/* do not overlay w/ ip.adj_index[0,1] */
            u8 next_index;
            u32 session_index;
        } l2t;

        /* L2 classify */
        struct
        {
            struct opaque_l2 pad;
            union
            {
                u32 table_index;
                u32 opaque_index;
            };
            u64 hash;
        } l2_classify;

        /* vnet policer */
        struct
        {
            u32 pad[8 - 2 - 1];	/* to end of opaque */
            u32 index;
        } policer;

        /* interface output features */
        struct
        {
            u32 flags;
            u32 sad_index;
        } ipsec;

        /* MAP */
        struct
        {
            u16 mtu;
        } map;

        /* MAP-T */
        struct
        {
            u32 map_domain_index;
            struct
            {
                u32 saddr, daddr;
                u16 frag_offset;	//Fragmentation header offset
                u16 l4_offset;		//L4 header overall offset
                u8 l4_protocol;		//The final protocol number
            } v6;			//Used by ip6_map_t only
            u16 checksum_offset;	//L4 checksum overall offset
            u16 mtu;			//Exit MTU
        } map_t;

        /* IP Fragmentation */
        struct
        {
            u32 pad[2];		/* do not overlay w/ ip.adj_index[0,1] */
            u16 mtu;
            u8 next_index;
            u8 flags;			//See ip_frag.h
        } ip_frag;

        /* COP - configurable junk filter(s) */
        struct
        {
            /* Current configuration index. */
            u32 current_config_index;
        } cop;

        /* LISP */
        struct
        {
            /* overlay address family */
            u16 overlay_afi;
        } lisp;

        /* TCP */
        struct
        {
            u32 connection_index;
            u32 seq_number;
            u32 seq_end;
            u32 ack_number;
            u16 hdr_offset;		/**< offset relative to ip hdr */
            u16 data_offset;		/**< offset relative to ip hdr */
            u16 data_len;		/**< data len */
            u8 flags;
        } tcp;

        /* SCTP */
        struct
        {
            u32 connection_index;
            u16 sid; /**< Stream ID */
            u16 ssn; /**< Stream Sequence Number */
            u32 tsn; /**< Transmission Sequence Number */
            u16 hdr_offset;		/**< offset relative to ip hdr */
            u16 data_offset;		/**< offset relative to ip hdr */
            u16 data_len;		/**< data len */
            u8 subconn_idx; /**< index of the sub_connection being used */
            u8 flags;
        } sctp;

        /* SNAT */
        struct
        {
            u32 flags;
        } snat;

        u32 unused[6];
    };
} vnet_buffer_opaque_t;


#define PTAS proto_tree_add_string(opaque_tree,                         \
                                   hf_vpp_buffer_opaque_opaque,         \
                                   tvb, 0, strlen(tmpbuf), tmpbuf)

static int
dissect_vpp_opaque (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, 
                    void* data _U_)
{
    int         offset   = 0;
    proto_item *ti;
    proto_tree *opaque_tree;
    char tmpbuf [512];
    int print_offset;
    guint32 opaque[10];
    vnet_buffer_opaque_t _o, *o = &_o;

    int i;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VPP-Opaque");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vpp_opaque, tvb, offset, -1, ENC_NA);
    opaque_tree = proto_item_add_subtree(ti, ett_vpp_opaque);

    print_offset = 0;
    for (i = 0; i < 10; i++) {
        opaque[i] = tvb_get_guint32 (tvb, offset + 4*i, ENC_LITTLE_ENDIAN);
        snprintf (tmpbuf + print_offset, sizeof(tmpbuf) - print_offset, 
                  "%08x ", opaque[i]);
        print_offset = strlen (tmpbuf);
    }
    offset += 40;

    proto_tree_add_string (opaque_tree, hf_vpp_buffer_opaque_raw, tvb, 0,
                           strlen(tmpbuf), tmpbuf);

    memset (o, 0, sizeof (*o));
    memcpy (o, opaque, sizeof (opaque));
 
    snprintf (tmpbuf, sizeof(tmpbuf), 
              "sw_if_index[VLIB_RX]: %d, sw_if_index[VLIB_TX]: %d",
              o->sw_if_index[0], o->sw_if_index[1]);
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "L2 offset %d, L3 offset %d, L4 offset %d, feature arc index %d",
              (u32)(o->l2_hdr_offset),
              (u32)(o->l3_hdr_offset),
              (u32)(o->l4_hdr_offset), 
              (u32)(o->feature_arc_index));
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf), 
              "ip.adj_index[VLIB_RX]: %d, ip.adj_index[VLIB_TX]: %d",
              (u32)(o->ip.adj_index[0]),
              (u32)(o->ip.adj_index[1]));
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf), 
              "ip.flow_hash: 0x%x, ip.save_protocol: 0x%x, ip.fib_index: %d",
              o->ip.flow_hash, o->ip.save_protocol, o->ip.fib_index);
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf), 
              "ip.save_rewrite_length: %d, ip.rpf_id: %d",
              o->ip.save_rewrite_length, o->ip.rpf_id);
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "ip.icmp.type: %d ip.icmp.code: %d, ip.icmp.data: 0x%x",
              (u32)(o->ip.icmp.type),
              (u32)(o->ip.icmp.code),
              o->ip.icmp.data);
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "ip.reass.next_index: %d, ip.reass.estimated_mtu: %d",
              o->ip.reass.next_index, (u32)(o->ip.reass.estimated_mtu));
    PTAS;
    snprintf (tmpbuf, sizeof(tmpbuf),
              "ip.reass.fragment_first: %d ip.reass.fragment_last: %d",
              (u32)(o->ip.reass.fragment_first),
              (u32)(o->ip.reass.fragment_last));
    PTAS;
    snprintf (tmpbuf, sizeof(tmpbuf),
              "ip.reass.range_first: %d ip.reass.range_last: %d",
              (u32)(o->ip.reass.range_first),
              (u32)(o->ip.reass.range_last));
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "ip.reass.next_range_bi: 0x%x, ip.reass.ip6_frag_hdr_offset: %d",
              o->ip.reass.next_range_bi, 
              (u32)(o->ip.reass.ip6_frag_hdr_offset));
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "mpls.ttl: %d, mpls.exp: %d, mpls.first: %d, "
              "mpls.save_rewrite_length: %d, mpls.bier.n_bytes: %d",
              (u32)(o->mpls.ttl), (u32)(o->mpls.exp), (u32)(o->mpls.first),
              o->mpls.save_rewrite_length, (u32)(o->mpls.bier.n_bytes));
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "l2.feature_bitmap: %08x, l2.bd_index: %d, l2.l2_len: %d, "
              "l2.shg: %d, l2.l2fib_sn: %d, l2.bd_age: %d",
              o->l2.feature_bitmap, (u32)(o->l2.bd_index),
              (u32)(o->l2.l2_len), (u32)(o->l2.shg), (u32)(o->l2.l2fib_sn),
              (u32)(o->l2.bd_age));
    PTAS;
        
    snprintf (tmpbuf, sizeof(tmpbuf),
              "l2t.next_index: %d, l2t.session_index: %d",
              (u32)(o->l2t.next_index), o->l2t.session_index);
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "l2_classify.table_index: %d, l2_classify.opaque_index: %d, "
              "l2_classify.hash: 0x%llx",
              o->l2_classify.table_index,
              o->l2_classify.opaque_index,
              o->l2_classify.hash);
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "policer.index: %d", o->policer.index);
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "ipsec.flags: 0x%x, ipsec.sad_index: %d",
              o->ipsec.flags, o->ipsec.sad_index);
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "map.mtu: %d", (u32)(o->map.mtu));
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "map_t.v6.saddr: 0x%x, map_t.v6.daddr: 0x%x, "
              "map_t.v6.frag_offset: %d, map_t.v6.l4_offset: %d",
              o->map_t.v6.saddr,
              o->map_t.v6.daddr,
              (u32)(o->map_t.v6.frag_offset),
              (u32)(o->map_t.v6.l4_offset));
    PTAS;
    snprintf (tmpbuf, sizeof(tmpbuf),
              "map_t.v6.l4_protocol: %d, map_t.checksum_offset: %d, "
              "map_t.mtu: %d",
              (u32)(o->map_t.v6.l4_protocol),
              (u32)(o->map_t.checksum_offset),
              (u32)(o->map_t.mtu));
    PTAS;
    
    snprintf (tmpbuf, sizeof(tmpbuf),
              "ip_frag.mtu: %d, ip_frag.next_index: %d, ip_frag.flags: 0x%x",
              (u32)(o->ip_frag.mtu),
              (u32)(o->ip_frag.next_index),
              (u32)(o->ip_frag.flags));
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "cop.current_config_index: %d",
              o->cop.current_config_index);
    PTAS;
    
    snprintf (tmpbuf, sizeof(tmpbuf),
              "lisp.overlay_afi: %d",
              (u32)(o->lisp.overlay_afi));
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "tcp.connection_index: %d, tcp.seq_number: %d, tcp.seq_end: %d, "
              "tcp.ack_number: %d, tcp.hdr_offset: %d, tcp.data_offset: %d",
              o->tcp.connection_index,
              o->tcp.seq_number,
              o->tcp.seq_end,
              o->tcp.ack_number,
              (u32)(o->tcp.hdr_offset),
              (u32)(o->tcp.data_offset));
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "tcp.data_len: %d, tcp.flags: 0x%x",
              (u32)(o->tcp.data_len),
              (u32)(o->tcp.flags));
    PTAS;

    snprintf (tmpbuf, sizeof(tmpbuf),
              "sctp.connection_index: %d, sctp.sid: %d, sctp.ssn: %d, "
              "sctp.tsn: %d, sctp.hdr_offset: %d",
              o->sctp.connection_index,
              (u32)(o->sctp.sid),
              (u32)(o->sctp.ssn),
              (u32)(o->sctp.tsn),
              (u32)(o->sctp.hdr_offset));
    PTAS;
    snprintf (tmpbuf, sizeof(tmpbuf),
              "sctp.data_offset: %d, sctp.data_len: %d, sctp.subconn_idx: %d, "
              "sctp.flags: 0x%x",
              (u32)(o->sctp.data_offset),
              (u32)(o->sctp.data_len),
              (u32)(o->sctp.subconn_idx),
              (u32)(o->sctp.flags));
    PTAS;
              
    snprintf (tmpbuf, sizeof(tmpbuf),
              "snat.flags: 0x%x",
              o->snat.flags);
    PTAS;

    return tvb_captured_length(tvb);
}


static int
dissect_vpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *vpp_tree;
    tvbuff_t *opaque_tvb, *eth_tvb, *trace_tvb;
    int         offset   = 0;
    guint8 major_version, minor_version;
    guint8 name_length;
    guint8 *name;
    guint16 trace_length;
    int i, found;
    static const int *buffer_flags[] = {
        &hf_vpp_buffer_flag_non_default_freelist,
        &hf_vpp_buffer_flag_traced,
        &hf_vpp_buffer_flag_next_present,
        &hf_vpp_buffer_flag_total_length_valid,
        &hf_vpp_buffer_flag_ext_hdr_valid,
        &hf_vpp_buffer_flag_l4_checksum_computed,
        &hf_vpp_buffer_flag_l4_checksum_correct,
        &hf_vpp_buffer_flag_vlan_2_deep,
        &hf_vpp_buffer_flag_vlan_1_deep,
        &hf_vpp_buffer_flag_span_clone,
        &hf_vpp_buffer_flag_loop_counter_valid,
        &hf_vpp_buffer_flag_locally_originated,
        &hf_vpp_buffer_flag_is_ip4,
        &hf_vpp_buffer_flag_is_ip6,
        &hf_vpp_buffer_flag_offload_ip_checksum,
        &hf_vpp_buffer_flag_offload_tcp_checksum,
        &hf_vpp_buffer_flag_offload_udp_checksum,
        &hf_vpp_buffer_flag_is_natted,
        &hf_vpp_buffer_flag_l2_hdr_offset_valid,
        &hf_vpp_buffer_flag_l3_hdr_offset_valid,
        &hf_vpp_buffer_flag_l4_hdr_offset_valid,
        &hf_vpp_buffer_flag_flow_report,
        &hf_vpp_buffer_flag_is_dvr,
        &hf_vpp_buffer_flag_qos_data_valid,
        NULL
    };

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "VPP");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_vpp, tvb, offset, -1, ENC_NA);
    vpp_tree = proto_item_add_subtree(ti, ett_vpp);

    major_version = tvb_get_guint8 (tvb, offset);
    offset++;

    minor_version = tvb_get_guint8 (tvb, offset);
    offset++;

    if (major_version != 1 || minor_version != 0)
        ws_debug_printf ("WARNING: version mismatch (%d, %d)",
                         major_version, minor_version);

    /* Skip the buffer index */
    offset += 4;

    /* Recover the node name */
    name_length = tvb_get_guint8 (tvb, offset);
    offset++;

    name = (guint8 *) g_malloc (name_length + 1);
    for (i = 0; i < name_length; i++, offset++) {
        name[i] = tvb_get_guint8 (tvb, offset);
    }
    name[i] = 0;
    offset++;

    proto_tree_add_string(vpp_tree, hf_vpp_nodename, tvb, 5, name_length,
                          name);
    proto_tree_add_item(vpp_tree, hf_vpp_buffer_index, tvb,
                        0 /* bi at offset 0 */, 4, ENC_LITTLE_ENDIAN);

    proto_tree_add_item(vpp_tree, hf_vpp_buffer_current_data, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;
    proto_tree_add_item(vpp_tree, hf_vpp_buffer_current_length, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_bitmask(vpp_tree, tvb, offset,
                           hf_vpp_buffer_flags, ett_vpp,
                           buffer_flags, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vpp_tree, hf_vpp_buffer_flow_id, tvb,
                        offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vpp_tree, hf_vpp_buffer_next_buffer, tvb,
                        offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vpp_tree, hf_vpp_buffer_current_config_index, tvb,
                        offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(vpp_tree, hf_vpp_buffer_error_index, tvb,
                        offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(vpp_tree, hf_vpp_buffer_n_add_refs, tvb,
                        offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    proto_tree_add_item(vpp_tree, hf_vpp_buffer_buffer_pool_index, tvb,
                        offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
    
    opaque_tvb = tvb_new_subset_remaining (tvb, offset);
    call_dissector (vpp_opaque_dissector_handle, opaque_tvb, pinfo, tree);
    
    /* Skip opaque */
    offset += 40;
    /* skip second opaque line */
    offset += 64; 

    trace_length = tvb_get_guint16 (tvb, offset, ENC_LITTLE_ENDIAN);
    offset += 2;

    if (trace_length > 0) {
        trace_tvb = tvb_new_subset_remaining (tvb, offset);
        offset += trace_length;

        call_dissector (vpp_trace_dissector_handle, trace_tvb, pinfo, tree);
    }

    eth_tvb = tvb_new_subset_remaining (tvb, offset);
    
    found = 0;

#define _(a,b,c)                                        \
     {                                                  \
        if (!strcmp (name, a)) {                        \
            call_dissector (c, eth_tvb, pinfo, tree);   \
            found = 1;                                  \
        }                                               \
      }
    foreach_node_to_dissector_handle;
#undef _
    if (found == 0)
        call_dissector (eth_dissector_handle, eth_tvb, pinfo, tree);

    g_free (name);
    return tvb_captured_length(tvb);
}

void
proto_register_vpp(void)
{
  static hf_register_info hf[] = {
      { &hf_vpp_buffer_index,
        { "BufferIndex", "vpp.bufferindex",  FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL },
      },
      { &hf_vpp_nodename,
        { "NodeName", "vpp.nodename",  FT_STRINGZ, BASE_NONE, NULL, 0x0,
          NULL, HFILL },
      },
      { &hf_vpp_buffer_current_data,
        { "CurrentData", "vpp.current_data", FT_INT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL },
      },
      { &hf_vpp_buffer_current_length,
        { "CurrentLength", "vpp.current_length", FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL },
      },

      /* 
       * Warning: buffer flag bits are not cast in concrete, and it's
       * impossible to imagine trying to compile WS with even a subset 
       * of the actual header files. 
       * 
       * See .../src/vlib/buffer.h, .../src/vnet/buffer.h in
       * the fd.io vpp source tree.
       */

      { &hf_vpp_buffer_flags,
        { "BufferFlags", "vpp.flags", FT_UINT32, BASE_HEX, NULL, 0x0,
          NULL, HFILL },
      },

      { &hf_vpp_buffer_flag_non_default_freelist,
        { "NonDefaultFreelist", "vpp.flags.non_default_freelist",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x1, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_traced,
        { "Traced", "vpp.flags.traced",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x2, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_next_present,
        { "NextPresent", "vpp.flags.next_present",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x4, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_total_length_valid,
        { "TotalLengthValid", "vpp.flags.total_length_valid",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x8, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_ext_hdr_valid,
        { "ExtHeaderValid", "vpp.flags.ext_hdr_valid",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x10, NULL, HFILL },
      },

      { &hf_vpp_buffer_flag_l4_checksum_computed,
        { "L4ChecksumComputed", "vpp.flags.l4_checksum_computed",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x80000000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_l4_checksum_correct,
        { "L4ChecksumCorrect", "vpp.flags.l4_checksum_correct",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x40000000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_vlan_2_deep,
        { "Vlan2Deep", "vpp.flags.vlan_2_deep",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x20000000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_vlan_1_deep,
        { "Vlan1Deep", "vpp.flags.vlan_1_deep",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x10000000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_span_clone,
        { "SpanClone", "vpp.flags.span_clone",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x08000000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_loop_counter_valid,
        { "LoopCounterValid", "vpp.flags.loop_counter_valid",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x04000000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_locally_originated,
        { "LocallyOriginated", "vpp.flags.locally_originated",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x02000000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_is_ip4,
        { "IsIP4", "vpp.flags.is_ip4",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x01000000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_is_ip6,
        { "IsIP4", "vpp.flags.is_ip6",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00800000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_offload_ip_checksum,
        { "OffloadIPChecksum", "vpp.flags.offload_ip_checksum",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00400000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_offload_tcp_checksum,
        { "OffloadTCPChecksum", "vpp.flags.offload_tcp_checksum",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00200000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_offload_udp_checksum,
        { "OffloadUDPChecksum", "vpp.flags.offload_udp_checksum",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00100000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_is_natted,
        { "IsNATted", "vpp.flags.is_natted",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00080000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_l2_hdr_offset_valid,
        { "L2HdrOffsetValid", "vpp.flags.l2_hdr_offset_valid",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00040000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_l3_hdr_offset_valid,
        { "L3HdrOffsetValid", "vpp.flags.l3_hdr_offset_valid",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00020000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_l4_hdr_offset_valid,
        { "L4HdrOffsetValid", "vpp.flags.l4_hdr_offset_valid",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00010000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_flow_report,
        { "FlowReport", "vpp.flags.flow_report",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00008000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_is_dvr,
        { "IsDVR", "vpp.flags.is_dvr",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00004000, NULL, HFILL },
      },
      { &hf_vpp_buffer_flag_qos_data_valid,
        { "QOSDataValid", "vpp.flags.qos_data_valid",
          FT_BOOLEAN, 32, TFS(&tfs_true_false), 0x00002000, NULL, HFILL },
      },

      { &hf_vpp_buffer_flow_id,
        { "FlowID", "vpp.flow_id", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL },
      },
      { &hf_vpp_buffer_next_buffer,
        { "NextBuffer", "vpp.next_buffer", FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL },
      },
      { &hf_vpp_buffer_current_config_index,
        { "CurrentConfigIndex", "vpp.current_config_index", 
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL },
      },
      { &hf_vpp_buffer_error_index,
        { "ErrorIndex", "vpp.error_index", 
          FT_UINT16, BASE_DEC, NULL, 0x0,
          NULL, HFILL },
      },
      { &hf_vpp_buffer_n_add_refs,
        { "AddRefs", "vpp.n_add_refs_index", 
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL },
      },
      { &hf_vpp_buffer_buffer_pool_index,
        { "BufferPoolIndex", "vpp.buffer_pool_index", 
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL },
      },
  };

  static hf_register_info opaque_hf[] = {
      { &hf_vpp_buffer_opaque_raw,
        { "Raw   ", "vppMetadata.opaque_raw",  FT_STRINGZ, BASE_NONE, NULL, 0x0,
          NULL, HFILL },
      },
      { &hf_vpp_buffer_opaque_opaque,
        { "Opaque", "vppMetadata.opaque",  
          FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL },
      },
  };

  static hf_register_info trace_hf[] = {
      { &hf_vpp_buffer_trace,
        { "Trace", "vppTrace.trace",  FT_STRINGZ, BASE_NONE, NULL, 0x0,
          NULL, HFILL },
      },
  };

  static gint *ett[] = {
    &ett_vpp,
  };
  static gint *ett_opaque[] = {
    &ett_vpp_opaque,
  };
  static gint *ett_trace[] = {
    &ett_vpp_trace,
  };

  proto_vpp = proto_register_protocol("VPP Buffer Metadata", "VPP", "vpp");
  proto_register_field_array(proto_vpp, hf, array_length(hf));
  proto_register_subtree_array (ett, array_length(ett));
  register_dissector("vpp", dissect_vpp, proto_vpp);

  proto_vpp_opaque = proto_register_protocol("VPP Buffer Opaque", "VPP-Opaque", 
                                             "vpp-opaque");
  proto_register_field_array(proto_vpp_opaque, opaque_hf, 
                             array_length(opaque_hf));
  proto_register_subtree_array (ett_opaque, array_length(ett_opaque));
  register_dissector("vppOpaque", dissect_vpp_opaque, proto_vpp_opaque);

  proto_vpp_trace = proto_register_protocol("VPP Buffer Trace", "VPP-Trace", 
                                             "vpp-trace");
  proto_register_field_array(proto_vpp_trace, trace_hf, 
                             array_length(trace_hf));
  proto_register_subtree_array (ett_trace, array_length(ett_trace));
  register_dissector("vppTrace", dissect_vpp_trace, proto_vpp_trace);
  
#define _(a,b,c) c = find_dissector(b);
  foreach_node_to_dissector_handle;
#undef _
}

void
proto_reg_handoff_vpp(void)
{
    vpp_dissector_handle = find_dissector("vpp");
    vpp_opaque_dissector_handle = find_dissector("vppOpaque");
    vpp_trace_dissector_handle = find_dissector("vppTrace");
    dissector_add_uint("wtap_encap", WTAP_ENCAP_USER13, vpp_dissector_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
