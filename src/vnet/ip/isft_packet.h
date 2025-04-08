#ifndef ISFT_DATA_H
#define ISFT_DATA_H
/*
Space Router -ISFT Module 
This file defines the data structures required by the ISFT module
*/

#include <vlib/vlib.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>

/*
typedef struct {
    // Namespace-ID: 7 bits
    u32 namespace_id : 7;

    // IOAM-Trace-Type: 2 bits
    u32 isft_option_type : 2;//trace、e2e、DEX

    // Flags: 3 bits
    u32 template : 3;

    // Flow ID: 20 bits
    u32 flow_id : 20;

    // Sequence Number: 32 bits
    u32 sequence_number;
} isft_hdr_t;
*/

typedef struct {
    // Namespace-ID: 7 bits
    u32 namespaceid_isftoptiontype_template_flowid;

    // Sequence Number: 32 bits
    u32 sequence_number;
} isft_hdr_t;



/*  

    The format of IOAM header is:

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   | Namespace-ID| O |  T  |                Flow ID                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         Sequence Number                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

typedef struct {
    // Node ID: 16 bits
    u16 node_id;

    // Ingress Port ID: 3 bits
    //u16 ingress_port_id : 3;

    // // Egress Port ID: 3 bits
    //u16 egress_port_id : 3;
   // u16 ingress_egress_port_id;

    //u16 reserved : 10;
    u16 in_eg_re;

    // In TimeStamp: 32 bits
    u32 in_timestamp;

    // Out TimeStamp: 32 bits
    u32 out_timestamp;

    // Forwarding Delay: 32 bits
    u32 forwarding_delay;

    // Queue Depth: 16 bits
    u16 queue_depth;

    // Buffer occupancy: 16 bits
    u16 buffer_occupancy;

    // Checksum Complement: 32 bits
    u32 checksum_complement;
} isft_MD_t;

static f64 isft_tsp_mul[4] = { 1, 1e3, 1e6, 1e9 };

typedef union
{
  u64 ts_u64;
  u32 ts_u32[2];
} isft_time_u64_t;

void determine_node_type(vlib_main_t *vm, vlib_buffer_t *b0, ip6_header_t *ip0);
void generate_isft_header(vlib_main_t *vm, isft_hdr_t *isft_hdr, u8 namespace_id, 
     u8 isft_option_type, u8 template, u32 flow_id, u32 sequence_number);
void extract_isft_header(vlib_main_t *vm, isft_hdr_t *isft_hdr);

void collect_isft_metadata(vlib_main_t *vm, vlib_buffer_t *b0, isft_hdr_t *isft_hdr, isft_MD_t *isft_md);
void create_isft_ipv4_udp_pak(vlib_main_t *vm, vlib_buffer_t *b0, u8 *isft_udp_pak,
                              ip4_address_t src, ip4_address_t collector_IPv6_Addr,
                              u16 src_port, u16 dst_port);
void send_ipv4_packet_to_next_node_with_isft(vlib_main_t *vm, u8 *packet, u16 packet_len);
void create_isft_ipv6_udp_pak (vlib_main_t *vm, vlib_buffer_t *b0, u8 * isft_udp_pak,	
			 ip6_address_t src, ip6_address_t collector_IPv6_Addr,
			 u16 src_port, u16 dst_port);
void send_ipv6_packet_to_next_node_with_isft(vlib_main_t *vm, u8 *packet, u16 packet_len);
void show_isft_hdr (vlib_main_t * vm, isft_hdr_t *isft_hdr);

u8 get_ingress_port_id(vlib_main_t *vm, vlib_buffer_t * b0);
u8 get_egress_port_id(vlib_main_t *vm, vlib_buffer_t * b0);
u32 get_in_timestamp(vlib_main_t *vm, vlib_buffer_t * b0); 
u32 get_eg_timestamp(vlib_main_t *vm);
u16 get_buffer_occupancy(vlib_main_t *vm, vlib_buffer_t * b0);
double get_buffer_occupancy_percent(vlib_main_t * vm, vlib_buffer_t *b0);


/*

        The format of MD data is:

          0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |          node_id              |  in | eg  |     Reserved      |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                         in_timestamp                          |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                         out_timestamp                         |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                         Transit_delay                         |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |          queue_depth          |        buffer_occupancy       |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         |                       checksum_complement                     |
         +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#endif /* ISFT_DATA_H */
