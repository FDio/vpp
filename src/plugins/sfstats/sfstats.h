#ifndef SYSTAT_SFSTATS_H
#define SYSTAT_SFSTATS_H

typedef struct
{
  u64 ipv4_count;
  u64 ipv6_count;
} sfstats_main_t;

extern sfstats_main_t sfstats_main;

typedef struct
{
  // Key for ICMPv6 statistics
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  ip6_address_t src_address;
  ip6_address_t dst_address;
  icmp6_type_t type;
  u16 id;

  // Counters for ICMPv6 statistics
  u32 count;
  u32 drop_count; // Count of dropped packets due to sequence mismatch
  u16 last_seq;
  f64 last_update; // Last update time for the statistics
} icmp6_stats_t;

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  ip46_address_t src_address;
  ip46_address_t dst_address;
  u16 src_port;
  u16 dst_port;
  u32 pkts;	   // Total number of TCP packets
  u64 bytes;	   // Total number of bytes in TCP packets
  u32 drop_count;  // Count of dropped packets
  u64 drop_bytes;  // Total number of bytes dropped
  u32 next_seq;	   // Next expected sequence number
  f64 last_update; // Last update time for the statistics
} tcp46_stats_t;

#define TCP4_FLOWS  10
#define TCP6_FLOWS  10
#define ICMP6_FLOWS 10

extern icmp6_stats_t icmp6_stats[ICMP6_FLOWS];
extern tcp46_stats_t tcp4_stats[TCP4_FLOWS];
extern tcp46_stats_t tcp6_stats[TCP6_FLOWS];

#endif
