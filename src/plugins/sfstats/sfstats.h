#ifndef SYSTAT_SFSTATS_H
#define SYSTAT_SFSTATS_H

typedef struct {
    u64 ipv4_count;
    u64 ipv6_count;
} sfstats_main_t;

extern sfstats_main_t sfstats_main;


typedef struct {
// Key for ICMPv6 statistics
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

#define ICMP6_FLOWS 10

extern icmp6_stats_t icmp6_stats[ICMP6_FLOWS];

#endif
