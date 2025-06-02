#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <sfstats/sfstats.h>


sfstats_main_t sfstats_main;
icmp6_stats_t icmp6_stats[ICMP6_FLOWS];

// Commande CLI pour afficher les compteurs
static clib_error_t *
show_sfstats_counters_command_fn(vlib_main_t *vm, unformat_input_t *input, vlib_cli_command_t *cmd) {
    sfstats_main_t *sm = &sfstats_main;

    vlib_cli_output(vm, "IPv4 Packets : %llu", sm->ipv4_count);
    vlib_cli_output(vm, "IPv6 Packets : %llu", sm->ipv6_count);

    for (int i = 0; i < ICMP6_FLOWS; i++) {
        icmp6_stats_t *icmp6_stat = &icmp6_stats[i];
        if (icmp6_stat->count == 0) {
            continue; // Skip empty statistics
        }
        vlib_cli_output(vm, "ICMPv6 Flow %d: Src: %U, Dst: %U, Type: %d, ID: %d, Count: %u, Drop Count: %u",
                        i,
                        format_ip6_address, &icmp6_stat->src_address,
                        format_ip6_address, &icmp6_stat->dst_address,
                        icmp6_stat->type,
                        clib_host_to_net_u16(icmp6_stat->id),
                        icmp6_stat->count,
                        icmp6_stat->drop_count);
    }
    return 0;
}

VLIB_CLI_COMMAND(show_sfstats_counters_command, static) = {
    .path = "show sfstats counters",
    .short_help = "Display flow counters",
    .function = show_sfstats_counters_command_fn,
};


static clib_error_t * sfstats_init(vlib_main_t *vm) {
    sfstats_main_t *sm = &sfstats_main;

    // Initialisation des compteurs
    sm->ipv4_count = 0;
    sm->ipv6_count = 0;


    return NULL;
}

VLIB_INIT_FUNCTION(sfstats_init);

VLIB_PLUGIN_REGISTER() = {
    .version = VPP_BUILD_VER,
    .description = "Plugin to count IPv4 and IPv6 packets and ICMPv6 flows",
};
