/* 
 * gpcapng_show.c - PCAPNG file reader and packet display for GENEVE plugin
 *
 * Reads and displays GENEVE tunnel packets from PCAPNG capture files
 */

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vnet/ip/icmp4.h>
#include <vnet/ip/icmp6.h>
#include <vppinfra/error.h>
#include <vlib/vlib.h>

/* PCAPng block types */
#define PCAPNG_BLOCK_TYPE_SHB        0x0A0D0D0A  /* Section Header Block */
#define PCAPNG_BLOCK_TYPE_IDB        0x00000001  /* Interface Description Block */
#define PCAPNG_BLOCK_TYPE_EPB        0x00000006  /* Enhanced Packet Block */
#define PCAPNG_BLOCK_TYPE_SPB        0x00000003  /* Simple Packet Block */

/* Max packet size to read */
#define MAX_PACKET_SIZE 65535

/* GENEVE header structure (must be packed) */
typedef CLIB_PACKED(struct {
  u8 ver_opt_len;      /* Version and option length */
  u8 flags;            /* Flags */
  u16 protocol;        /* Protocol type */
  u8 vni[3];           /* VNI (24 bits) */
  u8 reserved;         /* Reserved */
}) geneve_header_t;

/* GENEVE option structure (must be packed) */
typedef CLIB_PACKED(struct {
  u16 opt_class;       /* Option class */
  u8 type;             /* Type */
  u8 flags_length;     /* Flags (4 bits) and length (4 bits) in 4-byte multiples */
  u8 data[0];          /* Option data (variable length) */
}) geneve_option_t;

/* Structure to hold block reading context */
typedef struct {
  FILE *file;
  u32 position;
  u32 blocktype;
  u32 blocklen;
  u32 next_position;
  u8 *block_data;
} pcapng_read_context_t;

/* Forward declarations for recursive format functions */
static u8 *format_geneve_packet(u8 *s, va_list *args);
static u8 *format_geneve_options(u8 *s, va_list *args);
static u8 *format_inner_packet(u8 *s, va_list *args);

/* Initialize read context */
static pcapng_read_context_t *
init_pcapng_reader(char *filename)
{
  pcapng_read_context_t *ctx;
  
  ctx = clib_mem_alloc(sizeof(pcapng_read_context_t));
  memset(ctx, 0, sizeof(*ctx));
  
  ctx->file = fopen(filename, "rb");
  if (!ctx->file)
    {
      clib_mem_free(ctx);
      return NULL;
    }
    
  ctx->position = 0;
  ctx->next_position = 0;
  
  return ctx;
}

/* Clean up reader context */
static void
cleanup_pcapng_reader(pcapng_read_context_t *ctx)
{
  if (!ctx)
    return;
    
  if (ctx->file)
    fclose(ctx->file);
    
  if (ctx->block_data)
    vec_free(ctx->block_data);
    
  clib_mem_free(ctx);
}

/* Read the next block from the PCAPNG file */
static int
read_next_block(pcapng_read_context_t *ctx)
{
  u32 header[3];  /* blocktype, blocklen, magic/reserved */
  
  if (!ctx || !ctx->file)
    return -1;
    
  /* Free previous block data if any */
  if (ctx->block_data)
    {
      vec_free(ctx->block_data);
      ctx->block_data = NULL;
    }
    
  /* Move to next block position */
  if (fseek(ctx->file, ctx->next_position, SEEK_SET) != 0)
    return -1;
  
  ctx->position = ctx->next_position;
  
  /* Read block header */
  if (fread(header, sizeof(u32), 3, ctx->file) != 3)
    return -1;
    
  /* Store block type and length */
  ctx->blocktype = header[0];
  ctx->blocklen = header[1];
  
  /* Sanity check on block length */
  if (ctx->blocklen < 12 || ctx->blocklen > 100 * 1024 * 1024)
    return -1;
    
  /* Allocate memory for block data */
  vec_validate(ctx->block_data, ctx->blocklen - 1);
  
  /* Reset file position to start of block */
  fseek(ctx->file, ctx->position, SEEK_SET);
  
  /* Read the entire block */
  if (fread(ctx->block_data, 1, ctx->blocklen, ctx->file) != ctx->blocklen)
    return -1;
    
  /* Calculate next block position */
  ctx->next_position = ctx->position + ctx->blocklen;
  
  return 0;
}

/* Get interface name from an IDB block */
static char *
get_interface_name(u8 *block_data, u32 block_len)
{
  u16 option_code, option_len;
  u32 offset = 16;  /* Skip past IDB header */
  static char ifname[256];
  
  /* Default name if not found */
  snprintf(ifname, sizeof(ifname), "unknown");
  
  while (offset + 4 <= block_len)
    {
      option_code = *((u16 *)(block_data + offset));
      option_len = *((u16 *)(block_data + offset + 2));
      
      if (option_code == 2)  /* if_name option */
        {
          if (option_len < sizeof(ifname))
            {
              memcpy(ifname, block_data + offset + 4, option_len);
              ifname[option_len] = '\0';
              return ifname;
            }
        }
      
      /* Move to next option (4-byte aligned) */
      offset += 4 + ((option_len + 3) & ~3);
    }
  
  return ifname;
}

/* Format GENEVE version field */
static u8 *
format_geneve_version(u8 *s, va_list *args)
{
  u8 ver_opt_len = va_arg(*args, int);  /* promoted to int */
  u8 version = (ver_opt_len & 0xC0) >> 6;
  
  return format(s, "%d", version);
}

/* Format GENEVE option length field */
static u8 *
format_geneve_opt_len(u8 *s, va_list *args)
{
  u8 ver_opt_len = va_arg(*args, int);  /* promoted to int */
  u8 opt_len = (ver_opt_len & 0x3F) >> 1;
  
  return format(s, "%d (words), %d (bytes)", opt_len, opt_len * 4);
}

/* Format GENEVE VNI field */
static u8 *
format_geneve_vni(u8 *s, va_list *args)
{
  u8 *vni = va_arg(*args, u8 *);
  u32 vni_value = (((u32)vni[0]) << 16) | (((u32)vni[1]) << 8) | vni[2];
  
  return format(s, "%d (0x%x)", vni_value, vni_value);
}

/* Format GENEVE protocol field */
static u8 *
format_geneve_protocol(u8 *s, va_list *args)
{
  u16 proto = va_arg(*args, int);  /* promoted to int */
  proto = clib_net_to_host_u16(proto);
  
  switch (proto)
    {
    case 0x0800:
      return format(s, "IPv4 (0x0800)");
    case 0x86DD:
      return format(s, "IPv6 (0x86DD)");
    case 0x0806:
      return format(s, "ARP (0x0806)");
    case 0x8100:
      return format(s, "VLAN (0x8100)");
    case 0x88CC:
      return format(s, "LLDP (0x88CC)");
    default:
      return format(s, "0x%04x", proto);
    }
}

/* Format UDP port information */
static u8 *
format_udp_port(u8 *s, va_list *args)
{
  u16 *pport = va_arg(*args, u16 *);  /* promoted to int */
  u16 port = *pport;
  port = clib_net_to_host_u16(port);
  
  switch (port)
    {
    case 6081:
      return format(s, "%d (GENEVE)", port);
    case 4789:
      return format(s, "%d (VXLAN)", port);
    case 8472:
      return format(s, "%d (VXLAN-GPE)", port);
    case 4790:
      return format(s, "%d (VXLAN-NSH)", port);
    case 53:
      return format(s, "%d (DNS)", port);
    case 67:
    case 68:
      return format(s, "%d (DHCP)", port);
    case 80:
      return format(s, "%d (HTTP)", port);
    case 443:
      return format(s, "%d (HTTPS)", port);
    default:
      return format(s, "%d", port);
    }
}

/* Format TCP port information */
static u8 *
format_tcp_port(u8 *s, va_list *args)
{
  u16 *pport = va_arg(*args, u16 *);
  u16 port = *pport;
  port = clib_net_to_host_u16(port);
  
  switch (port)
    {
    case 22:
      return format(s, "%d (SSH)", port);
    case 23:
      return format(s, "%d (Telnet)", port);
    case 80:
      return format(s, "%d (HTTP)", port);
    case 443:
      return format(s, "%d (HTTPS)", port);
    case 179:
      return format(s, "%d (BGP)", port);
    case 389:
      return format(s, "%d (LDAP)", port);
    default:
      return format(s, "%d", port);
    }
}

/* Format GENEVE option */
static u8 *
format_geneve_option(u8 *s, va_list *args)
{
  geneve_option_t *opt = va_arg(*args, geneve_option_t *);
  u16 opt_class = clib_net_to_host_u16(opt->opt_class);
  u8 opt_type = opt->type;
  u8 opt_len = (opt->flags_length & 0x1F) * 4;
  u8 *data = opt->data;
  
  /* Start with basic option information */
  s = format(s, "\n      Option: class=0x%04x, type=0x%02x, length=%d bytes",
             opt_class, opt_type, opt_len);
  
  /* Display data in hex format */
  if (opt_len > 4)
    {
      s = format(s, "\n      Data: ");
      s = format(s, "%U", format_hex_bytes, data, opt_len - 4);
    }
  
  /* Try to interpret some known option types */
  switch (opt_class)
    {
    case 0x0100:
      /* Network virtualization base header - RFC 8926 */
      s = format(s, "\n      Interpretation: Network Virtualization Base Header (RFC 8926)");
      break;
    case 0x0101:
      /* OAM option class */
      s = format(s, "\n      Interpretation: OAM");
      break;
    case 0x0102:
      /* Flow ID option class */
      s = format(s, "\n      Interpretation: Flow Identifier");
      if (opt_len >= 8 && opt_type == 0x01)
        {
          u32 flow_id = clib_net_to_host_u32(*((u32 *)data));
          s = format(s, ", Flow ID: 0x%08x", flow_id);
        }
      break;
    }
  
  return s;
}

/* Format GENEVE options */
static u8 *
format_geneve_options(u8 *s, va_list *args)
{
  u8 *packet_data = va_arg(*args, u8 *);
  u32 data_len = va_arg(*args, u32);
  geneve_header_t *geneve = (geneve_header_t *)packet_data;
  u8 opt_len = ((geneve->ver_opt_len & 0x3F) >> 1) * 4;
  geneve_option_t *opt;
  u32 offset = sizeof(geneve_header_t);
  u32 remaining = opt_len;
  
  if (opt_len == 0 || offset + remaining > data_len)
    return s;
  
  s = format(s, "\n    GENEVE Options:");
  
  while (remaining >= sizeof(geneve_option_t))
    {
      u8 opt_size;
      
      opt = (geneve_option_t *)(packet_data + offset);
      opt_size = (opt->flags_length & 0x1F) * 4;
      
      if (opt_size < sizeof(geneve_option_t) || opt_size > remaining)
        break;
      
      s = format(s, "%U", format_geneve_option, opt);
      
      offset += opt_size;
      remaining -= opt_size;
    }
  
  return s;
}

/* Format TCP flags */
static u8 *
format_tcp_flags(u8 *s, va_list *args)
{
  u8 flags = va_arg(*args, int);  /* promoted to int */
  
  if (flags == 0)
    return format(s, "none");
    
  if (flags & TCP_FLAG_FIN)
    s = format(s, "FIN");
    
  if (flags & TCP_FLAG_SYN)
    s = format(s, "%sSYN", (s[0] != '\0') ? "," : "");
    
  if (flags & TCP_FLAG_RST)
    s = format(s, "%sRST", (s[0] != '\0') ? "," : "");
    
  if (flags & TCP_FLAG_PSH)
    s = format(s, "%sPSH", (s[0] != '\0') ? "," : "");
    
  if (flags & TCP_FLAG_ACK)
    s = format(s, "%sACK", (s[0] != '\0') ? "," : "");
    
  if (flags & TCP_FLAG_URG)
    s = format(s, "%sURG", (s[0] != '\0') ? "," : "");
    
  if (flags & TCP_FLAG_ECE)
    s = format(s, "%sECE", (s[0] != '\0') ? "," : "");
    
  if (flags & TCP_FLAG_CWR)
    s = format(s, "%sCWR", (s[0] != '\0') ? "," : "");
    
  return s;
}

/* Format inner IPv4 packet */
static u8 *
format_inner_ipv4(u8 *s, va_list *args)
{
  u8 *packet_data = va_arg(*args, u8 *);
  u32 data_len = va_arg(*args, u32);
  ip4_header_t *ip = (ip4_header_t *)packet_data;
  u8 hdr_len;
  u8 ip_ver;
  
  if (data_len < sizeof(ip4_header_t))
    return format(s, "\n      [Truncated IPv4 header]");
    
  ip_ver = (ip->ip_version_and_header_length >> 4);
  if (ip_ver != 4)
    return format(s, "\n      [Invalid IPv4 header version: %d]", ip_ver);
    
  hdr_len = (ip->ip_version_and_header_length & 0xF) * 4;
  
  s = format(s, "\n      Inner IPv4: %U -> %U, len=%d, proto=%d",
             format_ip4_address, &ip->src_address,
             format_ip4_address, &ip->dst_address,
             clib_net_to_host_u16(ip->length),
             ip->protocol);
  
  /* Handle inner transport protocols */
  if (data_len >= hdr_len)
    {
      switch (ip->protocol)
        {
        case IP_PROTOCOL_TCP:
          {
            tcp_header_t *tcp = (tcp_header_t *)(packet_data + hdr_len);
            
            if (data_len >= hdr_len + sizeof(tcp_header_t))
              {
                s = format(s, "\n      Inner TCP: src_port=%U, dst_port=%U, flags=%U",
                           format_tcp_port, &tcp->src_port,
                           format_tcp_port, &tcp->dst_port,
                           format_tcp_flags, tcp->flags);
              }
            else
              {
                s = format(s, "\n      [Truncated TCP header]");
              }
          }
          break;
          
        case IP_PROTOCOL_UDP:
          {
            udp_header_t *udp = (udp_header_t *)(packet_data + hdr_len);
            
            if (data_len >= hdr_len + sizeof(udp_header_t))
              {
                s = format(s, "\n      Inner UDP: src_port=%U, dst_port=%U, len=%d",
                           format_udp_port, &udp->src_port,
                           format_udp_port, &udp->dst_port,
                           clib_net_to_host_u16(udp->length));
              }
            else
              {
                s = format(s, "\n      [Truncated UDP header]");
              }
          }
          break;
          
        case IP_PROTOCOL_ICMP:
          {
            icmp46_header_t *icmp = (icmp46_header_t *)(packet_data + hdr_len);
            
            if (data_len >= hdr_len + sizeof(icmp46_header_t))
              {
                s = format(s, "\n      Inner ICMP: type=%d, code=%d",
                           icmp->type, icmp->code);
              }
            else
              {
                s = format(s, "\n      [Truncated ICMP header]");
              }
          }
          break;
          
        default:
          s = format(s, "\n      Inner Protocol %d: %U", 
                     ip->protocol,
                     format_hex_bytes, 
                     packet_data + hdr_len, 
                     data_len - hdr_len);
          break;
        }
    }
  
  return s;
}

/* Format inner IPv6 packet */
static u8 *
format_inner_ipv6(u8 *s, va_list *args)
{
  u8 *packet_data = va_arg(*args, u8 *);
  u32 data_len = va_arg(*args, u32);
  ip6_header_t *ip = (ip6_header_t *)packet_data;
  u8 protocol;
  u16 payload_length;
  
  if (data_len < sizeof(ip6_header_t))
    return format(s, "\n      [Truncated IPv6 header]");
    
  protocol = ip->protocol;
  payload_length = clib_net_to_host_u16(ip->payload_length);
  
  s = format(s, "\n      Inner IPv6: %U -> %U, len=%d, proto=%d",
             format_ip6_address, &ip->src_address,
             format_ip6_address, &ip->dst_address,
             payload_length,
             protocol);
  
  /* Handle inner transport protocols */
  if (data_len >= sizeof(ip6_header_t))
    {
      switch (protocol)
        {
        case IP_PROTOCOL_TCP:
          {
            tcp_header_t *tcp = (tcp_header_t *)(packet_data + sizeof(ip6_header_t));
            
            if (data_len >= sizeof(ip6_header_t) + sizeof(tcp_header_t))
              {
                s = format(s, "\n      Inner TCP: src_port=%U, dst_port=%U, flags=%U",
                           format_tcp_port, &tcp->src_port,
                           format_tcp_port, &tcp->dst_port,
                           format_tcp_flags, tcp->flags);
              }
            else
              {
                s = format(s, "\n      [Truncated TCP header]");
              }
          }
          break;
          
        case IP_PROTOCOL_UDP:
          {
            udp_header_t *udp = (udp_header_t *)(packet_data + sizeof(ip6_header_t));
            
            if (data_len >= sizeof(ip6_header_t) + sizeof(udp_header_t))
              {
                s = format(s, "\n      Inner UDP: src_port=%U, dst_port=%U, len=%d",
                           format_udp_port, &udp->src_port,
                           format_udp_port, &udp->dst_port,
                           clib_net_to_host_u16(udp->length));
              }
            else
              {
                s = format(s, "\n      [Truncated UDP header]");
              }
          }
          break;
          
        case IP_PROTOCOL_ICMP6:
          {
            icmp46_header_t *icmp = (icmp46_header_t *)(packet_data + sizeof(ip6_header_t));
            
            if (data_len >= sizeof(ip6_header_t) + sizeof(icmp46_header_t))
              {
                s = format(s, "\n      Inner ICMPv6: type=%d, code=%d",
                           icmp->type, icmp->code);
              }
            else
              {
                s = format(s, "\n      [Truncated ICMPv6 header]");
              }
          }
          break;
          
        default:
          s = format(s, "\n      Inner Protocol %d: %U", 
                     protocol,
                     format_hex_bytes, 
                     packet_data + sizeof(ip6_header_t), 
                     data_len - sizeof(ip6_header_t));
          break;
        }
    }
  
  return s;
}

/* Format inner packet based on GENEVE protocol field */
static u8 *
format_inner_packet(u8 *s, va_list *args)
{
  u8 *packet_data = va_arg(*args, u8 *);
  u32 data_len = va_arg(*args, u32);
  u16 protocol = va_arg(*args, int);  /* promoted to int */
  protocol = clib_net_to_host_u16(protocol);
  
  switch (protocol)
    {
    case 0x0800:  /* IPv4 */
      s = format(s, "%U", format_inner_ipv4, packet_data, data_len);
      break;
      
    case 0x86DD:  /* IPv6 */
      s = format(s, "%U", format_inner_ipv6, packet_data, data_len);
      break;
      
    case 0x0806:  /* ARP */
      s = format(s, "\n      Inner ARP: %U", 
                 format_hex_bytes, packet_data, data_len);
      break;
      
    default:
      s = format(s, "\n      Inner Protocol 0x%04x: %U", 
                 protocol,
                 format_hex_bytes, packet_data, data_len);
      break;
    }
  
  return s;
}

/* Format GENEVE packet */
static u8 *
format_geneve_packet(u8 *s, va_list *args)
{
  u8 *packet_data = va_arg(*args, u8 *);
  u32 data_len = va_arg(*args, u32);
  ethernet_header_t *eth;
  u16 ethertype;
  
  /* Check for minimum Ethernet header */
  if (data_len < sizeof(ethernet_header_t))
    return format(s, "Truncated Ethernet header");
    
  eth = (ethernet_header_t *)packet_data;
  ethertype = clib_net_to_host_u16(eth->type);
  
  /* Start with Ethernet header */
  s = format(s, "Ethernet: %U -> %U, type=0x%04x\n",
             format_ethernet_address, eth->src_address,
             format_ethernet_address, eth->dst_address,
             ethertype);
  
  /* Skip Ethernet header */
  packet_data += sizeof(ethernet_header_t);
  data_len -= sizeof(ethernet_header_t);
  
  /* Check packet type */
  switch (ethertype)
    {
    case ETHERNET_TYPE_IP4:
      {
        ip4_header_t *ip;
        u8 ip_hdr_len;
        
        if (data_len < sizeof(ip4_header_t))
          return format(s, "  Truncated IPv4 header");
          
        ip = (ip4_header_t *)packet_data;
        ip_hdr_len = (ip->ip_version_and_header_length & 0xF) * 4;
        
        if (ip_hdr_len < sizeof(ip4_header_t) || ip_hdr_len > data_len)
          return format(s, "  Invalid IPv4 header length: %d", ip_hdr_len);
          
        s = format(s, "  IPv4: %U -> %U, len=%d, ttl=%d, protocol=%d\n",
                   format_ip4_address, &ip->src_address,
                   format_ip4_address, &ip->dst_address,
                   clib_net_to_host_u16(ip->length),
                   ip->ttl,
                   ip->protocol);
                   
        /* Check if this is UDP/GENEVE */
        if (ip->protocol == IP_PROTOCOL_UDP)
          {
            udp_header_t *udp;
            geneve_header_t *geneve;
            u32 geneve_hdr_len;
            
            /* Ensure packet has enough data for UDP header */
            if (data_len < ip_hdr_len + sizeof(udp_header_t))
              return format(s, "  Truncated UDP header");
              
            udp = (udp_header_t *)(packet_data + ip_hdr_len);
            
            s = format(s, "  UDP: src_port=%U, dst_port=%U, len=%d, checksum=0x%04x\n",
                       format_udp_port, &udp->src_port,
                       format_udp_port, &udp->dst_port,
                       clib_net_to_host_u16(udp->length),
                       clib_net_to_host_u16(udp->checksum));
                       
            /* Check if this is GENEVE (port 6081) */
            if (clib_net_to_host_u16(udp->dst_port) == 6081)
              {
                /* Ensure packet has enough data for GENEVE header */
                if (data_len < ip_hdr_len + sizeof(udp_header_t) + sizeof(geneve_header_t))
                  return format(s, "  Truncated GENEVE header");
                  
                geneve = (geneve_header_t *)(packet_data + ip_hdr_len + sizeof(udp_header_t));
                geneve_hdr_len = sizeof(geneve_header_t) + (((geneve->ver_opt_len & 0x3F) >> 1) * 4);
                
                s = format(s, "  GENEVE: ver=%U, opt_len=%U, protocol=%U, VNI=%U",
                           format_geneve_version, geneve->ver_opt_len,
                           format_geneve_opt_len, geneve->ver_opt_len,
                           format_geneve_protocol, geneve->protocol,
                           format_geneve_vni, geneve->vni);
                
                /* Format GENEVE options if present */
                if ((geneve->ver_opt_len & 0x3F) != 0)
                  {
                    s = format(s, "%U", format_geneve_options, 
                               packet_data + ip_hdr_len + sizeof(udp_header_t), 
                               data_len - ip_hdr_len - sizeof(udp_header_t));
                  }
                
                /* Format inner packet if there's enough data */
                if (data_len > ip_hdr_len + sizeof(udp_header_t) + geneve_hdr_len)
                  {
                    s = format(s, "%U", format_inner_packet, 
                               packet_data + ip_hdr_len + sizeof(udp_header_t) + geneve_hdr_len,
                               data_len - ip_hdr_len - sizeof(udp_header_t) - geneve_hdr_len,
                               geneve->protocol);
                  }
              }
          }
      }
      break;
      
    case ETHERNET_TYPE_IP6:
      {
        ip6_header_t *ip;
        
        if (data_len < sizeof(ip6_header_t))
          return format(s, "  Truncated IPv6 header");
          
        ip = (ip6_header_t *)packet_data;
        
        s = format(s, "  IPv6: %U -> %U, len=%d, hop_limit=%d, protocol=%d\n",
                   format_ip6_address, &ip->src_address,
                   format_ip6_address, &ip->dst_address,
                   clib_net_to_host_u16(ip->payload_length),
                   ip->hop_limit,
                   ip->protocol);
                   
        /* Check if this is UDP/GENEVE */
        if (ip->protocol == IP_PROTOCOL_UDP)
          {
            udp_header_t *udp;
            geneve_header_t *geneve;
            u32 geneve_hdr_len;
            
            /* Ensure packet has enough data for UDP header */
            if (data_len < sizeof(ip6_header_t) + sizeof(udp_header_t))
              return format(s, "  Truncated UDP header");
              
            udp = (udp_header_t *)(packet_data + sizeof(ip6_header_t));
            
            s = format(s, "  UDP: src_port=%U, dst_port=%U, len=%d, checksum=0x%04x\n",
                       format_udp_port, &udp->src_port,
                       format_udp_port, &udp->dst_port,
                       clib_net_to_host_u16(udp->length),
                       clib_net_to_host_u16(udp->checksum));
                       
            /* Check if this is GENEVE (port 6081) */
            if (clib_net_to_host_u16(udp->dst_port) == 6081)
              {
                /* Ensure packet has enough data for GENEVE header */
                if (data_len < sizeof(ip6_header_t) + sizeof(udp_header_t) + sizeof(geneve_header_t))
                  return format(s, "  Truncated GENEVE header");
                  
                geneve = (geneve_header_t *)(packet_data + sizeof(ip6_header_t) + sizeof(udp_header_t));
                geneve_hdr_len = sizeof(geneve_header_t) + (((geneve->ver_opt_len & 0x3F) >> 1) * 4);
                
                s = format(s, "  GENEVE: ver=%U, opt_len=%U, protocol=%U, VNI=%U",
                           format_geneve_version, geneve->ver_opt_len,
                           format_geneve_opt_len, geneve->ver_opt_len,
                           format_geneve_protocol, geneve->protocol,
                           format_geneve_vni, geneve->vni);
                
                /* Format GENEVE options if present */
                if ((geneve->ver_opt_len & 0x3F) != 0)
                  {
                    s = format(s, "%U", format_geneve_options, 
                               packet_data + sizeof(ip6_header_t) + sizeof(udp_header_t), 
                               data_len - sizeof(ip6_header_t) - sizeof(udp_header_t));
                  }
                
                /* Format inner packet if there's enough data */
                if (data_len > sizeof(ip6_header_t) + sizeof(udp_header_t) + geneve_hdr_len)
                  {
                    s = format(s, "%U", format_inner_packet, 
                               packet_data + sizeof(ip6_header_t) + sizeof(udp_header_t) + geneve_hdr_len,
                               data_len - sizeof(ip6_header_t) - sizeof(udp_header_t) - geneve_hdr_len,
                               geneve->protocol);
                  }
              }
          }
      }
      break;
      
    default:
      s = format(s, "  Unknown EtherType: 0x%04x\n  Data: %U", 
                 ethertype,
                 format_hex_bytes, packet_data, data_len);
      break;
    }
  
  return s;
}

/* Command function for showing PCAPNG files */
static clib_error_t *
gpcapng_show_command_fn (vlib_main_t * vm,
                              unformat_input_t * input,
                              vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  char *filename = NULL;
  pcapng_read_context_t *ctx = NULL;
  u32 packet_count = 0;
  u32 max_packets = ~0;
  u8 verbose = 0;
  
  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected filename");
    
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%s", &filename))
        ;
      else if (unformat (line_input, "max-packets %u", &max_packets))
        ;
      else if (unformat (line_input, "verbose"))
        verbose = 1;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                   format_unformat_error, line_input);
          goto done;
        }
    }
    
  /* Validate inputs */
  if (!filename)
    {
      error = clib_error_return (0, "filename required");
      goto done;
    }
    
  /* Initialize PCAPNG reader */
  ctx = init_pcapng_reader(filename);
  if (!ctx)
    {
      error = clib_error_return (0, "failed to open file: %s", filename);
      goto done;
    }
    
  vlib_cli_output (vm, "Reading GENEVE packets from: %s\n", filename);
  
  /* Mapping from interface index to interface name */
  char *interface_names[256] = {0};
  
  /* Start reading blocks */
  while (read_next_block(ctx) == 0)
    {
      switch (ctx->blocktype)
        {
        case PCAPNG_BLOCK_TYPE_SHB:
          {
            u32 magic = *((u32 *)(ctx->block_data + 8));
            u16 major = *((u16 *)(ctx->block_data + 12));
            u16 minor = *((u16 *)(ctx->block_data + 14));
            
            if (verbose)
              {
                vlib_cli_output (vm, "Section Header Block: magic=0x%08x, version=%d.%d",
                               magic, major, minor);
              }
          }
          break;
          
        case PCAPNG_BLOCK_TYPE_IDB:
          {
            u16 link_type = *((u16 *)(ctx->block_data + 8));
            u32 if_index = *((u32 *)(ctx->block_data + 12));
            char *ifname = get_interface_name(ctx->block_data, ctx->blocklen);
            
            if (if_index < 256)
              {
                if (interface_names[if_index])
                  vec_free(interface_names[if_index]);
                interface_names[if_index] = (char *)format(0, "%s%c", ifname, 0);
              }
              
            if (verbose)
              {
                vlib_cli_output (vm, "Interface Description Block: index=%d, name=%s, link_type=%d",
                               if_index, ifname, link_type);
              }
          }
          break;
          
        case PCAPNG_BLOCK_TYPE_EPB:
          {
            u32 if_index = *((u32 *)(ctx->block_data + 8));
            u32 timestamp_high = *((u32 *)(ctx->block_data + 12));
            u32 timestamp_low = *((u32 *)(ctx->block_data + 16));
            u32 captured_len = *((u32 *)(ctx->block_data + 20));
            u32 packet_len = *((u32 *)(ctx->block_data + 24));
            u64 timestamp = ((u64)timestamp_high << 32) | timestamp_low;
            u8 *packet_data = ctx->block_data + 28;
            char *ifname = "unknown";
            
            if (if_index < 256 && interface_names[if_index])
              ifname = interface_names[if_index];
            
            /* Process only if we haven't reached max packets */
            if (packet_count < max_packets)
              {
                vlib_cli_output (vm, "\nPacket #%d: timestamp=%lu, len=%d, interface=%s (%d)",
                               packet_count + 1, timestamp, packet_len, ifname, if_index);
                
                /* Format the packet */
                vlib_cli_output (vm, "%U", format_geneve_packet, packet_data, captured_len);
                
                packet_count++;
                
                /* Pause every 10 packets for readability */
                if (packet_count % 10 == 0 && packet_count < max_packets)
                  {
                    vlib_cli_output (vm, "\nPress enter to continue...");
                    char c = getchar();
                    (void)c;  /* Avoid unused variable warning */
                  }
              }
          }
          break;
          
        case PCAPNG_BLOCK_TYPE_SPB:
          {
            u32 packet_len = *((u32 *)(ctx->block_data + 4));
            u8 *packet_data = ctx->block_data + 8;
            
            /* Process only if we haven't reached max packets */
            if (packet_count < max_packets)
              {
                vlib_cli_output (vm, "\nPacket #%d: len=%d, interface=unknown (simple packet block)",
                               packet_count + 1, packet_len);
                
                /* Format the packet */
                vlib_cli_output (vm, "%U", format_geneve_packet, packet_data, packet_len);
                
                packet_count++;
                
                /* Pause every 10 packets for readability */
                if (packet_count % 10 == 0 && packet_count < max_packets)
                  {
                    vlib_cli_output (vm, "\nPress enter to continue...");
                    char c = getchar();
                    (void)c;  /* Avoid unused variable warning */
                  }
              }
          }
          break;
          
        default:
          if (verbose)
            {
              vlib_cli_output (vm, "Unknown Block Type: 0x%08x, length=%d",
                             ctx->blocktype, ctx->blocklen);
            }
          break;
        }
        
      /* Stop if we've reached max packets */
      if (packet_count >= max_packets)
        break;
    }
    
  vlib_cli_output (vm, "\nTotal packets displayed: %d", packet_count);
  
  /* Cleanup interface name strings */
  for (int i = 0; i < 256; i++)
    {
      if (interface_names[i])
        vec_free(interface_names[i]);
    }
    
done:
  /* Cleanup */
  if (filename)
    vec_free(filename);
    
  if (ctx)
    cleanup_pcapng_reader(ctx);
    
  unformat_free (line_input);
  return error;
}

/* CLI command to show PCAPNG files */
VLIB_CLI_COMMAND (gpcapng_show_command, static) = {
  .path = "show gpcapng capture",
  .short_help = "show gpcapng capture <filename> [max-packets <count>] [verbose]",
  .function = gpcapng_show_command_fn,
};
