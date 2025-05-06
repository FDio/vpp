#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/ethernet/ethernet.h> /* for ethernet_header_t */
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/tcp/tcp_packet.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/vec.h>
#include <vlib/vlib.h>
#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vnet/format_fns.h>
#include <vppinfra/atomics.h>
#include <vlib/unix/unix.h>
#include <vppinfra/random.h>

#include "gpcapng.h"

static u32 random_seed = 42;



/******************************************************************************
 * 5-tuple filter utilities
 ******************************************************************************/

/* Helper functions to parse and format 5-tuple filter data */

/* Convert network prefix to mask */
static void
prefix_to_mask(u8 *mask, u8 is_ipv6, int prefix_len)
{
  int i, bytes;
  
  bytes = is_ipv6 ? 16 : 4;
  
  for (i = 0; i < bytes; i++) {
    if (prefix_len >= 8) {
      mask[i] = 0xFF;
      prefix_len -= 8;
    } else if (prefix_len > 0) {
      mask[i] = (0xFF << (8 - prefix_len));
      prefix_len = 0;
    } else {
      mask[i] = 0;
    }
  }
}

/* Parse IPv4 address with optional prefix */
uword
parse_ipv4_prefix(unformat_input_t *input, va_list * args)
{
  u8 **value = va_arg (*args, u8 **);
  u8 **mask = va_arg (*args, u8 **);
  int offset = va_arg (*args, int);
  ip4_address_t ip4;
  int prefix_len = 32;

  if (unformat(input, "%U/%d", unformat_ip4_address, &ip4, &prefix_len)) {
    /* Address with prefix */
    if (prefix_len > 32) {
      clib_warning("IPv4 prefix length must be <= 32");
      return 0;
      }
  } else if (unformat(input, "%U", unformat_ip4_address, &ip4)) {
    /* Just the address */
  } else {
    clib_warning("Invalid IPv4 address format");
    return 0;
  }
  
  /* Allocate and set value */
  vec_validate(*value, offset+4-1);
  vec_validate(*mask, offset+4-1);
  memcpy(*value + offset, &ip4, 4);
  
  /* Create mask based on prefix length */
  prefix_to_mask(*mask+offset, 0, prefix_len);
  clib_warning("Parsed address: %U prefix len %d", format_ip4_address, &ip4, prefix_len);
  
  return 1;
}

/* Parse IPv6 address with optional prefix */
uword
parse_ipv6_prefix(unformat_input_t *input, va_list * args)
{
  u8 **value = va_arg (*args, u8 **);
  u8 **mask = va_arg (*args, u8 **);
  int offset = va_arg (*args, int);
  ip6_address_t ip6;
  u8 prefix_len = 128;
  
  if (unformat(input, "%U/%d", unformat_ip6_address, &ip6, &prefix_len)) {
    /* Address with prefix */
    if (prefix_len > 128) {
      clib_warning("IPv6 prefix length must be <= 128");
      return 0;
      }
  } else if (unformat(input, "%U", unformat_ip6_address, &ip6)) {
    /* Just the address */
  } else {
    clib_warning("Invalid IPv6 address format");
    return 0;
  }
  
  /* Allocate and set value */
  vec_validate(*value, offset + 16 - 1);
  vec_validate(*mask, offset + 16 - 1);
  memcpy(*value + offset, &ip6, 16);
  
  /* Create mask based on prefix length */
  prefix_to_mask(*mask + offset, 1, prefix_len);
  
  return 1;
}

/* Parse port number or range */
uword
parse_port(unformat_input_t *input, va_list * args)
{
  u8 **value = va_arg (*args, u8 **);
  u8 **mask = va_arg (*args, u8 **);
  uword offset = va_arg (*args, uword);

  u32 port_lo = 0;
  
  if (unformat(input, "%d", &port_lo)) {
    /* the port is two bytes */
    vec_validate(*value, offset+1);
    vec_validate(*mask, offset+1);
    clib_warning("Set offset %d to value %u", offset, port_lo);
    
    /* Store port in network byte order */
    port_lo = clib_host_to_net_u16(port_lo);
    memcpy(*value + offset, &port_lo, 2);
    
    /* Mask is all 1's for exact match */
    memset(*mask + offset, 0xFF, 2);
    
  } else {
    return 0;
  }
  
  return 1;
}

/* Parse protocol number */
uword
parse_protocol(unformat_input_t *input,  va_list * args)
{
  u8 **value = va_arg (*args, u8 **);
  u8 **mask = va_arg (*args, u8 **);
  int offset = va_arg (*args, int);
  clib_warning("protocol offset: %d", offset);
  u32 proto;
  
  if (unformat(input, "tcp")) {
    proto = IP_PROTOCOL_TCP;
  } else if (unformat(input, "udp")) {
    proto = IP_PROTOCOL_UDP;
  } else if (unformat(input, "icmp")) {
    proto = IP_PROTOCOL_ICMP;
  } else if (unformat(input, "icmp6")) {
    proto = IP_PROTOCOL_ICMP6;
  } else if (unformat(input, "%d", &proto)) {
    /* Direct protocol number */
  } else {
    return 0;
  }
  
  vec_validate(*value, offset);
  vec_validate(*mask, offset);
  
  (*value)[offset] = proto;
  (*mask)[offset] = 0xFF;  /* Exact match for protocol */
  
  return 1;
}

/* Parse a raw byte value in hex format */
static clib_error_t *
parse_hex_byte(unformat_input_t *input, u8 **value, u8 **mask, u8 offset, u8 len)
{
  u8 i, byte_val;
  
  vec_validate(*value, offset + len - 1);
  vec_validate(*mask, offset + len - 1);
  
  for (i = 0; i < len; i++) {
    if (!unformat(input, "%x", &byte_val)) {
      return clib_error_return(0, "Invalid hex byte format");
    }
    
    (*value)[offset + i] = byte_val;
    (*mask)[offset + i] = 0xFF;  /* Exact match for hex */
  }
  
  return 0;
}

#define IP4_SRC_IP_OFFSET 12
#define IP4_DST_IP_OFFSET 16
#define IP4_SRC_PORT_OFFSET 20
#define IP4_DST_PORT_OFFSET 22
#define IP4_PROTO_OFFSET 9

/* Create an IPv4 5-tuple filter */
static clib_error_t *
create_ipv4_5tuple_filter(unformat_input_t *input, geneve_tuple_filter_t *filter)
{
  clib_error_t *error = NULL;
  u8 *value = filter->value;
  u8 *mask = filter->mask;

  vec_validate(value, 0);
  vec_validate(mask, 0);

  value[0] = 0x40;
  mask[0] = 0xf0;
  
  /* Parse fields in any order */
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "src-ip %U", parse_ipv4_prefix, &value, &mask, IP4_SRC_IP_OFFSET)) {
      /* Source IP already parsed */
    } else if (unformat(input, "dst-ip %U", parse_ipv4_prefix, &value, &mask, IP4_DST_IP_OFFSET)) {
      /* Destination IP already parsed */
    } else if (unformat(input, "src-port %U", parse_port, &value, &mask, IP4_SRC_PORT_OFFSET)) {
      /* Source port already parsed */
    } else if (unformat(input, "dst-port %U", parse_port, &value, &mask, IP4_DST_PORT_OFFSET)) {
      /* Destination port already parsed */
    } else if (unformat(input, "proto %U", parse_protocol, &value, &mask, IP4_PROTO_OFFSET)) {
      /* Protocol already parsed */
    } else if (unformat(input, "raw %U", parse_hex_byte, &value, &mask, 0, vec_len(value))) {
      /* Raw hex value parsed */
    } else {
      error = clib_error_return(0, "Unknown input: %U", format_unformat_error, input);
      goto done;
    }
  }
  
  /* Store the results */
  filter->value = value;
  filter->mask = mask;
  filter->length = vec_len(value);
  
  return 0;
  
done:
  vec_free(value);
  vec_free(mask);
  return error;
}

#define IP6_SRC_IP_OFFSET 8
#define IP6_DST_IP_OFFSET 24
#define IP6_SRC_PORT_OFFSET 40
#define IP6_DST_PORT_OFFSET 42
#define IP6_PROTO_OFFSET 6

/* Create an IPv6 5-tuple filter */
static clib_error_t *
create_ipv6_5tuple_filter(unformat_input_t *input, geneve_tuple_filter_t *filter)
{
  clib_error_t *error = NULL;
  u8 *value = filter->value;
  u8 *mask = filter->mask;
  
  vec_validate(value, 0);
  vec_validate(mask, 0);
  
  /* Default mask is all 0's (don't care) */
  memset(mask, 0, vec_len(mask));

  /* IPv6 */
  value[0] = 0x60;
  mask[0] = 0xf0;

  
  /* Parse fields in any order */
  while (unformat_check_input(input) != UNFORMAT_END_OF_INPUT) {
    if (unformat(input, "src-ip %U", parse_ipv6_prefix, &value, &mask, IP6_SRC_IP_OFFSET)) {
      /* Source IP already parsed */
    } else if (unformat(input, "dst-ip %U", parse_ipv6_prefix, &value, &mask, IP6_DST_IP_OFFSET)) {
      /* Destination IP already parsed */
    } else if (unformat(input, "src-port %U", parse_port, &value, &mask, IP6_SRC_PORT_OFFSET)) {
      /* Source port already parsed */
    } else if (unformat(input, "dst-port %U", parse_port, &value, &mask, IP6_DST_PORT_OFFSET)) {
      /* Destination port already parsed */
    } else if (unformat(input, "proto %U", parse_protocol, &value, &mask, IP6_PROTO_OFFSET)) {
      /* Protocol already parsed */
    } else if (unformat(input, "raw %U", parse_hex_byte, &value, &mask, 0, vec_len(value))) {
      /* Raw hex value parsed */
    } else {
      error = clib_error_return(0, "Unknown input: %U", format_unformat_error, input);
      goto done;
    }
  }
  
  /* Store the results */
  filter->value = value;
  filter->mask = mask;
  filter->length = vec_len(value);
  
  return 0;
  
done:
  vec_free(value);
  vec_free(mask);
  return error;
}

int
gpcapng_add_filter (u32 sw_if_index, const geneve_capture_filter_t *filter, u8 is_global)
{
  gpcapng_main_t *gpm = get_gpcapng_main();
  geneve_capture_filter_t *new_filter;
  u32 filter_id;
  
  /* For global filter, sw_if_index is ignored */
  if (!is_global) {
    /* Validate sw_if_index */
    if (sw_if_index == ~0)
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
      
    /* Ensure we have space for this interface */
    vec_validate (gpm->per_interface, sw_if_index);
  }
  
  /* Generate a unique filter ID */
  filter_id = random_u32(&random_seed);
  
  /* Add the filter to the appropriate list */
  if (is_global) {
    vec_add2 (gpm->global_filters, new_filter, 1);
  } else {
    vec_add2 (gpm->per_interface[sw_if_index].filters, new_filter, 1);
  }
  
  /* Copy filter data */
  clib_memcpy (new_filter, filter, sizeof (geneve_capture_filter_t));
  new_filter->filter_id = filter_id;
  
  /* Handle option filters */
  if (filter->option_filters)
    {
      int i;
      
      /* Allocate and copy option filters vector */
      vec_validate (new_filter->option_filters, 
                    vec_len (filter->option_filters) - 1);
                    
      for (i = 0; i < vec_len (filter->option_filters); i++)
        {
          clib_memcpy (&new_filter->option_filters[i],
                       &filter->option_filters[i],
                       sizeof (filter->option_filters[i]));
                       
          /* Copy option name if present */
          if (filter->option_filters[i].option_name)
            {
              new_filter->option_filters[i].option_name = 
                vec_dup (filter->option_filters[i].option_name);
            }
            
          /* Copy data and mask if present */
          if (filter->option_filters[i].data)
            {
              new_filter->option_filters[i].data = 
                vec_dup_aligned (filter->option_filters[i].data,
                                 CLIB_CACHE_LINE_BYTES);
            }
            
          if (filter->option_filters[i].mask)
            {
              new_filter->option_filters[i].mask = 
                vec_dup_aligned (filter->option_filters[i].mask,
                                 CLIB_CACHE_LINE_BYTES);
            }
        }
    }
    
  /* Copy 5-tuple filters */
  if (filter->outer_tuple_present)
    {
      new_filter->outer_tuple_present = 1;
      new_filter->outer_tuple.value = vec_dup (filter->outer_tuple.value);
      new_filter->outer_tuple.mask = vec_dup (filter->outer_tuple.mask);
      new_filter->outer_tuple.length = filter->outer_tuple.length;
    }
    
  if (filter->inner_tuple_present)
    {
      new_filter->inner_tuple_present = 1;
      new_filter->inner_tuple.value = vec_dup (filter->inner_tuple.value);
      new_filter->inner_tuple.mask = vec_dup (filter->inner_tuple.mask);
      new_filter->inner_tuple.length = filter->inner_tuple.length;
    }
    
  return filter_id;
}

int
gpcapng_del_filter (u32 sw_if_index, u32 filter_id, u8 is_global)
{
  gpcapng_main_t *gpm = get_gpcapng_main();
  geneve_capture_filter_t *filters;
  int i;
  
  /* Select filter list based on scope */
  if (is_global) {
    filters = gpm->global_filters;
  } else {
    /* Check interface exists */
    if (sw_if_index >= vec_len(gpm->per_interface))
      return VNET_API_ERROR_INVALID_SW_IF_INDEX;
      
    filters = gpm->per_interface[sw_if_index].filters;
  }
  
  /* Find and remove the filter with matching ID */
  for (i = 0; i < vec_len(filters); i++) {
    if (filters[i].filter_id == filter_id) {
      /* Cleanup option filters */
      if (filters[i].option_filters) {
        int j;
        for (j = 0; j < vec_len(filters[i].option_filters); j++) {
          if (filters[i].option_filters[j].option_name)
            vec_free (filters[i].option_filters[j].option_name);
          if (filters[i].option_filters[j].data)
            vec_free (filters[i].option_filters[j].data);
          if (filters[i].option_filters[j].mask)
            vec_free (filters[i].option_filters[j].mask);
        }
        vec_free (filters[i].option_filters);
      }
      
      /* Cleanup 5-tuple filters */
      if (filters[i].outer_tuple_present) {
        vec_free (filters[i].outer_tuple.value);
        vec_free (filters[i].outer_tuple.mask);
      }
      
      if (filters[i].inner_tuple_present) {
        vec_free (filters[i].inner_tuple.value);
        vec_free (filters[i].inner_tuple.mask);
      }
      
      /* Remove the filter from the vector */
      if (is_global) {
        vec_delete (gpm->global_filters, 1, i);
      } else {
        vec_delete (gpm->per_interface[sw_if_index].filters, 1, i);
      }
      
      return 0;
    }
  }
  
  return VNET_API_ERROR_NO_SUCH_ENTRY;
}
typedef enum {
   TUPLE_FILTER_UNKNOWN = 0,
   TUPLE_FILTER_IP4,
   TUPLE_FILTER_IP6,
} tuple_filter_t; 

/* Format a 5-tuple filter for display */
static u8 *
format_tuple_filter (u8 *s, va_list *args)
{
  geneve_tuple_filter_t *filter = va_arg (*args, geneve_tuple_filter_t *);
  int i;
  
  /* Display raw hex values first */
  s = format (s, "        Data bytes (%d): ", vec_len(filter->value));
  for (i = 0; i < vec_len(filter->value); i++)
    {
      s = format (s, "%02x", filter->value[i]);
      if (i < vec_len(filter->value) - 1)
        s = format (s, " ");
    }
  s = format (s, "\n");
  
  s = format (s, "        Mask bytes (%d): ", vec_len(filter->mask));
  for (i = 0; i < vec_len(filter->mask); i++)
    {
      s = format (s, "%02x", filter->mask[i]);
      if (i < vec_len(filter->mask) - 1)
        s = format (s, " ");
    }
  s = format (s, "\n");
  
  /* Try to interpret fields in a meaningful way */
  /* Protocol */
  int proto_offset = 0; /* should be reset from 0 */
  int src_port_offset = 0;
  int dst_port_offset = 0;

  tuple_filter_t filter_type = TUPLE_FILTER_UNKNOWN;
  if (filter->length > 0 && filter->mask[0])
    {
      s = format (s, "       ");
      switch (filter->value[0] & 0xf0) {
         case 0x40:
             s = format (s, "IPv4:\n");
	     proto_offset = IP4_PROTO_OFFSET;
	     src_port_offset = IP4_SRC_PORT_OFFSET;
	     dst_port_offset = IP4_DST_PORT_OFFSET;
	     filter_type = TUPLE_FILTER_IP4;
	     break;
	 case 0x60:
             s = format (s, "IPv6:\n");
	     proto_offset = IP6_PROTO_OFFSET;
	     src_port_offset = IP6_SRC_PORT_OFFSET;
	     dst_port_offset = IP6_DST_PORT_OFFSET;
	     filter_type = TUPLE_FILTER_IP6;
	     break;
      }
    }

  
  /* IP addresses - offset and format based on IPv4 or IPv6 */
  switch (filter_type) {
    case TUPLE_FILTER_IP6:
    {
      /* IPv6 source address (bytes 1-16) */
      u8 has_src_ip = 0;
      for (i = 0; i < 16; i++)
        {
          if (filter->mask[i + IP6_SRC_IP_OFFSET])
            {
              has_src_ip = 1;
              break;
            }
        }
      
      if (has_src_ip)
        {
          ip6_address_t src_ip;
          memcpy (&src_ip, filter->value + IP6_SRC_IP_OFFSET, 16);
          s = format (s, "       Src IP: %U", format_ip6_address, &src_ip);
          
          /* Check for prefix/mask and display it */
          u8 prefix_len = 128;
          for (i = 0; i < 16; i++)
            {
              if (filter->mask[i + IP6_SRC_IP_OFFSET] != 0xFF)
                {
                  if (filter->mask[i + IP6_SRC_IP_OFFSET] == 0)
                    {
                      prefix_len = i * 8;
                      break;
                    }
                  else
                    {
                      /* Calculate bits in this byte */
                      u8 mask = filter->mask[i + 1];
                      u8 bits = 0;
                      while (mask & 0x80)
                        {
                          bits++;
                          mask <<= 1;
                        }
                      prefix_len = i * 8 + bits;
                      break;
                    }
                }
            }
          
          if (prefix_len < 128)
            s = format (s, "/%d", prefix_len);
          s = format (s, "\n");
        }
      
      /* IPv6 destination address (bytes 17-32) */
      u8 has_dst_ip = 0;
      for (i = 0; i < 16; i++)
        {
          if (filter->mask[i + IP6_DST_IP_OFFSET])
            {
              has_dst_ip = 1;
              break;
            }
        }
      
      if (has_dst_ip)
        {
          ip6_address_t dst_ip;
          memcpy (&dst_ip, filter->value + IP6_DST_IP_OFFSET, 16);
          s = format (s, "       Dst IP: %U", format_ip6_address, &dst_ip);
          
          /* Check for prefix/mask and display it */
          u8 prefix_len = 128;
          for (i = 0; i < 16; i++)
            {
              if (filter->mask[i + IP6_DST_IP_OFFSET] != 0xFF)
                {
                  if (filter->mask[i + IP6_DST_IP_OFFSET] == 0)
                    {
                      prefix_len = i * 8;
                      break;
                    }
                  else
                    {
                      /* Calculate bits in this byte */
                      u8 mask = filter->mask[i + IP6_DST_IP_OFFSET];
                      u8 bits = 0;
                      while (mask & 0x80)
                        {
                          bits++;
                          mask <<= 1;
                        }
                      prefix_len = i * 8 + bits;
                      break;
                    }
                }
            }
          
          if (prefix_len < 128)
            s = format (s, "/%d", prefix_len);
          s = format (s, "\n");
        }
      
    }
    break;
  case TUPLE_FILTER_IP4:
    {
      /* IPv4 source address (bytes 1-4) */
      u8 has_src_ip = 0;
      for (i = 0; i < 4; i++)
        {
          if (filter->mask[i + IP4_SRC_IP_OFFSET])
            {
              has_src_ip = 1;
              break;
            }
        }
      
      if (has_src_ip)
        {
          ip4_address_t src_ip;
          memcpy (&src_ip, filter->value + IP4_SRC_IP_OFFSET, 4);
          s = format (s, "      Src IP: %U", format_ip4_address, &src_ip);
          
          /* Check for prefix/mask and display it */
          u8 prefix_len = 32;
          for (i = 0; i < 4; i++)
            {
              if (filter->mask[i + IP4_SRC_IP_OFFSET] != 0xFF)
                {
                  if (filter->mask[i + IP4_SRC_IP_OFFSET] == 0)
                    {
                      prefix_len = i * 8;
                      break;
                    }
                  else
                    {
                      /* Calculate bits in this byte */
                      u8 mask = filter->mask[i + IP4_SRC_IP_OFFSET];
                      u8 bits = 0;
                      while (mask & 0x80)
                        {
                          bits++;
                          mask <<= 1;
                        }
                      prefix_len = i * 8 + bits;
                      break;
                    }
                }
            }
          
          if (prefix_len < 32)
            s = format (s, "/%d", prefix_len);
          s = format (s, "\n");
        }
      
      /* IPv4 destination address (bytes 5-8) */
      u8 has_dst_ip = 0;
      for (i = 0; i < 4; i++)
        {
          if (filter->mask[i + IP4_DST_IP_OFFSET])
            {
              has_dst_ip = 1;
              break;
            }
        }
      
      if (has_dst_ip)
        {
          ip4_address_t dst_ip;
          memcpy (&dst_ip, filter->value + IP4_DST_IP_OFFSET, 4);
          s = format (s, "       Dst IP: %U", format_ip4_address, &dst_ip);
          
          /* Check for prefix/mask and display it */
          u8 prefix_len = 32;
          for (i = 0; i < 4; i++)
            {
              if (filter->mask[i + IP4_DST_IP_OFFSET] != 0xFF)
                {
                  if (filter->mask[i + IP4_DST_IP_OFFSET] == 0)
                    {
                      prefix_len = i * 8;
                      break;
                    }
                  else
                    {
                      /* Calculate bits in this byte */
                      u8 mask = filter->mask[i + IP4_DST_IP_OFFSET];
                      u8 bits = 0;
                      while (mask & 0x80)
                        {
                          bits++;
                          mask <<= 1;
                        }
                      prefix_len = i * 8 + bits;
                      break;
                    }
                }
            }
          
          if (prefix_len < 32)
            s = format (s, "/%d", prefix_len);
          s = format (s, "\n");
        }
    }
    break;
  default:
     /* no IP addresses */
     break;
  }

  if (filter->length > proto_offset  && proto_offset && filter->mask[proto_offset])
    {
      u8 proto = filter->value[proto_offset];
      s = format (s, "       Protocol: ");
      if (proto == IP_PROTOCOL_TCP)
        s = format (s, "TCP (6)\n");
      else if (proto == IP_PROTOCOL_UDP)
        s = format (s, "UDP (17)\n");
      else if (proto == IP_PROTOCOL_ICMP)
        s = format (s, "ICMP (1)\n");
      else if (proto == IP_PROTOCOL_ICMP6)
        s = format (s, "ICMPv6 (58)\n");
      else
        s = format (s, "0x%x (mask 0x%x)\n", proto, filter->mask[proto_offset]);

      /* Ports */
      if (filter->length > src_port_offset+1 && (filter->mask[src_port_offset] || filter->mask[src_port_offset+1]))
        {
          u16 src_port = 0;
          memcpy (&src_port, filter->value + src_port_offset, 2);
          src_port = clib_net_to_host_u16 (src_port);
          s = format (s, "         Src Port(%d): %d\n", src_port_offset, src_port);
        }
      
      if (filter->length > dst_port_offset+1 && (filter->mask[dst_port_offset] || filter->mask[dst_port_offset+1]))
        {
          u16 dst_port = 0;
          memcpy (&dst_port, filter->value + dst_port_offset, 2);
          dst_port = clib_net_to_host_u16 (dst_port);
          s = format (s, "         Dst Port(%d): %d\n", dst_port_offset, dst_port);
        }
    }
  
  return s;
}

/* Register with preferred data type */
void
gpcapng_register_option_def (const char *name, u16 class, u8 type, u8 length,
                                  geneve_opt_data_type_t preferred_type)
{
  gpcapng_main_t *gpm = get_gpcapng_main();
  geneve_option_def_t opt_def = {0};
  u64 key;
  u32 index;
  
  /* Create option definition */
  opt_def.option_name = (void *)format (0, "%s%c", name, 0);
  opt_def.opt_class = class;
  opt_def.type = type;
  opt_def.length = length;
  opt_def.preferred_type = preferred_type;
  
  /* Add to vector */
  index = vec_len (gpm->option_defs);
  vec_add1 (gpm->option_defs, opt_def);
  
  /* Add to hash tables */
  hash_set_mem (gpm->option_by_name, opt_def.option_name, index);
  
  key = ((u64)class << 8) | type;
  hash_set (gpm->option_by_class_type, key, index);
}

/* 
 * Helper function to parse option data based on type
 */
static clib_error_t *
parse_option_data (unformat_input_t * input, geneve_opt_data_type_t type,
                  u8 **data, u8 data_len)
{
  ip4_address_t ip4;
  ip6_address_t ip6;
  u32 value32;
  u16 value16;
  u8 value8;
  u8 *s = 0;
  u8 *raw_data = 0;
  u8 byte_val;
  int i;
  
  switch (type)
    {
    case GENEVE_OPT_TYPE_IPV4:
      if (unformat (input, "%U", unformat_ip4_address, &ip4))
        {
          *data = vec_new (u8, 4);
          clib_memcpy (*data, &ip4, 4);
          return 0;
        }
      return clib_error_return (0, "invalid IPv4 address format");
      
    case GENEVE_OPT_TYPE_IPV6:
      if (unformat (input, "%U", unformat_ip6_address, &ip6))
        {
          *data = vec_new (u8, 16);
          clib_memcpy (*data, &ip6, 16);
          return 0;
        }
      return clib_error_return (0, "invalid IPv6 address format");
      
    case GENEVE_OPT_TYPE_UINT8:
      if (unformat (input, "%u", &value32) && value32 <= 255)
        {
          value8 = (u8)value32;
          *data = vec_new (u8, 1);
          clib_memcpy (*data, &value8, 1);
          return 0;
        }
      return clib_error_return (0, "invalid 8-bit integer format");
      
    case GENEVE_OPT_TYPE_UINT16:
      if (unformat (input, "%u", &value32) && value32 <= 65535)
        {
          value16 = (u16)value32;
          value16 = clib_host_to_net_u16 (value16);
          *data = vec_new (u8, 2);
          clib_memcpy (*data, &value16, 2);
          return 0;
        }
      return clib_error_return (0, "invalid 16-bit integer format");
      
    case GENEVE_OPT_TYPE_UINT32:
      if (unformat (input, "%u", &value32))
        {
          value32 = clib_host_to_net_u32 (value32);
          *data = vec_new (u8, 4);
          clib_memcpy (*data, &value32, 4);
          return 0;
        }
      return clib_error_return (0, "invalid 32-bit integer format");
      
    case GENEVE_OPT_TYPE_STRING:
      if (unformat (input, "%v", &s))
        {
          /* Limit string to data_len - 1 (for NULL terminator) */
          if (vec_len (s) > data_len - 1)
            vec_set_len (s, data_len - 1);
          
          /* Allocate data vector and copy string with NULL terminator */
          *data = vec_new (u8, data_len);
          clib_memset (*data, 0, data_len);
          clib_memcpy (*data, s, vec_len (s));
          vec_free (s);
          return 0;
        }
      return clib_error_return (0, "invalid string format");
      
    case GENEVE_OPT_TYPE_RAW:
      /* Format: "HH HH HH ..." where HH is a hex byte */
      raw_data = vec_new (u8, data_len);
      clib_memset (raw_data, 0, data_len);
      
      for (i = 0; i < data_len; i++)
        {
          if (!unformat (input, "%x", &byte_val))
            {
              vec_free (raw_data);
              return clib_error_return (0, 
                "invalid raw format, expected %d hex bytes", data_len);
            }
          raw_data[i] = byte_val;
        }
      *data = raw_data;
      return 0;
      
    default:
      return clib_error_return (0, "unsupported option data type");
    }
}

static clib_error_t *
gpcapng_filter_command_fn (vlib_main_t * vm,
                                unformat_input_t * input,
                                vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  vnet_main_t *vnm = vnet_get_main ();
  gpcapng_main_t *gpm = get_gpcapng_main();
  clib_error_t *error = NULL;
  geneve_capture_filter_t filter = {0};
  u32 sw_if_index = ~0;
  u8 is_add = 1;
  u8 is_global = 0;
  u32 filter_id = ~0;
  char * option_name = 0;
  char * filter_name = 0;
  unformat_input_t sub_input;
  // needed for HTTP but not here. enable_session_manager (vm);

  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");
    
  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "interface %U",
                   unformat_vnet_sw_interface, vnm, &sw_if_index))
        ;
      else if (unformat (line_input, "name %s", &filter_name))
        filter.name = filter_name;
      else if (unformat (line_input, "global"))
        is_global = 1;
      else if (unformat (line_input, "del"))
        is_add = 0;
      else if (unformat (line_input, "id %d", &filter_id))
        ;
      else if (unformat (line_input, "ver %d", &filter.ver))
        filter.ver_present = 1;
      else if (unformat (line_input, "opt-len %d", &filter.opt_len))
        filter.opt_len_present = 1;
      else if (unformat (line_input, "protocol %d", &filter.protocol))
        filter.proto_present = 1;
      else if (unformat (line_input, "vni %d", &filter.vni))
        filter.vni_present = 1;
      else if (unformat (line_input, "outer-ipv4 %U", 
                        unformat_vlib_cli_sub_input, &sub_input))
        {
	  error = create_ipv4_5tuple_filter(&sub_input, &filter.outer_tuple);
	  if (error)
	  	goto done;
          filter.outer_tuple_present = 1;
        }
      else if (unformat (line_input, "outer-ipv6 %U", 
                        unformat_vlib_cli_sub_input, &sub_input))
        {
	  error = create_ipv6_5tuple_filter(&sub_input, &filter.outer_tuple);
	  if (error)
	  	goto done;
          filter.outer_tuple_present = 1;
        }
      else if (unformat (line_input, "inner-ipv4 %U", 
                        unformat_vlib_cli_sub_input, &sub_input))
        {
	  error = create_ipv4_5tuple_filter(&sub_input, &filter.inner_tuple);
	  if (error)
	  	goto done;
          filter.inner_tuple_present = 1;
        }
      else if (unformat (line_input, "inner-ipv6 %U", 
                        unformat_vlib_cli_sub_input, &sub_input))
        {
	  error = create_ipv6_5tuple_filter(&sub_input, &filter.inner_tuple);
	  if (error)
	  	goto done;
          filter.inner_tuple_present = 1;
        }
      else if (unformat (line_input, "option %s", &option_name))
        {
          /* Create option filter */
          geneve_option_filter_t opt_filter = {0};
          
          uword *p;
          
          /* Look up the option by name */
          p = hash_get_mem (gpm->option_by_name, option_name);
          if (!p)
            {
              error = clib_error_return (0, "unknown option name: %s",
                                        option_name);
              goto done;
            }
            
          const geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
          opt_filter.present = 1;
          opt_filter.option_name = vec_dup (option_name);
          
          /* Check if next token is "any" */
          if (unformat (line_input, "any"))
            {
              opt_filter.match_any = 1;
            }
          else if (unformat (line_input, "value"))
            {
              geneve_opt_data_type_t data_type = opt_def->preferred_type;
              
              /* Check for explicit type specification */
              if (unformat (line_input, "raw"))
                data_type = GENEVE_OPT_TYPE_RAW;
              else if (unformat (line_input, "ipv4"))
                data_type = GENEVE_OPT_TYPE_IPV4;
              else if (unformat (line_input, "ipv6"))
                data_type = GENEVE_OPT_TYPE_IPV6;
              else if (unformat (line_input, "uint8"))
                data_type = GENEVE_OPT_TYPE_UINT8;
              else if (unformat (line_input, "uint16"))
                data_type = GENEVE_OPT_TYPE_UINT16;
              else if (unformat (line_input, "uint32"))
                data_type = GENEVE_OPT_TYPE_UINT32;
              else if (unformat (line_input, "string"))
                data_type = GENEVE_OPT_TYPE_STRING;
                
              /* Parse the option data based on type */
              opt_filter.data_len = opt_def->length;
              error = parse_option_data (line_input, data_type, 
                                        &opt_filter.data, opt_filter.data_len);
              if (error)
                goto done;
                
              /* Check for mask */
              if (unformat (line_input, "mask"))
                {
                  error = parse_option_data (line_input, GENEVE_OPT_TYPE_RAW,
                                           &opt_filter.mask, opt_filter.data_len);
                  if (error)
                    goto done;
                }
            }
          else
            {
              /* Default to match any if no value provided */
              opt_filter.match_any = 1;
            }
            
          /* Add the option filter to the vector */
          vec_add1 (filter.option_filters, opt_filter);
        }
      else if (unformat (line_input, "option-direct class %d type %d", 
                        &filter.option_filters->opt_class, 
                        &filter.option_filters->type))
        {
          /* Direct specification of option class/type */
          geneve_option_filter_t opt_filter = {0};
          
          u64 key;
          uword *p;
          
          opt_filter.present = 1;
          opt_filter.opt_class = filter.option_filters->opt_class;
          opt_filter.type = filter.option_filters->type;
          
          /* Try to find registered option info */
          key = ((u64)opt_filter.opt_class << 8) | opt_filter.type;
          p = hash_get (gpm->option_by_class_type, key);
          
          if (p)
            {
              /* Option is registered */
              const geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
              
              /* Check if next token is "any" */
              if (unformat (line_input, "any"))
                {
                  opt_filter.match_any = 1;
                }
              else if (unformat (line_input, "value"))
                {
                  geneve_opt_data_type_t data_type = opt_def->preferred_type;
                  
                  /* Check for explicit type specification */
                  if (unformat (line_input, "raw"))
                    data_type = GENEVE_OPT_TYPE_RAW;
                  else if (unformat (line_input, "ipv4"))
                    data_type = GENEVE_OPT_TYPE_IPV4;
                  else if (unformat (line_input, "ipv6"))
                    data_type = GENEVE_OPT_TYPE_IPV6;
                  else if (unformat (line_input, "uint8"))
                    data_type = GENEVE_OPT_TYPE_UINT8;
                  else if (unformat (line_input, "uint16"))
                    data_type = GENEVE_OPT_TYPE_UINT16;
                  else if (unformat (line_input, "uint32"))
                    data_type = GENEVE_OPT_TYPE_UINT32;
                  else if (unformat (line_input, "string"))
                    data_type = GENEVE_OPT_TYPE_STRING;
                    
                  /* Parse the option data based on type */
                  opt_filter.data_len = opt_def->length;
                  error = parse_option_data (line_input, data_type, 
                                            &opt_filter.data, opt_filter.data_len);
                  if (error)
                    goto done;
                    
                  /* Check for mask */
                  if (unformat (line_input, "mask"))
                    {
                      error = parse_option_data (line_input, GENEVE_OPT_TYPE_RAW,
                                              &opt_filter.mask, opt_filter.data_len);
                      if (error)
                        goto done;
                    }
                }
              else
                {
                  /* Default to match any if no value provided */
                  opt_filter.match_any = 1;
                }
            }
          else
            {
              /* Option is not registered, handle raw data */
              if (unformat (line_input, "any"))
                {
                  opt_filter.match_any = 1;
                }
              else if (unformat (line_input, "length %d", &opt_filter.data_len))
                {
                  if (unformat (line_input, "value"))
                    {
                      error = parse_option_data (line_input, GENEVE_OPT_TYPE_RAW,
                                              &opt_filter.data, opt_filter.data_len);
                      if (error)
                        goto done;
                        
                      /* Check for mask */
                      if (unformat (line_input, "mask"))
                        {
                          error = parse_option_data (line_input, GENEVE_OPT_TYPE_RAW,
                                                &opt_filter.mask, opt_filter.data_len);
                          if (error)
                            goto done;
                        }
                    }
                  else
                    {
                      /* Default to match any if no value provided */
                      opt_filter.match_any = 1;
                    }
                }
              else
                {
                  /* No length specified, default to match any */
                  opt_filter.match_any = 1;
                }
            }
            
          /* Add the option filter to the vector */
          vec_add1 (filter.option_filters, opt_filter);
        }
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, line_input);
          goto done;
        }
    }

  if (!filter_name)
    {
      error = clib_error_return (0, "filter name is required");
      goto done;
    }
    
  /* Validate inputs */
  if (!is_global && sw_if_index == ~0)
    {
      error = clib_error_return (0, "interface required for interface filter");
      goto done;
    }
    
  if (!is_add && filter_id == ~0)
    {
      error = clib_error_return (0, "filter id required for delete");
      goto done;
    }
    
  /* Add/delete filter */
  if (is_add)
    {
      filter_id = gpcapng_add_filter (sw_if_index, &filter, is_global);
      if (filter_id < 0)
        {
          error = clib_error_return (0, "failed to add filter");
          goto done;
        }
        
      vlib_cli_output (vm, "Added GENEVE %s filter with ID: %d", 
                      is_global ? "global" : "interface", filter_id);
    }
  else
    {
      int rv = gpcapng_del_filter (sw_if_index, filter_id, is_global);
      if (rv < 0)
        {
          error = clib_error_return (0, "failed to delete filter (id: %d)", filter_id);
          goto done;
        }
        
      vlib_cli_output (vm, "Deleted GENEVE %s filter with ID: %d", 
                      is_global ? "global" : "interface", filter_id);
    }
    
done:
  /* Cleanup if error */
  if (error && is_add)
    {
      /* Clean up filter resources */
      if (filter.option_filters)
        {
          int i;
          for (i = 0; i < vec_len (filter.option_filters); i++)
            {
              if (filter.option_filters[i].option_name)
                vec_free (filter.option_filters[i].option_name);
              if (filter.option_filters[i].data)
                vec_free (filter.option_filters[i].data);
              if (filter.option_filters[i].mask)
                vec_free (filter.option_filters[i].mask);
            }
          vec_free (filter.option_filters);
        }
        
      if (filter.outer_tuple_present)
        {
          vec_free (filter.outer_tuple.value);
          vec_free (filter.outer_tuple.mask);
        }
        
      if (filter.inner_tuple_present)
        {
          vec_free (filter.inner_tuple.value);
          vec_free (filter.inner_tuple.mask);
        }
    }
    
  unformat_free (line_input);
  return error;
}

/* Updated CLI command for better help text */
VLIB_CLI_COMMAND (gpcapng_filter_command, static) = {
  .path = "gpcapng filter",
  .short_help = "gpcapng filter name <filtername> [interface <interface> | global] "
                "[ver <ver>] [opt-len <len>] [protocol <proto>] [vni <vni>] "
                "[outer-ipv4 | outer-ipv6 | inner-ipv4 | inner-ipv6] "
                "[option <name> [any|value [raw|ipv4|ipv6|uint8|uint16|uint32|string] <data> [mask <mask>]]] "
                "[option-direct class <class> type <type> [any|value [raw|ipv4|ipv6|uint8|uint16|uint32|string] <data> [mask <mask>]]] "
                "[del id <id>]",
  .function = gpcapng_filter_command_fn,
};

/* Updated option registrations with preferred types */
static void
register_default_options (void)
{
  /* Register some basic GENEVE option definitions with preferred types */
  gpcapng_register_option_def ("vpp-metadata", 0x0123, 0x01, 8, GENEVE_OPT_TYPE_UINT32);
  gpcapng_register_option_def ("legacy-oam", 0x0F0F, 0x01, 4, GENEVE_OPT_TYPE_UINT32);
  gpcapng_register_option_def ("tenant-ip", 0x0124, 0x02, 4, GENEVE_OPT_TYPE_IPV4);
  gpcapng_register_option_def ("tenant-ipv6", 0x0124, 0x03, 16, GENEVE_OPT_TYPE_IPV6);
  gpcapng_register_option_def ("flow-id", 0x0125, 0x01, 4, GENEVE_OPT_TYPE_UINT32);
  gpcapng_register_option_def ("app-id", 0x0125, 0x02, 2, GENEVE_OPT_TYPE_UINT16);
  gpcapng_register_option_def ("service-tag", 0x0126, 0x01, 8, GENEVE_OPT_TYPE_STRING);
}

static clib_error_t *
gpcapng_register_option_command_fn (vlib_main_t * vm,
                                         unformat_input_t * input,
                                         vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  clib_error_t *error = NULL;
  u8 *name = NULL;
  u32 opt_class = 0;
  u32 type = 0;
  u32 length = 0;
  geneve_opt_data_type_t data_type = GENEVE_OPT_TYPE_RAW;

  /* Get a line of input */
  if (!unformat_user (input, unformat_line_input, line_input))
    return clib_error_return (0, "expected arguments");

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "name %s", &name))
        ;
      else if (unformat (line_input, "class %d", &opt_class))
        ;
      else if (unformat (line_input, "type %d", &type))
        ;
      else if (unformat (line_input, "length %d", &length))
        ;
      else if (unformat (line_input, "data-type raw"))
        data_type = GENEVE_OPT_TYPE_RAW;
      else if (unformat (line_input, "data-type ipv4"))
        data_type = GENEVE_OPT_TYPE_IPV4;
      else if (unformat (line_input, "data-type ipv6"))
        data_type = GENEVE_OPT_TYPE_IPV6;
      else if (unformat (line_input, "data-type uint8"))
        data_type = GENEVE_OPT_TYPE_UINT8;
      else if (unformat (line_input, "data-type uint16"))
        data_type = GENEVE_OPT_TYPE_UINT16;
      else if (unformat (line_input, "data-type uint32"))
        data_type = GENEVE_OPT_TYPE_UINT32;
      else if (unformat (line_input, "data-type string"))
        data_type = GENEVE_OPT_TYPE_STRING;
      else
        {
          error = clib_error_return (0, "unknown input '%U'",
                                    format_unformat_error, line_input);
          goto done;
        }
    }

  /* Validate inputs */
  if (name == NULL)
    {
      error = clib_error_return (0, "option name required");
      goto done;
    }

  if (length == 0)
    {
      error = clib_error_return (0, "length must be greater than 0");
      goto done;
    }

  /* Validate data type against length */
  switch (data_type)
    {
    case GENEVE_OPT_TYPE_IPV4:
      if (length < 4)
        {
          error = clib_error_return (0, "length must be at least 4 bytes for IPv4 data type");
          goto done;
        }
      break;

    case GENEVE_OPT_TYPE_IPV6:
      if (length < 16)
        {
          error = clib_error_return (0, "length must be at least 16 bytes for IPv6 data type");
          goto done;
        }
      break;

    case GENEVE_OPT_TYPE_UINT8:
      if (length < 1)
        {
          error = clib_error_return (0, "length must be at least 1 byte for uint8 data type");
          goto done;
        }
      break;

    case GENEVE_OPT_TYPE_UINT16:
      if (length < 2)
        {
          error = clib_error_return (0, "length must be at least 2 bytes for uint16 data type");
          goto done;
        }
      break;

    case GENEVE_OPT_TYPE_UINT32:
      if (length < 4)
        {
          error = clib_error_return (0, "length must be at least 4 bytes for uint32 data type");
          goto done;
        }
      break;

    case GENEVE_OPT_TYPE_STRING:
      /* Strings need at least 1 byte for the null terminator */
      if (length < 1)
        {
          error = clib_error_return (0, "length must be at least 1 byte for string data type");
          goto done;
        }
      break;

    default:
      /* Raw type has no constraints */
      break;
    }

  /* Register the option */
  gpcapng_register_option_def ((char *)name, opt_class, type, length, data_type);
  vlib_cli_output (vm, "Registered GENEVE option: name=%s, class=0x%x, type=0x%x, length=%d, data-type=%s",
                  name, opt_class, type, length,
                  data_type == GENEVE_OPT_TYPE_RAW ? "raw" :
                  data_type == GENEVE_OPT_TYPE_IPV4 ? "ipv4" :
                  data_type == GENEVE_OPT_TYPE_IPV6 ? "ipv6" :
                  data_type == GENEVE_OPT_TYPE_UINT8 ? "uint8" :
                  data_type == GENEVE_OPT_TYPE_UINT16 ? "uint16" :
                  data_type == GENEVE_OPT_TYPE_UINT32 ? "uint32" :
                  data_type == GENEVE_OPT_TYPE_STRING ? "string" : "unknown");

done:
  unformat_free (line_input);
  return error;
}

/* Helper function to format data type as string */
static u8 *
format_geneve_data_type (u8 * s, va_list * args)
{
  geneve_opt_data_type_t type = va_arg (*args, int);  /* enum is promoted to int */

  switch (type)
    {
    case GENEVE_OPT_TYPE_RAW:
      return format (s, "raw");
    case GENEVE_OPT_TYPE_IPV4:
      return format (s, "ipv4");
    case GENEVE_OPT_TYPE_IPV6:
      return format (s, "ipv6");
    case GENEVE_OPT_TYPE_UINT8:
      return format (s, "uint8");
    case GENEVE_OPT_TYPE_UINT16:
      return format (s, "uint16");
    case GENEVE_OPT_TYPE_UINT32:
      return format (s, "uint32");
    case GENEVE_OPT_TYPE_STRING:
      return format (s, "string");
    default:
      return format (s, "unknown");
    }
}

/* Show registered GENEVE options */
static clib_error_t *
gpcapng_show_options_command_fn (vlib_main_t * vm,
                                      unformat_input_t * input,
                                      vlib_cli_command_t * cmd)
{
  gpcapng_main_t *gpm = get_gpcapng_main();
  u32 i;

  vlib_cli_output (vm, "Registered GENEVE options:");
  vlib_cli_output (vm, "%-20s %-10s %-10s %-10s %s",
                  "Name", "Class", "Type", "Length", "Data Type");
  vlib_cli_output (vm, "%-20s %-10s %-10s %-10s %s",
                  "--------------------", "----------", "----------", "----------", "----------");

  /* Display all registered options */
  for (i = 0; i < vec_len (gpm->option_defs); i++)
    {
      geneve_option_def_t *opt = &gpm->option_defs[i];
      vlib_cli_output (vm, "%-20s 0x%-8x %-10u %-10u %U",
                      opt->option_name, opt->opt_class, opt->type, opt->length,
                      format_geneve_data_type, opt->preferred_type);
    }

  return 0;
}

/* Helper function to format option data based on its type */
static u8 *
format_option_data (u8 * s, va_list * args)
{
  u8 *data = va_arg (*args, u8 *);
  u8 data_len = va_arg (*args, int);  /* promoted to int */
  geneve_opt_data_type_t type = va_arg (*args, int);  /* enum promoted to int */
  
  if (!data || data_len == 0)
    return format (s, "(empty)");
    
  switch (type)
    {
    case GENEVE_OPT_TYPE_IPV4:
      {
        ip4_address_t *ip4 = (ip4_address_t *)data;
        return format (s, "%U", format_ip4_address, ip4);
      }
      
    case GENEVE_OPT_TYPE_IPV6:
      {
        ip6_address_t *ip6 = (ip6_address_t *)data;
        return format (s, "%U", format_ip6_address, ip6);
      }
      
    case GENEVE_OPT_TYPE_UINT8:
      {
        u8 val = data[0];
        return format (s, "%u", val);
      }
      
    case GENEVE_OPT_TYPE_UINT16:
      {
        u16 val = clib_net_to_host_u16(*(u16 *)data);
        return format (s, "%u", val);
      }
      
    case GENEVE_OPT_TYPE_UINT32:
      {
        u32 val = clib_net_to_host_u32(*(u32 *)data);
        return format (s, "%u", val);
      }
      
    case GENEVE_OPT_TYPE_STRING:
      {
        /* Ensure null-termination */
        char *str = (char *)vec_dup (data);
        str[data_len - 1] = '\0';
        s = format (s, "\"%s\"", str);
        vec_free (str);
        return s;
      }
      
    case GENEVE_OPT_TYPE_RAW:
    default:
      {
        /* Display as hex bytes */
        int i;
        for (i = 0; i < data_len; i++)
          {
            s = format (s, "%02x", data[i]);
            if (i < data_len - 1)
              s = format (s, " ");
          }
        return s;
      }
    }
}

/* Show active GENEVE capture filters */
static clib_error_t *
gpcapng_show_filters_command_fn (vlib_main_t * vm,
                                      unformat_input_t * input,
                                      vlib_cli_command_t * cmd)
{
  gpcapng_main_t *gpm = get_gpcapng_main();
  u32 sw_if_index;
  u32 i, j;
  int filters_displayed = 0;
  
  vlib_cli_output (vm, "GENEVE Capture Filters:");
  
  /* Display global filters first */
  if (vec_len (gpm->global_filters) > 0)
    {
      vlib_cli_output (vm, "\nGlobal Filters:");
      
      for (i = 0; i < vec_len (gpm->global_filters); i++)
        {
          geneve_capture_filter_t *filter = &gpm->global_filters[i];
          
          vlib_cli_output (vm, "  Filter Name: %s", filter->name);
          vlib_cli_output (vm, "  Filter ID: %u", filter->filter_id);
          vlib_cli_output (vm, "  Destination Output Index: %u", filter->destination_index);
          
          /* Basic header filters */
          if (filter->ver_present)
            vlib_cli_output (vm, "    Version: %u", filter->ver);
            
          if (filter->opt_len_present)
            vlib_cli_output (vm, "    Option Length: %u", filter->opt_len);
            
          if (filter->proto_present)
            vlib_cli_output (vm, "    Protocol: 0x%04x", filter->protocol);
            
          if (filter->vni_present)
            vlib_cli_output (vm, "    VNI: %u", filter->vni);
            
          /* 5-tuple filters */
          if (filter->outer_tuple_present)
            {
              vlib_cli_output (vm, "    Outer 5-tuple filter:");
              vlib_cli_output (vm, "%U", format_tuple_filter, 
                             &filter->outer_tuple, 
                             filter->outer_tuple.length > 20); /* is_ipv6 */
            }
            
          if (filter->inner_tuple_present)
            {
              vlib_cli_output (vm, "    Inner 5-tuple filter:");
              vlib_cli_output (vm, "%U", format_tuple_filter, 
                             &filter->inner_tuple,
                             filter->inner_tuple.length > 20); /* is_ipv6 */
            }
            
          /* Option filters */
          if (filter->option_filters)
            {
              vlib_cli_output (vm, "    Option Filters:");
              
              for (j = 0; j < vec_len (filter->option_filters); j++)
                {
                  if (!filter->option_filters[j].present)
                    continue;
                    
                  /* Determine option details */
                  u16 opt_class;
                  u8 opt_type;
                  char *name = NULL;
                  geneve_opt_data_type_t data_type = GENEVE_OPT_TYPE_RAW;
                  
                  if (filter->option_filters[j].option_name)
                    {
                      /* Look up registered option by name */
                      uword *p = hash_get_mem (gpm->option_by_name, 
                                             filter->option_filters[j].option_name);
                      if (p)
                        {
                          geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
                          opt_class = opt_def->opt_class;
                          opt_type = opt_def->type;
                          name = opt_def->option_name;
                          data_type = opt_def->preferred_type;
                        }
                      else
                        {
                          /* This shouldn't happen if validation was done at filter creation */
                          opt_class = 0;
                          opt_type = 0;
                          name = (char *)filter->option_filters[j].option_name;
                        }
                    }
                  else
                    {
                      /* Direct class/type specification */
                      opt_class = filter->option_filters[j].opt_class;
                      opt_type = filter->option_filters[j].type;
                      
                      /* Try to find a registered name for this option */
                      u64 key = ((u64)opt_class << 8) | opt_type;
                      uword *p = hash_get (gpm->option_by_class_type, key);
                      if (p)
                        {
                          geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
                          name = opt_def->option_name;
                          data_type = opt_def->preferred_type;
                        }
                    }
                    
                  /* Output option filter details */
                  if (name)
                    vlib_cli_output (vm, "      Option: %s (class=0x%x, type=0x%x)",
                                    name, opt_class, opt_type);
                  else
                    vlib_cli_output (vm, "      Option: class=0x%x, type=0x%x",
                                    opt_class, opt_type);
                                    
                  if (filter->option_filters[j].match_any)
                    {
                      vlib_cli_output (vm, "        Match: Any (presence only)");
                    }
                  else if (filter->option_filters[j].data)
                    {
                      /* Show data in both formatted and raw forms */
                      vlib_cli_output (vm, "        Match Value: %U",
                                      format_option_data,
                                      filter->option_filters[j].data,
                                      filter->option_filters[j].data_len,
                                      data_type);
                                      
                      /* For non-raw types, also show raw bytes */
                      if (data_type != GENEVE_OPT_TYPE_RAW)
                        {
                          vlib_cli_output (vm, "        Raw Bytes: %U",
                                          format_option_data,
                                          filter->option_filters[j].data,
                                          filter->option_filters[j].data_len,
                                          GENEVE_OPT_TYPE_RAW);
                        }
                        
                      /* Show mask if present */
                      if (filter->option_filters[j].mask)
                        {
                          vlib_cli_output (vm, "        Mask: %U",
                                          format_option_data,
                                          filter->option_filters[j].mask,
                                          filter->option_filters[j].data_len,
                                          GENEVE_OPT_TYPE_RAW);
                        }
                    }
                }
            }
          
          filters_displayed++;
        }
    }
  
  /* Display per-interface filters */
  for (sw_if_index = 0; sw_if_index < vec_len (gpm->per_interface); sw_if_index++)
    {
      if (gpm->per_interface[sw_if_index].filters == 0)
        continue;
        
      if (vec_len (gpm->per_interface[sw_if_index].filters) == 0)
        continue;
        
      vnet_sw_interface_t *sw = vnet_get_sw_interface (vnet_get_main(), sw_if_index);
      if (!sw)
        continue;
        
      vlib_cli_output (vm, "\nInterface: %U (idx %d) - Capture %s",
                      format_vnet_sw_interface_name, vnet_get_main(), sw,
                      sw_if_index,
                      gpm->per_interface[sw_if_index].capture_enabled ? 
                      "enabled" : "disabled");
                      
      /* Display each filter on this interface */
      for (i = 0; i < vec_len (gpm->per_interface[sw_if_index].filters); i++)
        {
          geneve_capture_filter_t *filter = &gpm->per_interface[sw_if_index].filters[i];
          
          vlib_cli_output (vm, "  Filter Name: %s", filter->name);
          vlib_cli_output (vm, "  Filter ID: %u", filter->filter_id);
          vlib_cli_output (vm, "  Destination Output Index: %u", filter->destination_index);
          
          /* Basic header filters */
          if (filter->ver_present)
            vlib_cli_output (vm, "    Version: %u", filter->ver);
            
          if (filter->opt_len_present)
            vlib_cli_output (vm, "    Option Length: %u", filter->opt_len);
            
          if (filter->proto_present)
            vlib_cli_output (vm, "    Protocol: 0x%04x", filter->protocol);
            
          if (filter->vni_present)
            vlib_cli_output (vm, "    VNI: %u", filter->vni);
            
          /* 5-tuple filters */
          if (filter->outer_tuple_present)
            {
              vlib_cli_output (vm, "    Outer 5-tuple filter:");
              vlib_cli_output (vm, "%U", format_tuple_filter, 
                             &filter->outer_tuple, 
                             filter->outer_tuple.length > 20); /* is_ipv6 */
            }
            
          if (filter->inner_tuple_present)
            {
              vlib_cli_output (vm, "    Inner 5-tuple filter:");
              vlib_cli_output (vm, "%U", format_tuple_filter, 
                             &filter->inner_tuple,
                             filter->inner_tuple.length > 20); /* is_ipv6 */
            }
            
          /* Option filters */
          if (filter->option_filters)
            {
              vlib_cli_output (vm, "    Option Filters:");
              
              for (j = 0; j < vec_len (filter->option_filters); j++)
                {
                  if (!filter->option_filters[j].present)
                    continue;
                    
                  /* Determine option details */
                  u16 opt_class;
                  u8 opt_type;
                  char *name = NULL;
                  geneve_opt_data_type_t data_type = GENEVE_OPT_TYPE_RAW;
                  
                  if (filter->option_filters[j].option_name)
                    {
                      /* Look up registered option by name */
                      uword *p = hash_get_mem (gpm->option_by_name, 
                                             filter->option_filters[j].option_name);
                      if (p)
                        {
                          geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
                          opt_class = opt_def->opt_class;
                          opt_type = opt_def->type;
                          name = opt_def->option_name;
                          data_type = opt_def->preferred_type;
                        }
                      else
                        {
                          /* This shouldn't happen if validation was done at filter creation */
                          opt_class = 0;
                          opt_type = 0;
                          name = (char *)filter->option_filters[j].option_name;
                        }
                    }
                  else
                    {
                      /* Direct class/type specification */
                      opt_class = filter->option_filters[j].opt_class;
                      opt_type = filter->option_filters[j].type;
                      
                      /* Try to find a registered name for this option */
                      u64 key = ((u64)opt_class << 8) | opt_type;
                      uword *p = hash_get (gpm->option_by_class_type, key);
                      if (p)
                        {
                          geneve_option_def_t *opt_def = &gpm->option_defs[p[0]];
                          name = opt_def->option_name;
                          data_type = opt_def->preferred_type;
                        }
                    }
                    
                  /* Output option filter details */
                  if (name)
                    vlib_cli_output (vm, "      Option: %s (class=0x%x, type=0x%x)",
                                    name, opt_class, opt_type);
                  else
                    vlib_cli_output (vm, "      Option: class=0x%x, type=0x%x",
                                    opt_class, opt_type);
                                    
                  if (filter->option_filters[j].match_any)
                    {
                      vlib_cli_output (vm, "        Match: Any (presence only)");
                    }
                  else if (filter->option_filters[j].data)
                    {
                      /* Show data in both formatted and raw forms */
                      vlib_cli_output (vm, "        Match Value: %U",
                                      format_option_data,
                                      filter->option_filters[j].data,
                                      filter->option_filters[j].data_len,
                                      data_type);
                                      
                      /* For non-raw types, also show raw bytes */
                      if (data_type != GENEVE_OPT_TYPE_RAW)
                        {
                          vlib_cli_output (vm, "        Raw Bytes: %U",
                                          format_option_data,
                                          filter->option_filters[j].data,
                                          filter->option_filters[j].data_len,
                                          GENEVE_OPT_TYPE_RAW);
                        }
                        
                      /* Show mask if present */
                      if (filter->option_filters[j].mask)
                        {
                          vlib_cli_output (vm, "        Mask: %U",
                                          format_option_data,
                                          filter->option_filters[j].mask,
                                          filter->option_filters[j].data_len,
                                          GENEVE_OPT_TYPE_RAW);
                        }
                    }
                }
            }
          
          filters_displayed++;
        }
    }
    
  if (filters_displayed == 0)
    vlib_cli_output (vm, "  No active filters");
    
  return 0;
}

/* CLI command to show active filters */
VLIB_CLI_COMMAND (gpcapng_show_filters_command, static) = {
  .path = "show gpcapng filters",
  .short_help = "show gpcapng filters",
  .function = gpcapng_show_filters_command_fn,
};

/* Updated CLI command to register a named GENEVE option */
VLIB_CLI_COMMAND (gpcapng_register_option_command, static) = {
  .path = "gpcapng register-option",
  .short_help = "gpcapng register-option name <name> class <class> type <type> length <length>"
                " [data-type raw|ipv4|ipv6|uint8|uint16|uint32|string]",
  .function = gpcapng_register_option_command_fn,
};

/* CLI command to show registered options */
VLIB_CLI_COMMAND (gpcapng_show_options_command, static) = {
  .path = "show gpcapng options",
  .short_help = "show gpcapng options",
  .function = gpcapng_show_options_command_fn,
};




void gpcapng_filter_init() {
 /* Register some basic GENEVE option definitions */
  gpcapng_register_option_def ("vpp-metadata", 0x0123, 0x01, 8, GENEVE_OPT_TYPE_STRING);
  gpcapng_register_option_def ("legacy-oam", 0x0F0F, 0x01, 4, GENEVE_OPT_TYPE_UINT32);
   register_default_options();
}
