/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 */

#include <vnet/lisp-cp/lisp_types.h>

static u16 gid_address_put_no_vni (u8 * b, gid_address_t * gid);
static u16 gid_address_size_to_put_no_vni (gid_address_t * gid);
static u16 fid_addr_size_to_write (fid_address_t * a);

u32 mac_parse (u8 * offset, u8 * a);

typedef u16 (*size_to_write_fct) (void *);
typedef void *(*cast_fct) (gid_address_t *);
typedef u16 (*serdes_fct) (u8 *, void *);
typedef u8 (*addr_len_fct) (void *);
typedef void (*copy_fct) (void *, void *);
typedef void (*free_fct) (void *);
typedef int (*cmp_fct) (void *, void *);

size_to_write_fct size_to_write_fcts[GID_ADDR_TYPES] =
  { ip_prefix_size_to_write, lcaf_size_to_write, mac_size_to_write,
  sd_size_to_write, nsh_size_to_write, 0 /* arp */ , no_addr_size_to_write
};

serdes_fct write_fcts[GID_ADDR_TYPES] =
  { ip_prefix_write, lcaf_write, mac_write, sd_write, nsh_write, 0 /* arp */ ,
  no_addr_write
};

cast_fct cast_fcts[GID_ADDR_TYPES] =
  { ip_prefix_cast, lcaf_cast, mac_cast, sd_cast, nsh_cast, 0 /* arp */ ,
  no_addr_cast
};

addr_len_fct addr_len_fcts[GID_ADDR_TYPES] =
  { ip_prefix_length, lcaf_length, mac_length, sd_length, nsh_length,
  0 /* arp */ , no_addr_length
};

copy_fct copy_fcts[GID_ADDR_TYPES] =
  { ip_prefix_copy, lcaf_copy, mac_copy, sd_copy, nsh_copy, 0 /* arp */ ,
  no_addr_copy
};

#define foreach_lcaf_type \
  _(1, no_addr)      \
  _(0, NULL)         \
  _(1, vni)          \
  _(0, NULL)         \
  _(0, NULL)         \
  _(0, NULL)         \
  _(0, NULL)         \
  _(0, NULL)         \
  _(0, NULL)         \
  _(0, NULL)         \
  _(0, NULL)         \
  _(0, NULL)         \
  _(1, sd)           \
  _(0, NULL)         \
  _(0, NULL)         \
  _(0, NULL)         \
  _(0, NULL)         \
  _(1, nsh)

#define _(cond, name)                             \
  u16 name ## _write (u8 * p, void * a);          \
  u16 name ## _parse (u8 * p, void * a);          \
  u16 name ## _size_to_write (void * a);          \
  void name ## _free (void * a);                  \
  void name ## _copy (void * dst, void * src);    \
  u8 name ## _length (void * a);                  \
  int name ## _cmp (void *, void *);
foreach_lcaf_type
#undef _
#define CONCAT(a,b) a##_##b
#define IF(c, t, e) CONCAT(IF, c)(t, e)
#define IF_0(t, e) e
#define IF_1(t, e) t
#define EXPAND_FCN(cond, fcn)                           \
  IF(cond, fcn, NULL)
  cmp_fct lcaf_cmp_fcts[LCAF_TYPES] =
{
#define _(cond, name)                                   \
    EXPAND_FCN(cond, name##_cmp),
  foreach_lcaf_type
#undef _
};

addr_len_fct lcaf_body_length_fcts[LCAF_TYPES] = {
#define _(cond, name)                                   \
    EXPAND_FCN(cond, name##_length),
  foreach_lcaf_type
#undef _
};

copy_fct lcaf_copy_fcts[LCAF_TYPES] = {
#define _(cond, name)                                   \
    EXPAND_FCN(cond, name##_copy),
  foreach_lcaf_type
#undef _
};

free_fct lcaf_free_fcts[LCAF_TYPES] = {
#define _(cond, name)                                   \
    EXPAND_FCN(cond, name##_free),
  foreach_lcaf_type
#undef _
};

size_to_write_fct lcaf_size_to_write_fcts[LCAF_TYPES] = {
#define _(cond, name)                                   \
    EXPAND_FCN(cond, name##_size_to_write),
  foreach_lcaf_type
#undef _
};

serdes_fct lcaf_write_fcts[LCAF_TYPES] = {
#define _(cond, name)                                   \
    EXPAND_FCN(cond, name##_write),
  foreach_lcaf_type
#undef _
};

serdes_fct lcaf_parse_fcts[LCAF_TYPES] = {
#define _(cond, name)                                   \
    EXPAND_FCN(cond, name##_parse),
  foreach_lcaf_type
#undef _
};

u8 *
format_ip_address (u8 * s, va_list * args)
{
  ip_address_t *a = va_arg (*args, ip_address_t *);
  u8 ver = ip_addr_version (a);
  if (ver == IP4)
    {
      return format (s, "%U", format_ip4_address, &ip_addr_v4 (a));
    }
  else if (ver == IP6)
    {
      return format (s, "%U", format_ip6_address, &ip_addr_v6 (a));
    }
  else
    {
      clib_warning ("Can't format IP version %d!", ver);
      return 0;
    }
}

uword
unformat_ip_address (unformat_input_t * input, va_list * args)
{
  ip_address_t *a = va_arg (*args, ip_address_t *);

  clib_memset (a, 0, sizeof (*a));
  if (unformat (input, "%U", unformat_ip4_address, &ip_addr_v4 (a)))
    ip_addr_version (a) = IP4;
  else if (unformat_user (input, unformat_ip6_address, &ip_addr_v6 (a)))
    ip_addr_version (a) = IP6;
  else
    return 0;
  return 1;
}

u8 *
format_ip_prefix (u8 * s, va_list * args)
{
  ip_prefix_t *a = va_arg (*args, ip_prefix_t *);
  return format (s, "%U/%d", format_ip_address, &ip_prefix_addr (a),
		 ip_prefix_len (a));
}

uword
unformat_ip_prefix (unformat_input_t * input, va_list * args)
{
  ip_prefix_t *a = va_arg (*args, ip_prefix_t *);
  if (unformat (input, "%U/%d", unformat_ip_address, &ip_prefix_addr (a),
		&ip_prefix_len (a)))
    {
      if ((ip_prefix_version (a) == IP4 && 32 < ip_prefix_len (a)) ||
	  (ip_prefix_version (a) == IP6 && 128 < ip_prefix_length (a)))
	{
	  clib_warning ("Prefix length to big: %d!", ip_prefix_len (a));
	  return 0;
	}
      ip_prefix_normalize (a);
    }
  else
    return 0;
  return 1;
}

uword
unformat_nsh_address (unformat_input_t * input, va_list * args)
{
  nsh_t *a = va_arg (*args, nsh_t *);
  return unformat (input, "SPI:%d SI:%d", &a->spi, &a->si);
}

u8 *
format_nsh_address (u8 * s, va_list * args)
{
  nsh_t *a = va_arg (*args, nsh_t *);
  return format (s, "SPI:%d SI:%d", a->spi, a->si);
}

u8 *
format_fid_nsh_address (u8 * s, va_list * args)
{
  u32 *a = va_arg (*args, u32 *);
  return format (s, "SPI:%d SI:%d", *a >> 8, *a & 0xff);
}

u8 *
format_fid_address (u8 * s, va_list * args)
{
  fid_address_t *a = va_arg (*args, fid_address_t *);

  switch (fid_addr_type (a))
    {
    case FID_ADDR_IP_PREF:
      return format (s, "%U", format_ip_prefix, &fid_addr_ippref (a));
    case FID_ADDR_MAC:
      return format (s, "%U", format_mac_address, &fid_addr_mac (a));
    case FID_ADDR_NSH:
      return format (s, "%U", format_fid_nsh_address, &fid_addr_nsh (a));

    default:
      clib_warning ("Can't format fid address type %d!", fid_addr_type (a));
      return 0;
    }
  return 0;
}

u8 *
format_gid_address (u8 * s, va_list * args)
{
  gid_address_t *a = va_arg (*args, gid_address_t *);
  u8 type = gid_address_type (a);
  switch (type)
    {
    case GID_ADDR_IP_PREFIX:
      return format (s, "[%d] %U", gid_address_vni (a), format_ip_prefix,
		     &gid_address_ippref (a));
    case GID_ADDR_SRC_DST:
      return format (s, "[%d] %U|%U", gid_address_vni (a),
		     format_fid_address, &gid_address_sd_src (a),
		     format_fid_address, &gid_address_sd_dst (a));
    case GID_ADDR_MAC:
      return format (s, "[%d] %U", gid_address_vni (a), format_mac_address,
		     &gid_address_mac (a));
    case GID_ADDR_ARP:
    case GID_ADDR_NDP:
      return format (s, "[%d, %U]", gid_address_arp_ndp_bd (a),
		     format_ip_address, &gid_address_arp_ndp_ip (a));
    case GID_ADDR_NSH:
      return format (s, "%U", format_nsh_address, &gid_address_nsh (a));

    default:
      clib_warning ("Can't format gid type %d", type);
      return 0;
    }
  return 0;
}

uword
unformat_fid_address (unformat_input_t * i, va_list * args)
{
  fid_address_t *a = va_arg (*args, fid_address_t *);
  ip_prefix_t ippref;
  u8 mac[6] = { 0 };
  nsh_t nsh;

  if (unformat (i, "%U", unformat_ip_prefix, &ippref))
    {
      fid_addr_type (a) = FID_ADDR_IP_PREF;
      ip_prefix_copy (&fid_addr_ippref (a), &ippref);
    }
  else if (unformat (i, "%U", unformat_mac_address, mac))
    {
      fid_addr_type (a) = FID_ADDR_MAC;
      mac_copy (fid_addr_mac (a), mac);
    }
  else if (unformat (i, "%U", unformat_nsh_address, &nsh))
    {
      fid_addr_type (a) = FID_ADDR_NSH;
      nsh_copy (&fid_addr_nsh (a), &nsh);
    }
  else
    return 0;

  return 1;
}

uword
unformat_hmac_key_id (unformat_input_t * input, va_list * args)
{
  u32 *key_id = va_arg (*args, u32 *);
  u8 *s = 0;

  if (unformat (input, "%s", &s))
    {
      if (!strcmp ((char *) s, "sha1"))
	key_id[0] = HMAC_SHA_1_96;
      else if (!strcmp ((char *) s, "sha256"))
	key_id[0] = HMAC_SHA_256_128;
      else
	{
	  clib_warning ("invalid key_id: '%s'", s);
	  key_id[0] = HMAC_NO_KEY;
	}
    }
  else
    return 0;

  vec_free (s);
  return 1;
}

uword
unformat_gid_address (unformat_input_t * input, va_list * args)
{
  gid_address_t *a = va_arg (*args, gid_address_t *);
  u8 mac[6] = { 0 };
  ip_prefix_t ippref;
  fid_address_t sim1, sim2;
  nsh_t nsh;

  clib_memset (&ippref, 0, sizeof (ippref));
  clib_memset (&sim1, 0, sizeof (sim1));
  clib_memset (&sim2, 0, sizeof (sim2));

  if (unformat (input, "%U|%U", unformat_fid_address, &sim1,
		unformat_fid_address, &sim2))
    {
      gid_address_sd_src (a) = sim1;
      gid_address_sd_dst (a) = sim2;
      gid_address_type (a) = GID_ADDR_SRC_DST;
    }
  else if (unformat (input, "%U", unformat_ip_prefix, &ippref))
    {
      ip_prefix_copy (&gid_address_ippref (a), &ippref);
      gid_address_type (a) = GID_ADDR_IP_PREFIX;
    }
  else if (unformat (input, "%U", unformat_mac_address, mac))
    {
      mac_copy (gid_address_mac (a), mac);
      gid_address_type (a) = GID_ADDR_MAC;
    }
  else if (unformat (input, "%U", unformat_nsh_address, &nsh))
    {
      nsh_copy (&gid_address_nsh (a), &nsh);
      gid_address_type (a) = GID_ADDR_NSH;
    }
  else
    return 0;

  return 1;
}

uword
unformat_negative_mapping_action (unformat_input_t * input, va_list * args)
{
  u32 *action = va_arg (*args, u32 *);
  u8 *s = 0;

  if (unformat (input, "%s", &s))
    {
      if (!strcmp ((char *) s, "no-action"))
	action[0] = LISP_NO_ACTION;
      else if (!strcmp ((char *) s, "natively-forward"))
	action[0] = LISP_FORWARD_NATIVE;
      else if (!strcmp ((char *) s, "send-map-request"))
	action[0] = LISP_SEND_MAP_REQUEST;
      else if (!strcmp ((char *) s, "drop"))
	action[0] = LISP_DROP;
      else
	{
	  clib_warning ("invalid action: '%s'", s);
	  action[0] = LISP_DROP;
	}
    }
  else
    return 0;

  vec_free (s);
  return 1;
}

u8 *
format_hmac_key_id (u8 * s, va_list * args)
{
  lisp_key_type_t key_id = va_arg (*args, lisp_key_type_t);

  switch (key_id)
    {
    case HMAC_SHA_1_96:
      return format (0, "sha1");
    case HMAC_SHA_256_128:
      return format (0, "sha256");
    default:
      return 0;
    }

  return 0;
}

u8 *
format_negative_mapping_action (u8 * s, va_list * args)
{
  lisp_action_e action = va_arg (*args, lisp_action_e);

  switch (action)
    {
    case LISP_NO_ACTION:
      s = format (s, "no-action");
      break;
    case LISP_FORWARD_NATIVE:
      s = format (s, "natively-forward");
      break;
    case LISP_SEND_MAP_REQUEST:
      s = format (s, "send-map-request");
      break;
    case LISP_DROP:
    default:
      s = format (s, "drop");
      break;
    }
  return (s);
}

u16
ip_address_size (const ip_address_t * a)
{
  switch (ip_addr_version (a))
    {
    case IP4:
      return sizeof (ip4_address_t);
      break;
    case IP6:
      return sizeof (ip6_address_t);
      break;
    }
  return 0;
}

u16
ip_version_to_size (u8 ver)
{
  switch (ver)
    {
    case IP4:
      return sizeof (ip4_address_t);
      break;
    case IP6:
      return sizeof (ip6_address_t);
      break;
    }
  return 0;
}

u8
ip_version_to_max_plen (u8 ver)
{
  switch (ver)
    {
    case IP4:
      return 32;
      break;
    case IP6:
      return 128;
      break;
    }
  return 0;
}

always_inline lisp_afi_e
ip_version_to_iana_afi (u16 version)
{
  switch (version)
    {
    case IP4:
      return LISP_AFI_IP;
    case IP6:
      return LISP_AFI_IP6;
    default:
      return 0;
    }
  return 0;
}

always_inline u8
ip_iana_afi_to_version (lisp_afi_e afi)
{
  switch (afi)
    {
    case LISP_AFI_IP:
      return IP4;
    case LISP_AFI_IP6:
      return IP6;
    default:
      return 0;
    }
  return 0;
}

u16
ip_address_size_to_write (ip_address_t * a)
{
  return ip_address_size (a) + sizeof (u16);
}

u16
ip_address_iana_afi (ip_address_t * a)
{
  return ip_version_to_iana_afi (ip_addr_version (a));
}

u8
ip_address_max_len (u8 version)
{
  return version == IP4 ? 32 : 128;
}

u16
ip4_address_size_to_put ()
{
  // return sizeof(u16) + sizeof (ip4_address_t);
  return 6;
}

u16
ip6_address_size_to_put ()
{
  //return sizeof(u16) + sizeof (ip6_address_t);
  return 18;
}

u32
ip4_address_put (u8 * b, ip4_address_t * a)
{
  *(u16 *) b = clib_host_to_net_u16 (ip_version_to_iana_afi (IP4));
  u8 *p = b + sizeof (u16);
  clib_memcpy (p, a, sizeof (*a));
  return ip4_address_size_to_put ();
}

u32
ip6_address_put (u8 * b, ip6_address_t * a)
{
  *(u16 *) b = clib_host_to_net_u16 (ip_version_to_iana_afi (IP6));
  u8 *p = b + sizeof (u16);
  clib_memcpy (p, a, sizeof (*a));
  return ip6_address_size_to_put ();
}

u32
ip_address_put (u8 * b, ip_address_t * a)
{
  u32 len = ip_address_size (a);
  *(u16 *) b = clib_host_to_net_u16 (ip_address_iana_afi (a));
  u8 *p = b + sizeof (u16);
  clib_memcpy (p, &ip_addr_addr (a), len);
  return (len + sizeof (u16));
}

u32
ip_address_parse (void *offset, u16 iana_afi, ip_address_t * dst)
{
  ip_addr_version (dst) = ip_iana_afi_to_version (iana_afi);
  u8 size = ip_version_to_size (ip_addr_version (dst));
  clib_memcpy (&ip_addr_addr (dst), offset + sizeof (u16), size);
  return (sizeof (u16) + size);
}

void
gid_to_dp_address (gid_address_t * g, dp_address_t * d)
{
  switch (gid_address_type (g))
    {
    case GID_ADDR_SRC_DST:
      switch (gid_address_sd_dst_type (g))
	{
	case FID_ADDR_IP_PREF:
	  ip_prefix_copy (&d->ippref, &gid_address_sd_dst_ippref (g));
	  d->type = FID_ADDR_IP_PREF;
	  break;
	case FID_ADDR_MAC:
	  mac_copy (&d->mac, &gid_address_sd_dst_mac (g));
	  d->type = FID_ADDR_MAC;
	  break;
	default:
	  clib_warning ("Source/Dest address type %d not supported!",
			gid_address_sd_dst_type (g));
	  break;
	}
      break;
    case GID_ADDR_IP_PREFIX:
      ip_prefix_copy (&d->ippref, &gid_address_ippref (g));
      d->type = FID_ADDR_IP_PREF;
      break;
    case GID_ADDR_MAC:
      mac_copy (&d->mac, &gid_address_mac (g));
      d->type = FID_ADDR_MAC;
      break;
    case GID_ADDR_NSH:
    default:
      d->nsh = gid_address_nsh (g).spi << 8 | gid_address_nsh (g).si;
      d->type = FID_ADDR_NSH;
      break;
    }
}

u32
lcaf_hdr_parse (void *offset, lcaf_t * lcaf)
{
  lcaf_hdr_t *lh = offset;
  lcaf->type = lh->type;

  /* this is a bit of hack: since the LCAF Instance ID is the
     only message that uses reserved2 field, we can set it here.
     If any LCAF format starts using reserved2 field as well this needs
     to be moved elsewhere */
  lcaf_vni_len (lcaf) = lh->reserved2;

  return sizeof (lh[0]);
}

static u8
iana_afi_to_fid_addr_type (u16 type)
{
  switch (type)
    {
    case LISP_AFI_IP:
    case LISP_AFI_IP6:
      return FID_ADDR_IP_PREF;

    case LISP_AFI_MAC:
      return FID_ADDR_MAC;
    }
  return ~0;
}

static u16
fid_addr_parse (u8 * p, fid_address_t * a)
{
  u16 afi = clib_net_to_host_u16 (*(u16 *) p);
  fid_addr_type (a) = iana_afi_to_fid_addr_type (afi);
  ip_address_t *ip_addr = &ip_prefix_addr (&fid_addr_ippref (a));

  switch (fid_addr_type (a))
    {
    case FID_ADDR_MAC:
      return mac_parse (p, fid_addr_mac (a));

    case FID_ADDR_IP_PREF:
      return ip_address_parse (p, afi, ip_addr);

    case FID_ADDR_NSH:
      break;
    }
  return ~0;
}

#define INC(dst, exp)   \
do {                    \
  u16 _sum = (exp);     \
  if ((u16)~0 == _sum)  \
    return ~0;          \
  dst += _sum;          \
} while (0);

void
nsh_free (void *a)
{
  /* nothing to do */
}

u16
nsh_parse (u8 * p, void *a)
{
  lcaf_spi_hdr_t *h = (lcaf_spi_hdr_t *) p;
  gid_address_t *g = a;

  gid_address_type (g) = GID_ADDR_NSH;
  gid_address_nsh_spi (g) = clib_net_to_host_u32 (LCAF_SPI_SI (h)) >> 8;
  gid_address_nsh_si (g) = (u8) clib_net_to_host_u32 (LCAF_SPI_SI (h));

  return sizeof (lcaf_spi_hdr_t);
}

int
nsh_cmp (void *a1, void *a2)
{
  nsh_t *n1 = a1;
  nsh_t *n2 = a2;

  if (n1->spi != n2->spi)
    return 1;
  if (n1->si != n2->si)
    return 1;
  return 0;
}

u16
sd_parse (u8 * p, void *a)
{
  lcaf_src_dst_hdr_t *sd_hdr;
  gid_address_t *g = a;
  u16 size = 0;
  fid_address_t *src = &gid_address_sd_src (g);
  fid_address_t *dst = &gid_address_sd_dst (g);

  gid_address_type (g) = GID_ADDR_SRC_DST;

  sd_hdr = (lcaf_src_dst_hdr_t *) (p + size);
  size += sizeof (sd_hdr[0]);

  INC (size, fid_addr_parse (p + size, src));
  INC (size, fid_addr_parse (p + size, dst));

  if (fid_addr_type (src) == FID_ADDR_IP_PREF)
    {
      ip_prefix_t *ippref = &fid_addr_ippref (src);
      ip_prefix_len (ippref) = LCAF_SD_SRC_ML (sd_hdr);
    }
  if (fid_addr_type (dst) == FID_ADDR_IP_PREF)
    {
      ip_prefix_t *ippref = &fid_addr_ippref (dst);
      ip_prefix_len (ippref) = LCAF_SD_DST_ML (sd_hdr);
    }
  return size;
}

u16
try_parse_src_dst_lcaf (u8 * p, gid_address_t * a)
{
  lcaf_t lcaf;
  u16 size = sizeof (u16);	/* skip AFI */

  size += lcaf_hdr_parse (p + size, &lcaf);

  if (LCAF_SOURCE_DEST != lcaf_type (&lcaf))
    return ~0;

  INC (size, sd_parse (p + size, a));
  return size;
}

u16
vni_parse (u8 * p, void *a)
{
  lcaf_t *lcaf = a;
  gid_address_t *g = a;
  u16 size = 0;

  gid_address_vni (g) = clib_net_to_host_u32 (*(u32 *) p);
  size += sizeof (u32);
  gid_address_vni_mask (g) = lcaf_vni_len (lcaf);

  /* nested LCAFs are not supported except of src/dst with vni - to handle
   * such case look at the next AFI and process src/dest LCAF separately */
  u16 afi = clib_net_to_host_u16 (*((u16 *) (p + size)));
  if (LISP_AFI_LCAF == afi)
    {
      INC (size, try_parse_src_dst_lcaf (p + size, g));
    }
  else
    INC (size, gid_address_parse (p + size, g));

  return size;
}

u16
no_addr_parse (u8 * p, void *a)
{
  /* do nothing */
  return 0;
}

u32
lcaf_parse (void *offset, gid_address_t * addr)
{
  /* skip AFI type */
  offset += sizeof (u16);
  lcaf_t *lcaf = &gid_address_lcaf (addr);

  u32 size = lcaf_hdr_parse (offset, lcaf);
  u8 type = lcaf_type (lcaf);

  if (!lcaf_parse_fcts[type])
    {
      clib_warning ("Unsupported LCAF type: %u", type);
      return ~0;
    }
  INC (size, (*lcaf_parse_fcts[type]) (offset + size, lcaf));
  return sizeof (u16) + size;
}

void
vni_free (void *a)
{
  vni_t *v = a;
  gid_address_free (vni_gid (v));
  clib_mem_free (vni_gid (v));
}

void
no_addr_free (void *a)
{
  /* nothing to do */
}

void
sd_free (void *a)
{
  /* nothing */
}

void
gid_address_free (gid_address_t * a)
{
  if (gid_address_type (a) != GID_ADDR_LCAF)
    return;

  lcaf_t *lcaf = &gid_address_lcaf (a);
  u8 lcaf_type = lcaf_type (lcaf);
  (*lcaf_free_fcts[lcaf_type]) (lcaf);
}

void
gid_address_from_ip (gid_address_t * g, ip_address_t * ip)
{
  clib_memset (g, 0, sizeof (g[0]));
  ip_address_set (&gid_address_ip (g), ip, ip_addr_version (ip));
  gid_address_ippref_len (g) = 32;
}

int
ip_address_cmp (const ip_address_t * ip1, const ip_address_t * ip2)
{
  int res = 0;
  if (ip_addr_version (ip1) != ip_addr_version (ip2))
    return -1;
  res =
    memcmp (&ip_addr_addr (ip1), &ip_addr_addr (ip2), ip_address_size (ip1));

  if (res < 0)
    res = 2;
  else if (res > 0)
    res = 1;

  return res;
}

void
ip_address_copy (ip_address_t * dst, const ip_address_t * src)
{
  if (IP4 == ip_addr_version (src))
    {
      /* don't copy any garbage from the union */
      clib_memset (dst, 0, sizeof (*dst));
      dst->ip.v4 = src->ip.v4;
      dst->version = IP4;
    }
  else
    {
      clib_memcpy (dst, src, sizeof (ip_address_t));
    }
}

void
ip_address_copy_addr (void *dst, const ip_address_t * src)
{
  clib_memcpy (dst, src, ip_address_size (src));
}

void
ip_address_set (ip_address_t * dst, const void *src, u8 version)
{
  clib_memcpy (dst, src, ip_version_to_size (version));
  ip_addr_version (dst) = version;
}

void
ip_address_to_46 (const ip_address_t * addr,
		  ip46_address_t * a, fib_protocol_t * proto)
{
  *proto = (IP4 == ip_addr_version (addr) ?
	    FIB_PROTOCOL_IP4 : FIB_PROTOCOL_IP6);
  switch (*proto)
    {
    case FIB_PROTOCOL_IP4:
      ip46_address_set_ip4 (a, &addr->ip.v4);
      break;
    case FIB_PROTOCOL_IP6:
      a->ip6 = addr->ip.v6;
      break;
    default:
      ASSERT (0);
      break;
    }
}

static void
ip_prefix_normalize_ip4 (ip4_address_t * ip4, u8 preflen)
{
  u32 mask = ~0;

  ASSERT (ip4);

  if (32 <= preflen)
    {
      return;
    }

  mask = pow2_mask (preflen) << (32 - preflen);
  mask = clib_host_to_net_u32 (mask);
  ip4->data_u32 &= mask;
}

static void
ip_prefix_normalize_ip6 (ip6_address_t * ip6, u8 preflen)
{
  u8 mask_6[16];
  u32 *m;
  u8 j, i0, i1;

  ASSERT (ip6);

  clib_memset (mask_6, 0, sizeof (mask_6));

  if (128 <= preflen)
    {
      return;
    }

  i1 = preflen % 32;
  i0 = preflen / 32;
  m = (u32 *) & mask_6[0];

  for (j = 0; j < i0; j++)
    {
      m[j] = ~0;
    }

  if (i1)
    {
      m[i0] = clib_host_to_net_u32 (pow2_mask (i1) << (32 - i1));
    }

  for (j = 0; j < sizeof (mask_6); j++)
    {
      ip6->as_u8[j] &= mask_6[j];
    }
}

void
ip_prefix_normalize (ip_prefix_t * a)
{
  u8 preflen = ip_prefix_len (a);

  switch (ip_prefix_version (a))
    {
    case IP4:
      ip_prefix_normalize_ip4 (&ip_prefix_v4 (a), preflen);
      break;

    case IP6:
      ip_prefix_normalize_ip6 (&ip_prefix_v6 (a), preflen);
      break;

    default:
      ASSERT (0);
    }
}

void *
ip_prefix_cast (gid_address_t * a)
{
  return &gid_address_ippref (a);
}

u16
ip_prefix_size_to_write (void *pref)
{
  ip_prefix_t *a = (ip_prefix_t *) pref;
  return ip_address_size_to_write (&ip_prefix_addr (a));
}

u16
ip_prefix_write (u8 * p, void *gid)
{
  gid_address_t *g = gid;
  ip_prefix_t *a = &gid_address_ippref (g);

  switch (ip_prefix_version (a))
    {
    case IP4:
      return ip4_address_put (p, &ip_prefix_v4 (a));
      break;
    case IP6:
      return ip6_address_put (p, &ip_prefix_v6 (a));
      break;
    }
  return 0;
}

u8
ip_prefix_length (void *a)
{
  return ip_prefix_len ((ip_prefix_t *) a);
}

void
ip_prefix_copy (void *dst, void *src)
{
  clib_memcpy (dst, src, sizeof (ip_prefix_t));
}

void
mac_copy (void *dst, void *src)
{
  clib_memcpy (dst, src, 6);
}

void
sd_copy (void *dst, void *src)
{
  clib_memcpy (dst, src, sizeof (source_dest_t));
}

void
nsh_copy (void *dst, void *src)
{
  clib_memcpy (dst, src, sizeof (nsh_t));
}

int
ip_prefix_cmp (ip_prefix_t * p1, ip_prefix_t * p2)
{
  int cmp = 0;

  ip_prefix_normalize (p1);
  ip_prefix_normalize (p2);

  cmp = ip_address_cmp (&ip_prefix_addr (p1), &ip_prefix_addr (p2));
  if (cmp == 0)
    {
      if (ip_prefix_len (p1) < ip_prefix_len (p2))
	{
	  cmp = 1;
	}
      else
	{
	  if (ip_prefix_len (p1) > ip_prefix_len (p2))
	    cmp = 2;
	}
    }
  return cmp;
}

void
no_addr_copy (void *dst, void *src)
{
  /* nothing to do */
}

void
vni_copy (void *dst, void *src)
{
  vni_t *vd = dst;
  vni_t *vs = src;

  clib_memcpy (vd, vs, sizeof (vd[0]));
  vni_gid (vd) = clib_mem_alloc (sizeof (gid_address_t));
  gid_address_copy (vni_gid (vd), vni_gid (vs));
}

void
lcaf_copy (void *dst, void *src)
{
  lcaf_t *lcaf_dst = dst;
  lcaf_t *lcaf_src = src;

  lcaf_type (lcaf_dst) = lcaf_type (lcaf_src);
  (*lcaf_copy_fcts[lcaf_type (lcaf_src)]) (dst, src);
}

u8
lcaf_length (void *a)
{
  return 0;
}

u8
mac_length (void *a)
{
  return 0;
}

u8
sd_length (void *a)
{
  return 0;
}

u8
nsh_length (void *a)
{
  return 0;
}

void *
lcaf_cast (gid_address_t * a)
{
  return &gid_address_lcaf (a);
}

void *
mac_cast (gid_address_t * a)
{
  return &gid_address_mac (a);
}

void *
no_addr_cast (gid_address_t * a)
{
  return (void *) a;
}

void *
sd_cast (gid_address_t * a)
{
  return &gid_address_sd (a);
}

void *
nsh_cast (gid_address_t * a)
{
  return &gid_address_nsh (a);
}

u8
no_addr_length (void *a)
{
  return 0;
}

u8
vni_length (void *a)
{
  vni_t *v = a;
  return (sizeof (u32)		/* VNI size */
	  + gid_address_size_to_put (vni_gid (v)) /* vni body size */ );
}

u16
lcaf_write (u8 * p, void *a)
{
  u16 size = 0, len;
  lcaf_t *lcaf = a;
  u8 type = lcaf_type (lcaf);
  lcaf_hdr_t _h, *h = &_h;

  *(u16 *) p = clib_host_to_net_u16 (LISP_AFI_LCAF);
  size += sizeof (u16);
  clib_memset (h, 0, sizeof (h[0]));
  LCAF_TYPE (h) = type;
  u16 lcaf_len = (*lcaf_body_length_fcts[type]) (lcaf);
  LCAF_LENGTH (h) = clib_host_to_net_u16 (lcaf_len);

  clib_memcpy (p + size, h, sizeof (h[0]));
  size += sizeof (h[0]);
  len = (*lcaf_write_fcts[type]) (p + size, lcaf);

  if ((u16) ~ 0 == len)
    return ~0;

  return size + len;
}

u16
mac_write (u8 * p, void *a)
{
  *(u16 *) p = clib_host_to_net_u16 (LISP_AFI_MAC);
  clib_memcpy (p + sizeof (u16), a, 6);
  return mac_size_to_write (a);
}

static u16
fid_addr_write (u8 * p, fid_address_t * a)
{
  switch (fid_addr_type (a))
    {
    case FID_ADDR_IP_PREF:
      return ip_prefix_write (p, &fid_addr_ippref (a));

    case FID_ADDR_MAC:
      return mac_write (p, &fid_addr_mac (a));

    default:
      return ~0;
    }
  return ~0;
}

static u8
fid_address_length (fid_address_t * a)
{
  switch (fid_addr_type (a))
    {
    case FID_ADDR_IP_PREF:
      return ip_prefix_length (&fid_addr_ippref (a));
    case FID_ADDR_MAC:
      return 0;
    case FID_ADDR_NSH:
      return 0;
    }
  return 0;
}

u16
sd_write (u8 * p, void *a)
{
  source_dest_t *sd = a;
  u16 size = 0;
  lcaf_hdr_t _h, *h = &_h;
  lcaf_src_dst_hdr_t sd_hdr;

  *(u16 *) p = clib_host_to_net_u16 (LISP_AFI_LCAF);
  size += sizeof (u16);
  clib_memset (h, 0, sizeof (h[0]));
  LCAF_TYPE (h) = LCAF_SOURCE_DEST;
  u16 lcaf_len = sizeof (lcaf_src_dst_hdr_t)
    + fid_addr_size_to_write (&sd_src (sd))
    + fid_addr_size_to_write (&sd_dst (sd));
  LCAF_LENGTH (h) = clib_host_to_net_u16 (lcaf_len);

  clib_memcpy (p + size, h, sizeof (h[0]));
  size += sizeof (h[0]);

  clib_memset (&sd_hdr, 0, sizeof (sd_hdr));
  LCAF_SD_SRC_ML (&sd_hdr) = fid_address_length (&sd_src (sd));
  LCAF_SD_DST_ML (&sd_hdr) = fid_address_length (&sd_dst (sd));
  clib_memcpy (p + size, &sd_hdr, sizeof (sd_hdr));
  size += sizeof (sd_hdr);

  u16 len = fid_addr_write (p + size, &sd_src (sd));
  if ((u16) ~ 0 == len)
    return ~0;
  size += len;

  len = fid_addr_write (p + size, &sd_dst (sd));
  if ((u16) ~ 0 == len)
    return ~0;
  size += len;

  return size;
}

u16
nsh_write (u8 * p, void *a)
{
  lcaf_spi_hdr_t spi;
  lcaf_hdr_t lcaf;
  gid_address_t *g = a;
  u16 size = 0;

  ASSERT (gid_address_type (g) == GID_ADDR_NSH);

  clib_memset (&lcaf, 0, sizeof (lcaf));
  clib_memset (&spi, 0, sizeof (spi));

  LCAF_TYPE (&lcaf) = LCAF_NSH;
  LCAF_LENGTH (&lcaf) = clib_host_to_net_u16 (sizeof (lcaf_spi_hdr_t));

  u32 s = clib_host_to_net_u32 (gid_address_nsh_spi (g) << 8 |
				gid_address_nsh_si (g));
  LCAF_SPI_SI (&spi) = s;

  *(u16 *) p = clib_host_to_net_u16 (LISP_AFI_LCAF);
  size += sizeof (u16);

  clib_memcpy (p + size, &lcaf, sizeof (lcaf));
  size += sizeof (lcaf);

  clib_memcpy (p + size, &spi, sizeof (spi));
  size += sizeof (spi);

  return size;
}

u16
vni_write (u8 * p, void *a)
{
  lcaf_hdr_t _h, *h = &_h;
  gid_address_t *g = a;
  u16 size = 0, len;

  /* put lcaf header */
  *(u16 *) p = clib_host_to_net_u16 (LISP_AFI_LCAF);
  size += sizeof (u16);
  clib_memset (h, 0, sizeof (h[0]));
  LCAF_TYPE (h) = LCAF_INSTANCE_ID;
  u16 lcaf_len = sizeof (u32)	/* Instance ID size */
    + gid_address_size_to_put_no_vni (g);
  LCAF_LENGTH (h) = clib_host_to_net_u16 (lcaf_len);
  LCAF_RES2 (h) = gid_address_vni_mask (g);

  /* put vni header */
  clib_memcpy (p + size, h, sizeof (h[0]));
  size += sizeof (h[0]);

  u32 *afip = (u32 *) (p + size);
  afip[0] = clib_host_to_net_u32 (gid_address_vni (g));
  size += sizeof (u32);

  if (GID_ADDR_SRC_DST == gid_address_type (g))
    /* write src/dst LCAF */
    {
      len = sd_write (p + size, g);
      if ((u16) ~ 0 == len)
	return ~0;
    }
  else
    /* write the actual address */
    len = gid_address_put_no_vni (p + size, g);

  if ((u16) ~ 0 == len)
    return ~0;

  return size + len;
}

u16
no_addr_write (u8 * p, void *a)
{
  /* do nothing; return AFI field size */
  return sizeof (u16);
}

u16
no_addr_size_to_write (void *a)
{
  return sizeof (u16);		/* AFI field length */
}

static u16
fid_addr_size_to_write (fid_address_t * a)
{
  switch (fid_addr_type (a))
    {
    case FID_ADDR_IP_PREF:
      return ip_prefix_size_to_write (a);

    case FID_ADDR_MAC:
      return mac_size_to_write (a);

    default:
      break;
    }
  return 0;
}

u16
vni_size_to_write (void *a)
{
  gid_address_t *g = a;

  u16 lcaf_size = sizeof (u32) + sizeof (u16)	/* LCAF AFI field size */
    + sizeof (lcaf_hdr_t);

  if (gid_address_type (g) == GID_ADDR_SRC_DST)
    /* special case where nested LCAF is supported */
    return lcaf_size + sd_size_to_write (g);
  else
    return lcaf_size + gid_address_size_to_put_no_vni (g);
}

u16
lcaf_size_to_write (void *a)
{
  lcaf_t *lcaf = (lcaf_t *) a;
  u32 size = 0, len;
  u8 type = lcaf_type (lcaf);

  size += sizeof (u16);		/* AFI size */

  len = (*lcaf_size_to_write_fcts[type]) (lcaf);
  if (~0 == len)
    return ~0;

  return size + len;
}

u16
sd_size_to_write (void *a)
{
  source_dest_t *sd = a;
  return sizeof (u16)
    + sizeof (lcaf_hdr_t)
    + sizeof (lcaf_src_dst_hdr_t)
    + fid_addr_size_to_write (&sd_src (sd))
    + fid_addr_size_to_write (&sd_dst (sd));
}

u16
mac_size_to_write (void *a)
{
  return sizeof (u16) + 6;
}

u16
nsh_size_to_write (void *a)
{
  return sizeof (u16) + sizeof (lcaf_hdr_t) + sizeof (lcaf_spi_hdr_t);
}

u8
gid_address_len (gid_address_t * a)
{
  gid_address_type_t type = gid_address_type (a);
  return (*addr_len_fcts[type]) ((*cast_fcts[type]) (a));
}

static u16
gid_address_put_no_vni (u8 * b, gid_address_t * gid)
{
  gid_address_type_t type = gid_address_type (gid);
  return (*write_fcts[type]) (b, (*cast_fcts[type]) (gid));
}

u16
gid_address_put (u8 * b, gid_address_t * gid)
{
  if (0 != gid_address_vni (gid))
    return vni_write (b, gid);

  return gid_address_put_no_vni (b, gid);
}

static u16
gid_address_size_to_put_no_vni (gid_address_t * gid)
{
  gid_address_type_t type = gid_address_type (gid);
  return (*size_to_write_fcts[type]) ((*cast_fcts[type]) (gid));
}

u16
gid_address_size_to_put (gid_address_t * gid)
{
  if (0 != gid_address_vni (gid))
    return vni_size_to_write (gid);

  return gid_address_size_to_put_no_vni (gid);
}

void *
gid_address_cast (gid_address_t * gid, gid_address_type_t type)
{
  return (*cast_fcts[type]) (gid);
}

void
gid_address_copy (gid_address_t * dst, gid_address_t * src)
{
  gid_address_type_t type = gid_address_type (src);
  (*copy_fcts[type]) ((*cast_fcts[type]) (dst), (*cast_fcts[type]) (src));
  gid_address_type (dst) = type;
  gid_address_vni (dst) = gid_address_vni (src);
  gid_address_vni_mask (dst) = gid_address_vni_mask (src);
}

u32
mac_parse (u8 * offset, u8 * a)
{
  /* skip AFI field */
  offset += sizeof (u16);

  clib_memcpy (a, offset, 6);
  return sizeof (u16) + 6;
}

u32
gid_address_parse (u8 * offset, gid_address_t * a)
{
  lisp_afi_e afi;
  u16 len = 0;

  ASSERT (a);

  /* NOTE: since gid_address_parse may be called by vni_parse, we can't 0
   * the gid address here */
  afi = clib_net_to_host_u16 (*((u16 *) offset));

  switch (afi)
    {
    case LISP_AFI_NO_ADDR:
      len = sizeof (u16);
      gid_address_type (a) = GID_ADDR_NO_ADDRESS;
      break;
    case LISP_AFI_IP:
      len = ip_address_parse (offset, afi, &gid_address_ip (a));
      gid_address_type (a) = GID_ADDR_IP_PREFIX;
      /* this should be modified outside if needed */
      gid_address_ippref_len (a) = 32;
      break;
    case LISP_AFI_IP6:
      len = ip_address_parse (offset, afi, &gid_address_ip (a));
      gid_address_type (a) = GID_ADDR_IP_PREFIX;
      /* this should be modified outside if needed */
      gid_address_ippref_len (a) = 128;
      break;
    case LISP_AFI_LCAF:
      gid_address_type (a) = GID_ADDR_LCAF;
      len = lcaf_parse (offset, a);
      break;
    case LISP_AFI_MAC:
      len = mac_parse (offset, gid_address_mac (a));
      gid_address_type (a) = GID_ADDR_MAC;
      break;
    default:
      clib_warning ("LISP AFI %d not supported!", afi);
      return ~0;
    }
  return (len == (u16) ~ 0) ? ~0 : len;
}

void
gid_address_ip_set (gid_address_t * dst, void *src, u8 version)
{
  gid_address_ippref_len (dst) = ip_address_max_len (version);
  ip_address_set (&gid_address_ip (dst), src, version);
}

int
no_addr_cmp (void *a1, void *a2)
{
  return 0;
}

int
vni_cmp (void *a1, void *a2)
{
  vni_t *v1 = a1;
  vni_t *v2 = a2;

  if (vni_mask_len (v1) != vni_mask_len (v2))
    return -1;
  if (vni_vni (v1) != vni_vni (v2))
    return -1;
  return gid_address_cmp (vni_gid (v1), vni_gid (v2));
}

static int
mac_cmp (void *a1, void *a2)
{
  return memcmp (a1, a2, 6);
}

static int
fid_addr_cmp (fid_address_t * a1, fid_address_t * a2)
{
  if (fid_addr_type (a1) != fid_addr_type (a2))
    return -1;

  switch (fid_addr_type (a1))
    {
    case FID_ADDR_IP_PREF:
      return ip_prefix_cmp (&fid_addr_ippref (a1), &fid_addr_ippref (a2));

    case FID_ADDR_MAC:
      return mac_cmp (fid_addr_mac (a1), fid_addr_mac (a2));

    default:
      return -1;
    }
  return -1;
}

int
sd_cmp (void *a1, void *a2)
{
  source_dest_t *sd1 = a1;
  source_dest_t *sd2 = a2;

  if (fid_addr_cmp (&sd_dst (sd1), &sd_dst (sd2)))
    return -1;
  if (fid_addr_cmp (&sd_src (sd1), &sd_src (sd2)))
    return -1;
  return 0;
}

/* Compare two gid_address_t.
 * Returns:
 *        -1: If they are from different afi
 *             0: Both address are the same
 *             1: Addr1 is bigger than addr2
 *             2: Addr2 is bigger than addr1
 */
int
gid_address_cmp (gid_address_t * a1, gid_address_t * a2)
{
  lcaf_t *lcaf1, *lcaf2;
  int cmp = -1;
  if (!a1 || !a2)
    return -1;
  if (gid_address_type (a1) != gid_address_type (a2))
    return -1;
  if (gid_address_vni (a1) != gid_address_vni (a2))
    return -1;

  /* TODO vni mask is not supported, disable comparing for now
     if (gid_address_vni_mask (a1) != gid_address_vni_mask (a2))
     return -1;
   */

  switch (gid_address_type (a1))
    {
    case GID_ADDR_NO_ADDRESS:
      if (a1 == a2)
	cmp = 0;
      else
	cmp = 2;
      break;
    case GID_ADDR_IP_PREFIX:
      cmp =
	ip_prefix_cmp (&gid_address_ippref (a1), &gid_address_ippref (a2));
      break;
    case GID_ADDR_LCAF:
      lcaf1 = &gid_address_lcaf (a1);
      lcaf2 = &gid_address_lcaf (a2);
      if (lcaf_type (lcaf1) == lcaf_type (lcaf2))
	cmp = (*lcaf_cmp_fcts[lcaf_type (lcaf1)]) (lcaf1, lcaf2);
      break;
    case GID_ADDR_MAC:
      cmp = mac_cmp (gid_address_mac (a1), gid_address_mac (a2));
      break;

    case GID_ADDR_SRC_DST:
      cmp = sd_cmp (&gid_address_sd (a1), &gid_address_sd (a2));
      break;
    case GID_ADDR_NSH:
      cmp = nsh_cmp (&gid_address_nsh (a1), &gid_address_nsh (a2));
      break;
    default:
      break;
    }

  return cmp;
}

u32
locator_parse (void *b, locator_t * loc)
{
  locator_hdr_t *h;
  u8 status = 1;		/* locator up */
  int len;

  h = b;
  if (!LOC_REACHABLE (h) && LOC_LOCAL (h))
    status = 0;

  len = gid_address_parse (LOC_ADDR (h), &loc->address);
  if (len == ~0)
    return len;

  loc->state = status;
  loc->local = 0;
  loc->priority = LOC_PRIORITY (h);
  loc->weight = LOC_WEIGHT (h);
  loc->mpriority = LOC_MPRIORITY (h);
  loc->mweight = LOC_MWEIGHT (h);

  return sizeof (locator_hdr_t) + len;
}

void
locator_copy (locator_t * dst, locator_t * src)
{
  /* TODO if gid become more complex, this will need to be changed! */
  clib_memcpy (dst, src, sizeof (*dst));
  if (!src->local)
    gid_address_copy (&dst->address, &src->address);
}

u32
locator_cmp (locator_t * l1, locator_t * l2)
{
  u32 ret = 0;
  if ((ret = gid_address_cmp (&l1->address, &l2->address)) != 0)
    return 1;

  if (l1->priority != l2->priority)
    return 1;
  if (l1->weight != l2->weight)
    return 1;
  if (l1->mpriority != l2->mpriority)
    return 1;
  if (l1->mweight != l2->mweight)
    return 1;
  return 0;
}

void
locator_free (locator_t * l)
{
  if (!l->local)
    gid_address_free (&l->address);
}

void
build_src_dst (gid_address_t * sd, gid_address_t * src, gid_address_t * dst)
{
  clib_memset (sd, 0, sizeof (*sd));
  gid_address_type (sd) = GID_ADDR_SRC_DST;
  gid_address_vni (sd) = gid_address_vni (dst);
  gid_address_vni_mask (sd) = gid_address_vni_mask (dst);

  switch (gid_address_type (dst))
    {
    case GID_ADDR_IP_PREFIX:
      gid_address_sd_src_type (sd) = FID_ADDR_IP_PREF;
      gid_address_sd_dst_type (sd) = FID_ADDR_IP_PREF;
      ip_prefix_copy (&gid_address_sd_src_ippref (sd),
		      &gid_address_ippref (src));
      ip_prefix_copy (&gid_address_sd_dst_ippref (sd),
		      &gid_address_ippref (dst));
      break;
    case GID_ADDR_MAC:
      gid_address_sd_src_type (sd) = FID_ADDR_MAC;
      gid_address_sd_dst_type (sd) = FID_ADDR_MAC;
      mac_copy (gid_address_sd_src_mac (sd), gid_address_mac (src));
      mac_copy (gid_address_sd_dst_mac (sd), gid_address_mac (dst));
      break;
    default:
      clib_warning ("Unsupported gid type %d while conversion!",
		    gid_address_type (dst));
      break;
    }
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
