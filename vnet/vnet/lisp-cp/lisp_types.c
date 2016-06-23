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

typedef u16 (*size_to_write_fct)(void *);
typedef void * (*cast_fct)(gid_address_t *);
typedef u16 (*serdes_fct)(u8 *, void *);
typedef u8 (*addr_len_fct)(void *);
typedef void (*copy_fct)(void *, void *);
typedef void (*free_fct)(void *);
typedef int (*cmp_fct)(void *, void *);

u16 vni_write (u8 * p, void * a);
u16 vni_parse (u8 * p, void * a);
u16 vni_size_to_write (void * a);
void vni_free (void * a);
void vni_copy (void * dst, void * src);
u16 vni_length (void * a);
int vni_cmp (void *, void *);

u16 no_addr_size_to_write (void *);
u16 no_addr_write (u8 * p, void * a);
u16 no_addr_parse (u8 * p, void * a);
void no_addr_free (void * a);
void no_addr_copy (void *, void *);
u16 no_addr_length (void * a);
int no_addr_cmp (void * a1, void * a2);

size_to_write_fct size_to_write_fcts[GID_ADDR_TYPES] =
  { ip_prefix_size_to_write, lcaf_size_to_write, mac_size_to_write };
serdes_fct write_fcts[GID_ADDR_TYPES] =
  { ip_prefix_write, lcaf_write, mac_write };
cast_fct cast_fcts[GID_ADDR_TYPES] =
  { ip_prefix_cast, lcaf_cast, mac_cast };
addr_len_fct addr_len_fcts[GID_ADDR_TYPES] =
  { ip_prefix_length, lcaf_length, mac_length };
copy_fct copy_fcts[GID_ADDR_TYPES] =
  { ip_prefix_copy, lcaf_copy, mac_copy };

cmp_fct lcaf_cmp_fcts[LCAF_TYPES] =
  {
    no_addr_cmp,
    NULL,
    vni_cmp
  };

size_to_write_fct lcaf_body_length_fcts[LCAF_TYPES] =
  {
    no_addr_length,
    NULL,
    vni_length
  };

copy_fct lcaf_copy_fcts[LCAF_TYPES] =
  {
    no_addr_copy,
    NULL,
    vni_copy
  };

free_fct lcaf_free_fcts[LCAF_TYPES] =
  {
    no_addr_free,
    NULL,
    vni_free
  };

size_to_write_fct lcaf_size_to_write_fcts[LCAF_TYPES] =
  {
    no_addr_size_to_write,
    NULL,
    vni_size_to_write
  };

serdes_fct lcaf_write_fcts[LCAF_TYPES] =
  {
    no_addr_write,
    NULL,
    vni_write
  };

serdes_fct lcaf_parse_fcts[LCAF_TYPES] =
  {
    no_addr_parse,
    NULL,
    vni_parse
  };

u8 *
format_ip_address (u8 * s, va_list * args)
{
  ip_address_t * a = va_arg (*args, ip_address_t *);
  u8 ver = ip_addr_version(a);
  if (ver == IP4)
    {
      return format (s, "%U", format_ip4_address, &ip_addr_v4(a));
    }
  else if (ver == IP6)
    {
      return format (s, "%U", format_ip6_address, &ip_addr_v6(a));
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
  ip_address_t * a = va_arg(*args, ip_address_t *);
  if (unformat(input, "%U", unformat_ip4_address, &ip_addr_v4(a)))
    ip_addr_version(a) = IP4;
  else if (unformat_user (input, unformat_ip6_address, &ip_addr_v6(a)))
    ip_addr_version(a) = IP6;
  else
    return 0;
  return 1;
}

u8 *
format_ip_prefix (u8 * s, va_list * args)
{
  ip_prefix_t * a = va_arg (*args, ip_prefix_t *);
  return format (s, "%U/%d", format_ip_address, &ip_prefix_addr(a), ip_prefix_len(a));
}

uword
unformat_ip_prefix (unformat_input_t * input, va_list * args)
{
  ip_prefix_t * a = va_arg(*args, ip_prefix_t *);
  return unformat (input, "%U/%d", unformat_ip_address, &ip_prefix_addr(a),
                   &ip_prefix_len(a));
}

uword
unformat_mac_address (unformat_input_t * input, va_list * args)
{
  u8 * a = va_arg(*args, u8 *);
  return unformat (input, "%x:%x:%x:%x:%x:%x", &a[0], &a[1], &a[2], &a[3],
                   &a[4], &a[5]);
}

u8 *
format_mac_address (u8 * s, va_list * args)
{
  u8 * a = va_arg (*args, u8 *);
  return format (s, "%02x:%02x:%02x:%02x:%02x:%02x",
                 a[0], a[1], a[2], a[3], a[4], a[5]);
}

u8 *
format_gid_address (u8 * s, va_list * args)
{
  gid_address_t * a = va_arg(*args, gid_address_t *);
  u8 type = gid_address_type(a);
  switch (type)
    {
    case GID_ADDR_IP_PREFIX:
      return format (s, "[%d] %U", gid_address_vni(a), format_ip_prefix,
                     &gid_address_ippref(a));
    case GID_ADDR_SRC_DST:
      return format (s, "[%d] %U|%U", gid_address_vni(a),
                     format_ip_prefix, &gid_address_sd_source_pref(a),
                     format_ip_prefix, &gid_address_sd_dest_pref(a));
    case GID_ADDR_MAC:
      return format (s, "[%d] %U", gid_address_vni(a), format_mac_address,
                     &gid_address_mac(a));
    default:
      clib_warning("Can't format gid type %d", type);
      return 0;
    }
}

uword
unformat_gid_address (unformat_input_t * input, va_list * args)
{
  gid_address_t * a = va_arg(*args, gid_address_t *);
  if (unformat (input, "%U", unformat_ip_prefix, &gid_address_ippref(a)))
    gid_address_type(a) = GID_ADDR_IP_PREFIX;
  else
    return 0;
  return 1;
}

u16
ip_address_size (ip_address_t * a)
{
  switch (ip_addr_version (a))
  {
    case IP4:
      return sizeof(ip4_address_t);
      break;
    case IP6:
      return sizeof(ip6_address_t);
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
      return sizeof(ip4_address_t);
      break;
    case IP6:
      return sizeof(ip6_address_t);
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
ip_address_iana_afi(ip_address_t *a)
{
    return ip_version_to_iana_afi(ip_addr_version(a));
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
  *(u16 *)b = clib_host_to_net_u16(ip_version_to_iana_afi(IP4));
  u8 *p = b + sizeof (u16);
  clib_memcpy (p, a, sizeof(*a));
  return ip4_address_size_to_put();
}

u32
ip6_address_put (u8 * b, ip6_address_t * a)
{
  *(u16 *)b = clib_host_to_net_u16(ip_version_to_iana_afi(IP6));
  u8 *p = b + sizeof (u16);
  clib_memcpy (p, a, sizeof(*a));
  return ip6_address_size_to_put();
}

u32
ip_address_put (u8 * b, ip_address_t * a)
{
  u32 len = ip_address_size (a);
  *(u16 *) b = clib_host_to_net_u16(ip_address_iana_afi (a));
  u8 * p = b + sizeof (u16);
  clib_memcpy (p, &ip_addr_addr (a), len);
  return (len + sizeof (u16));
}

u32
ip_address_parse(void * offset, u16 iana_afi, ip_address_t *dst)
{
  ip_addr_version(dst) = ip_iana_afi_to_version (iana_afi);
  u8 size = ip_version_to_size (ip_addr_version(dst));
  clib_memcpy (&ip_addr_addr(dst), offset + sizeof(u16), size);
  return(sizeof(u16) + size);
}

u32
lcaf_hdr_parse (void * offset, lcaf_t * lcaf)
{
  lcaf_hdr_t * lh = offset;
  lcaf->type = lh->type;

  /* this is a bit of hack: since the LCAF Instance ID is the
    only message that uses reserved2 field, we can set it here.
    If any LCAF format starts using reserved2 field as well this needs
    to be moved elsewhere */
  lcaf_vni_len (lcaf) = lh->reserved2;

  return sizeof (lh[0]);
}

u16
vni_parse (u8 * p, void * a)
{
  lcaf_t * lcaf = a;
  gid_address_t * g = a;
  u16 size = 0;

  gid_address_vni (g) = clib_net_to_host_u32 ( *(u32 *) p);
  size += sizeof (u32);
  gid_address_vni_mask (g) = lcaf_vni_len (lcaf);

  /* nested LCAFs are not supported - it is expected that nested AFI type is
     IP address */
  size += gid_address_parse (p + size, g);
  return size;
}

u16
no_addr_parse (u8 * p, void * a)
{
  /* do nothing */
  return 0;
}

u32
lcaf_parse (void * offset, gid_address_t *addr)
{
  /* skip AFI type */
  offset += sizeof (u16);
  lcaf_t * lcaf = &gid_address_lcaf (addr);

  u32 size = lcaf_hdr_parse (offset, lcaf);
  u8 type = lcaf_type (lcaf);

  if (!lcaf_parse_fcts[type])
    {
      clib_warning ("Unsupported LCAF type: %u", type);
      return ~0;
    }
  size += (*lcaf_parse_fcts[type])(offset + size, lcaf);
  return sizeof (u16) + size;
}

void
vni_free (void * a)
{
  vni_t * v = a;
  gid_address_free (vni_gid (v));
  clib_mem_free (vni_gid (v));
}

void
no_addr_free (void * a)
{
  /* nothing to do */
}

void
gid_address_free (gid_address_t *a)
{
  if (gid_address_type (a) != GID_ADDR_LCAF)
    return;

  lcaf_t * lcaf = &gid_address_lcaf (a);
  u8 lcaf_type = lcaf_type (lcaf);
  (*lcaf_free_fcts[lcaf_type])(lcaf);
}

int
ip_address_cmp (ip_address_t * ip1, ip_address_t * ip2)
{
  int res = 0;
  if (ip_addr_version (ip1) != ip_addr_version(ip2))
    return -1;
  res = memcmp (&ip_addr_addr(ip1), &ip_addr_addr(ip2), ip_address_size (ip1));

  if (res < 0)
    res = 2;
  else if (res > 0)
    res = 1;

  return res;
}

void
ip_address_copy (ip_address_t * dst , ip_address_t * src)
{
  clib_memcpy (dst, src, sizeof (ip_address_t));
}

void
ip_address_copy_addr (void * dst , ip_address_t * src)
{
  clib_memcpy (dst, src, ip_address_size(src));
}

void
ip_address_set(ip_address_t * dst, void * src, u8 version)
{
  clib_memcpy(dst, src, ip_version_to_size(version));
  ip_addr_version(dst) = version;
}

void *
ip_prefix_cast (gid_address_t * a)
{
  return &gid_address_ippref(a);
}

u16
ip_prefix_size_to_write (void * pref)
{
  ip_prefix_t *a = (ip_prefix_t *) pref;
  return ip_address_size_to_write (&ip_prefix_addr (a));
}

u16
ip_prefix_write (u8 * p, void * gid)
{
  gid_address_t * g = gid;
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
  return ip_prefix_len((ip_prefix_t *) a);
}

void
ip_prefix_copy (void * dst , void * src)
{
  clib_memcpy (dst, src, sizeof (ip_prefix_t));
}

void
mac_copy (void * dst , void * src)
{
  clib_memcpy (dst, src, 6);
}

int
ip_prefix_cmp(ip_prefix_t * p1, ip_prefix_t * p2)
{
  int cmp = 0;
  cmp = ip_address_cmp (&ip_prefix_addr(p1), &ip_prefix_addr(p2));
  if (cmp == 0)
  {
    if (ip_prefix_len(p1) < ip_prefix_len(p2))
    {
      cmp = 1;
    }
    else
    {
      if (ip_prefix_len(p1) > ip_prefix_len(p2))
        cmp = 2;
    }
  }
  return cmp;
}

void
no_addr_copy (void * dst, void * src)
{
  /* nothing to do */
}

void
vni_copy (void * dst, void * src)
{
  vni_t * vd = dst;
  vni_t * vs = src;

  clib_memcpy (vd, vs, sizeof (vd[0]));
  vni_gid (vd) = clib_mem_alloc (sizeof (gid_address_t));
  gid_address_copy (vni_gid (vd), vni_gid (vs));
}

void
lcaf_copy (void * dst , void * src)
{
  lcaf_t * lcaf_dst = dst;
  lcaf_t * lcaf_src = src;

  lcaf_type (lcaf_dst) = lcaf_type (lcaf_src);
  (*lcaf_copy_fcts[lcaf_type (lcaf_src)])(dst, src);
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

u16
no_addr_length (void * a)
{
  return 0;
}

u16
vni_length (void * a)
{
  vni_t * v = a;
  return (sizeof (u32) /* VNI size */
   + gid_address_size_to_put (vni_gid (v)) /* vni body size*/);
}

u16
lcaf_write (u8 * p, void * a)
{
  u16 size = 0, len;
  lcaf_t * lcaf = a;
  u8 type = lcaf_type (lcaf);
  lcaf_hdr_t _h, *h = &_h;

  *(u16 *) p = clib_host_to_net_u16 (LISP_AFI_LCAF);
  size += sizeof (u16);
  memset (h, 0, sizeof (h[0]));
  LCAF_TYPE (h) = type;
  u16 lcaf_len = (*lcaf_body_length_fcts[type])(lcaf);
  LCAF_LENGTH (h) = clib_host_to_net_u16 (lcaf_len);

  clib_memcpy (p + size, h, sizeof (h[0]));
  size += sizeof (h[0]);
  len = (*lcaf_write_fcts[type])(p + size, lcaf);

  if ((u16)~0 == len)
    return ~0;

  return size + len;
}

u16
mac_write (u8 * p, void * a)
{
  *(u16 *)p = clib_host_to_net_u16 (LISP_AFI_MAC);
  clib_memcpy(p + sizeof (u16), a, 6);
  return mac_size_to_write (a);
}

u16
vni_write (u8 * p, void * a)
{
  lcaf_hdr_t _h, *h = &_h;
  gid_address_t * g = a;
  u16 size = 0, len;

  /* put lcaf header */
  *(u16 *) p = clib_host_to_net_u16 (LISP_AFI_LCAF);
  size += sizeof (u16);
  memset (h, 0, sizeof (h[0]));
  LCAF_TYPE (h) = LCAF_INSTANCE_ID;
  u16 lcaf_len = sizeof (u32) /* Instance ID size */
    + gid_address_size_to_put_no_vni (g);
  LCAF_LENGTH (h) = clib_host_to_net_u16 (lcaf_len);
  LCAF_RES2 (h) = gid_address_vni_mask (g);

  /* put vni header */
  clib_memcpy (p + size, h, sizeof (h[0]));
  size += sizeof (h[0]);

  u32 * afip = (u32 *)(p + size);
  afip[0] = clib_host_to_net_u32 (gid_address_vni (g));
  size += sizeof (u32);

  /* write the actual address */
  len = gid_address_put_no_vni (p + size, g);

  if ((u16)~0 == len)
    return ~0;

  return size + len;
}

u16
no_addr_write (u8 * p, void * a)
{
  /* do nothing; return AFI field size */
  return sizeof (u16);
}

u16
no_addr_size_to_write (void * a)
{
  return sizeof (u16); /* AFI field length */
}

u16
vni_size_to_write (void * a)
{
  gid_address_t * g =  a;
  return (sizeof (u32) /* vni size */
          + sizeof (u16) /* LCAF AFI field size */
          + sizeof (lcaf_hdr_t)
    + gid_address_size_to_put_no_vni (g));
}

u16
lcaf_size_to_write (void * a)
{
  lcaf_t * lcaf = (lcaf_t *) a;
  u32 size = 0, len;
  u8 type = lcaf_type (lcaf);

  size += sizeof (u16); /* AFI size */

  len = (*lcaf_size_to_write_fcts[type])(lcaf);
  if (~0 == len)
    return ~0;

  return size + len;
}

u16
mac_size_to_write (void * a)
{
  return sizeof (u16) + 6;
}

u8
gid_address_len (gid_address_t *a)
{
  gid_address_type_t type = gid_address_type (a);
  return (*addr_len_fcts[type])((*cast_fcts[type])(a));
}

static u16
gid_address_put_no_vni (u8 * b, gid_address_t * gid)
{
  gid_address_type_t type = gid_address_type (gid);
  return (*write_fcts[type])(b, (*cast_fcts[type])(gid));
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
  return (*size_to_write_fcts[type])((*cast_fcts[type])(gid));
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
  return (*cast_fcts[type])(gid);
}

void
gid_address_copy(gid_address_t * dst, gid_address_t * src)
{
  gid_address_type_t type = gid_address_type(src);
  (*copy_fcts[type])((*cast_fcts[type])(dst), (*cast_fcts[type])(src));
  gid_address_type(dst) = type;
  gid_address_vni(dst) = gid_address_vni(src);
  gid_address_vni_mask(dst) = gid_address_vni_mask(src);
}

u32
mac_parse (u8 * offset, gid_address_t * a)
{
  /* skip AFI field */
  offset += sizeof (u16);

  memcpy (gid_address_mac (a), offset, sizeof (gid_address_mac (a)));
  return (sizeof (u16) + sizeof (gid_address_mac (a)));
}

u32
gid_address_parse (u8 * offset, gid_address_t *a)
{
  lisp_afi_e afi;
  int len = 0;

  if (!a)
    return 0;

  /* NOTE: since gid_adress_parse may be called by vni_parse, we can't 0
   * the gid address here */
  afi = clib_net_to_host_u16 (*((u16 *) offset));

  switch (afi)
    {
    case LISP_AFI_NO_ADDR:
      len = sizeof(u16);
      gid_address_type(a) = GID_ADDR_NO_ADDRESS;
      break;
    case LISP_AFI_IP:
      len = ip_address_parse (offset, afi, &gid_address_ip(a));
      gid_address_type(a) = GID_ADDR_IP_PREFIX;
      /* this should be modified outside if needed*/
      gid_address_ippref_len(a) = 32;
      break;
    case LISP_AFI_IP6:
      len = ip_address_parse (offset, afi, &gid_address_ip(a));
      gid_address_type(a) = GID_ADDR_IP_PREFIX;
      /* this should be modified outside if needed*/
      gid_address_ippref_len(a) = 128;
      break;
    case LISP_AFI_LCAF:
      gid_address_type(a) = GID_ADDR_LCAF;
      len = lcaf_parse (offset, a);
      break;
    case LISP_AFI_MAC:
      len = mac_parse (offset, a);
      gid_address_type(a) = GID_ADDR_MAC;
      break;
    default:
      clib_warning("LISP AFI %d not supported!", afi);
      return ~0;
    }
  return len;
}

int
no_addr_cmp (void * a1, void * a2)
{
  return 0;
}

int
vni_cmp (void * a1, void * a2)
{
  vni_t * v1 = a1;
  vni_t * v2 = a2;

  if (vni_mask_len (v1) != vni_mask_len (v2))
    return -1;
  if (vni_vni (v1) != vni_vni (v2))
    return -1;
  return gid_address_cmp (vni_gid (v1), vni_gid (v2));
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
  lcaf_t * lcaf1, * lcaf2;
  int cmp = -1;
  if (!a1 || !a2)
    return -1;
  if (gid_address_type(a1) != gid_address_type(a2))
    return -1;
  if (gid_address_vni(a1) != gid_address_vni(a2))
    return -1;
  if (gid_address_vni_mask(a1) != gid_address_vni_mask(a2))
    return -1;

  switch (gid_address_type(a1))
    {
    case GID_ADDR_NO_ADDRESS:
      if (a1 == a2)
        cmp = 0;
      else
        cmp = 2;
      break;
    case GID_ADDR_IP_PREFIX:
      cmp = ip_prefix_cmp (&gid_address_ippref(a1), &gid_address_ippref(a2));
      break;
    case GID_ADDR_LCAF:
      lcaf1 = &gid_address_lcaf (a1);
      lcaf2 = &gid_address_lcaf (a2);
      if (lcaf_type (lcaf1) == lcaf_type (lcaf2))
        cmp = (*lcaf_cmp_fcts[lcaf_type (lcaf1)])(lcaf1, lcaf2);
      break;
    case GID_ADDR_MAC:
      cmp = memcmp (gid_address_mac (a1), gid_address_mac (a2),
                    sizeof (gid_address_mac (a1)));
      break;
    default:
      break;
    }

  return cmp;
}


u32
locator_parse (void * b, locator_t * loc)
{
  locator_hdr_t * h;
  u8 status = 1; /* locator up */
  int len;

  h = b;
  if (!LOC_REACHABLE(h) && LOC_LOCAL(h))
    status = 0;

  len = gid_address_parse (LOC_ADDR(h), &loc->address);
  if (len == ~0)
    return len;

  loc->state = status;
  loc->local = 0;
  loc->priority = LOC_PRIORITY(h);
  loc->weight = LOC_WEIGHT(h);
  loc->mpriority = LOC_MPRIORITY(h);
  loc->mweight = LOC_MWEIGHT(h);

  return sizeof(locator_hdr_t) + len;
}

void
locator_copy (locator_t * dst, locator_t * src)
{
  /* TODO if gid become more complex, this will need to be changed! */
  clib_memcpy (dst, src, sizeof(*dst));
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
