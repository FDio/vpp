/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <edma_hw.h>
#include <qppe.h>
#include <ppe_hw.h>

static const qppe_reg_field_t ppe_reg_rss_hash_mask_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_rss_hash_mask_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_rss_hash_seed_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_rss_hash_seed_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_rss_hash_mix_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_rss_hash_mix_t_fields
#undef _
};

static const qppe_reg_field_t ppe_reg_rss_hash_fin_fields[] = {
#define _(n_bits, name)                                                                            \
  {                                                                                                \
    #name,                                                                                         \
    n_bits,                                                                                        \
  },
  foreach_ppe_reg_rss_hash_fin_t_fields
#undef _
};

u8 *
format_qppe_rss_cfg (u8 *s, va_list *args)
{
  vnet_dev_t *dev = va_arg (*args, vnet_dev_t *);
  qppe_device_t *qd = vnet_dev_get_data (dev);
  const struct
  {
    const char *name;
    u32 reg;
    u32 count;
    const qppe_reg_field_t *fields;
    uword n_fields;
  } registers[] = {
    {
      "RSS_HASH_MASK_REG",
      HPPE_REG_RSS_HASH_MASK,
      1,
      ppe_reg_rss_hash_mask_fields,
      ARRAY_LEN (ppe_reg_rss_hash_mask_fields),
    },
    {
      "RSS_HASH_SEED_REG",
      HPPE_REG_RSS_HASH_SEED,
      1,
      ppe_reg_rss_hash_seed_fields,
      ARRAY_LEN (ppe_reg_rss_hash_seed_fields),
    },
    {
      "RSS_HASH_MIX_REG",
      HPPE_REG_RSS_HASH_MIX (0),
      HPPE_RSS_HASH_MIX_COUNT,
      ppe_reg_rss_hash_mix_fields,
      ARRAY_LEN (ppe_reg_rss_hash_mix_fields),
    },
    {
      "RSS_HASH_FIN_REG",
      HPPE_REG_RSS_HASH_FIN (0),
      HPPE_RSS_HASH_FIN_COUNT,
      ppe_reg_rss_hash_fin_fields,
      ARRAY_LEN (ppe_reg_rss_hash_fin_fields),
    },
    {
      "RSS_HASH_MASK_IPV4_REG",
      HPPE_REG_RSS_HASH_MASK_IPV4,
      1,
      ppe_reg_rss_hash_mask_fields,
      ARRAY_LEN (ppe_reg_rss_hash_mask_fields),
    },
    {
      "RSS_HASH_SEED_IPV4_REG",
      HPPE_REG_RSS_HASH_SEED_IPV4,
      1,
      ppe_reg_rss_hash_seed_fields,
      ARRAY_LEN (ppe_reg_rss_hash_seed_fields),
    },
    {
      "RSS_HASH_MIX_IPV4_REG",
      HPPE_REG_RSS_HASH_MIX_IPV4 (0),
      HPPE_RSS_HASH_MIX_IPV4_COUNT,
      ppe_reg_rss_hash_mix_fields,
      ARRAY_LEN (ppe_reg_rss_hash_mix_fields),
    },
    {
      "RSS_HASH_FIN_IPV4_REG",
      HPPE_REG_RSS_HASH_FIN_IPV4 (0),
      HPPE_RSS_HASH_FIN_COUNT,
      ppe_reg_rss_hash_fin_fields,
      ARRAY_LEN (ppe_reg_rss_hash_fin_fields),
    },
  };
  u32 indent = format_get_indent (s);

  if (!qd->regs)
    return s;

  for (u32 i = 0; i < ARRAY_LEN (registers); i++)
    for (u32 j = 0; j < registers[i].count; j++)
      {
	u32 value = qppe_mmio_read32 (qd, registers[i].reg + j * HPPE_RSS_REG_STRIDE);
	u8 *name = registers[i].count == 1 ? format (0, "%s%c", registers[i].name, 0) :
					     format (0, "%s[%u]%c", registers[i].name, j, 0);

	if (i || j)
	  {
	    s = format (s, "\n");
	    s = format_newline (s, indent);
	  }
	s = format (s, "%s: 0x%08x", name, value);
	vec_free (name);
	s = format_newline (s, indent + 2);
	s = format (s, "%U", format_qppe_reg_fields, value, registers[i].fields,
		    registers[i].n_fields);
      }

  return s;
}
