/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <vnet/dev/log.h>

VLIB_REGISTER_LOG_CLASS (dev_log, static) = {
  .class_name = "dev",
  .subclass_name = "rss",
};

static char *class_names[] = {
#define _(n, s, p) [VNET_DEV_RSS_CLASS_##n] = s,
  foreach_vnet_dev_rss_class
#undef _
};

static char *function_names[] = {
#define _(n, s) [VNET_DEV_RSS_FUNCTION_##n] = s,
  foreach_vnet_dev_rss_function
#undef _
};

u8 *
format_vnet_dev_rss_class (u8 *s, va_list *args)
{
  u32 class = va_arg (*args, u32);

  if (class < VNET_DEV_RSS_N_CLASSES)
    return format (s, "%s", class_names[class]);
  return format (s, "unknown(%u)", class);
}

u8 *
format_vnet_dev_rss_function (u8 *s, va_list *args)
{
  u32 function = va_arg (*args, u32);

  if (function < VNET_DEV_RSS_N_FUNCTIONS)
    return format (s, "%s", function_names[function]);
  return format (s, "unknown(%u)", function);
}

/* aliases first, the first matching name is the one shown */
static const struct
{
  char *name;
  u32 fields;
} field_names[] = {
#define _(n, v, h) { n, v },
  foreach_vnet_dev_rss_fields_alias
#undef _
#define _(v, n, s, h) { s, v },
    foreach_vnet_dev_rss_field
#undef _
  { "inherit", VNET_DEV_RSS_FIELDS_INHERIT },
};

u8 *
format_vnet_dev_rss_fields (u8 *s, va_list *args)
{
  u32 fields = va_arg (*args, u32) & VNET_DEV_RSS_FIELDS_MASK;
  char *sep = "";

  /* inner first, then the fields it applies to, e.g. inner,4-tuple */
  if ((fields & VNET_DEV_RSS_FIELDS_INNER) && fields != VNET_DEV_RSS_FIELDS_INNER)
    {
      s = format (s, "inner,");
      fields &= ~VNET_DEV_RSS_FIELDS_INNER;
    }

  for (u32 i = 0; i < ARRAY_LEN (field_names); i++)
    if (field_names[i].fields == fields)
      return format (s, "%s", field_names[i].name);

  for (u32 i = 0; i < ARRAY_LEN (field_names); i++)
    if (count_set_bits (field_names[i].fields) == 1 && (fields & field_names[i].fields))
      {
	s = format (s, "%s%s", sep, field_names[i].name);
	sep = ",";
      }

  return s;
}

static int
rss_fields_word (u8 *w, u32 len, u32 *fields)
{
  for (u32 i = 0; i < ARRAY_LEN (field_names); i++)
    if (len == strlen (field_names[i].name) && memcmp (w, field_names[i].name, len) == 0)
      {
	*fields = field_names[i].fields;
	return 1;
      }

  return 0;
}

/* <alias>, inherit or a comma separated list of fields, into u32 * */
uword
unformat_vnet_dev_rss_fields (unformat_input_t *input, va_list *args)
{
  u32 *result = va_arg (*args, u32 *);
  u32 fields = 0, start = 0, len, f;
  uword rv = 0;
  u8 *tok;

  if (!unformat (input, "%s", &tok))
    return 0;

  len = strlen ((char *) tok);
  for (u32 i = 0; i <= len; i++)
    {
      if (i < len && tok[i] != ',')
	continue;
      if (!rss_fields_word (tok + start, i - start, &f))
	goto done;
      fields |= f;
      start = i + 1;
    }

  if ((fields & VNET_DEV_RSS_FIELDS_INHERIT) && fields != VNET_DEV_RSS_FIELDS_INHERIT)
    goto done;

  *result = fields;
  rv = 1;

done:
  vec_free (tok);
  return rv;
}

static uword
unformat_name (unformat_input_t *input, char **names, u32 n_names, u32 *result)
{
  uword rv = 0;
  u8 *tok;

  if (!unformat (input, "%s", &tok))
    return 0;

  for (u32 i = 0; i < n_names; i++)
    if (strcmp ((char *) tok, names[i]) == 0)
      {
	*result = i;
	rv = 1;
	break;
      }

  vec_free (tok);
  return rv;
}

uword
unformat_vnet_dev_rss_class (unformat_input_t *input, va_list *args)
{
  u32 *class = va_arg (*args, u32 *);
  return unformat_name (input, class_names, ARRAY_LEN (class_names), class);
}

uword
unformat_vnet_dev_rss_function (unformat_input_t *input, va_list *args)
{
  u32 *function = va_arg (*args, u32 *);
  return unformat_name (input, function_names, ARRAY_LEN (function_names), function);
}

void
vnet_dev_rss_config_set_class (vnet_dev_rss_config_t *cfg, vnet_dev_rss_class_t class, u32 fields)
{
  if (fields & VNET_DEV_RSS_FIELDS_INHERIT)
    {
      cfg->fields[class].as_u32 = 0;
      cfg->reset_classes |= 1 << class;
      return;
    }

  cfg->fields[class].as_u32 = fields & VNET_DEV_RSS_FIELDS_MASK;
  cfg->fields[class].is_set = 1;
  cfg->reset_classes &= ~(1 << class);
}

void
vnet_dev_rss_config_merge (vnet_dev_rss_config_t *cfg, const vnet_dev_rss_config_t *req)
{
  if (req->set_key)
    {
      clib_memcpy (cfg->key, req->key, sizeof (cfg->key));
      cfg->key_len = req->key_len;
      cfg->set_key = 1;
    }

  if (req->set_lut)
    {
      clib_memcpy (cfg->lut, req->lut, sizeof (cfg->lut));
      cfg->lut_len = req->lut_len;
      cfg->set_lut = 1;
    }

  if (req->set_function)
    {
      cfg->function = req->function;
      cfg->set_function = 1;
    }

  for (u32 i = 0; i < VNET_DEV_RSS_N_CLASSES; i++)
    if (req->fields[i].is_set)
      cfg->fields[i] = req->fields[i];
    else if (req->reset_classes & (1 << i))
      cfg->fields[i].as_u32 = 0;
}

/* 1 if the class can hash on fields, no-hash if fields is 0 */
static int
vnet_dev_rss_class_accepts (const vnet_dev_rss_class_caps_t *c, u32 fields)
{
  if (fields == 0)
    return c->no_hash;

  if (fields & ~c->fields.as_u32)
    return 0;

  if (c->any)
    return 1;

  for (u32 i = 0; i < c->n_sets; i++)
    if (c->sets[i].as_u32 == fields)
      return 1;

  return 0;
}

/* checks req against the port capabilities, on failure returns an error and,
 * if errp is set, the reason */
vnet_dev_rv_t
vnet_dev_rss_config_validate (vnet_dev_port_t *port, const vnet_dev_rss_config_t *req, u8 **errp)
{
  const vnet_dev_rss_caps_t *caps = &port->attr.rss_caps;
  vnet_dev_rv_t rv = VNET_DEV_OK;
  u8 *err = 0;

  if (req->set_function &&
      (req->function >= VNET_DEV_RSS_N_FUNCTIONS || (caps->functions & (1 << req->function)) == 0))
    {
      err =
	format (0, "rss function %U is not supported", format_vnet_dev_rss_function, req->function);
      rv = VNET_DEV_ERR_NOT_SUPPORTED;
      goto done;
    }

  if (req->reset_classes >> VNET_DEV_RSS_N_CLASSES ||
      req->reset_classes & (1 << VNET_DEV_RSS_CLASS_DEFAULT))
    {
      err = format (0, "rss class default can't inherit");
      rv = VNET_DEV_ERR_INVALID_VALUE;
      goto done;
    }

  for (u32 i = 0; i < VNET_DEV_RSS_N_CLASSES; i++)
    {
      const vnet_dev_rss_class_caps_t *c = caps->classes + i;
      vnet_dev_rss_fields_t f = req->fields[i];
      u32 mask = f.as_u32 & VNET_DEV_RSS_FIELDS_MASK;

      if (f.is_set == 0 && (req->reset_classes & (1 << i)) == 0)
	continue;

      if (f._reserved || (f.is_set && (req->reset_classes & (1 << i))))
	{
	  err = format (0, "rss class %U has invalid fields", format_vnet_dev_rss_class, i);
	  rv = VNET_DEV_ERR_INVALID_VALUE;
	  goto done;
	}

      if (c->fields.as_u32 == 0 && c->no_hash == 0)
	{
	  err = format (0, "rss class %U can't be set", format_vnet_dev_rss_class, i);
	  rv = VNET_DEV_ERR_NOT_SUPPORTED;
	  goto done;
	}

      if (f.is_set && vnet_dev_rss_class_accepts (c, mask) == 0)
	{
	  if (mask)
	    err = format (0, "rss class %U doesn't support fields %U", format_vnet_dev_rss_class, i,
			  format_vnet_dev_rss_fields, mask);
	  else
	    err = format (0, "rss class %U doesn't support no-hash", format_vnet_dev_rss_class, i);
	  rv = VNET_DEV_ERR_NOT_SUPPORTED;
	  goto done;
	}
    }

done:
  if (err && errp)
    *errp = err;
  else if (err)
    {
      log_err (port->dev, "port %u: %v", port->port_id, err);
      vec_free (err);
    }
  return rv;
}

void
vnet_dev_rss_config_set_defaults (vnet_dev_port_t *port)
{
  vnet_dev_rss_caps_t *caps = &port->attr.rss_caps;
  vnet_dev_rss_config_t *cfg = &port->rss_config;
  vnet_dev_rss_class_t ip[] = { VNET_DEV_RSS_CLASS_IP4, VNET_DEV_RSS_CLASS_IP6 };

  if (!vnet_dev_rss_caps_has_fields (caps))
    return;

  /* traffic the device doesn't hash as IP isn't hashed, so default can always be no-hash */
  caps->classes[VNET_DEV_RSS_CLASS_DEFAULT].no_hash = 1;

  /* default (non-IP traffic) stays no-hash, IPv4 and IPv6 hash 4-tuple if they can */
  for (u32 i = 0; i < ARRAY_LEN (ip); i++)
    {
      const vnet_dev_rss_class_caps_t *c = caps->classes + ip[i];

      if (cfg->fields[ip[i]].is_set)
	continue;
      if (vnet_dev_rss_class_accepts (c, VNET_DEV_RSS_FIELDS_4_TUPLE))
	vnet_dev_rss_config_set_class (cfg, ip[i], VNET_DEV_RSS_FIELDS_4_TUPLE);
      else if (vnet_dev_rss_class_accepts (c, VNET_DEV_RSS_FIELDS_2_TUPLE))
	vnet_dev_rss_config_set_class (cfg, ip[i], VNET_DEV_RSS_FIELDS_2_TUPLE);
    }

  /* toeplitz if the device has it, otherwise its first function */
  if (caps->functions && (caps->functions & (1 << cfg->function)) == 0)
    {
      if (caps->functions & VNET_DEV_RSS_FUNCTION (TOEPLITZ))
	cfg->function = VNET_DEV_RSS_FUNCTION_TOEPLITZ;
      else
	cfg->function = count_trailing_zeros (caps->functions);
    }

  ASSERT (caps->functions & (1 << cfg->function));
  ASSERT (cfg->reset_classes == 0);
  ASSERT (vnet_dev_rss_config_validate (port, cfg, 0) == VNET_DEV_OK);
}

static const struct
{
  vnet_dev_rss_class_t ip, l4[2];
  vnet_dev_rss_tuple_types_t ip_type, l4_type[2];
} tuple_families[] = {
  {
    .ip = VNET_DEV_RSS_CLASS_IP4,
    .l4 = { VNET_DEV_RSS_CLASS_IP4_TCP, VNET_DEV_RSS_CLASS_IP4_UDP },
    .ip_type.ip4 = 1,
    .l4_type = { { .ip4_tcp = 1 }, { .ip4_udp = 1 } },
  },
  {
    .ip = VNET_DEV_RSS_CLASS_IP6,
    .l4 = { VNET_DEV_RSS_CLASS_IP6_TCP, VNET_DEV_RSS_CLASS_IP6_UDP },
    .ip_type.ip6 = 1,
    .l4_type = { { .ip6_tcp = 1 }, { .ip6_udp = 1 } },
  },
};

/* a tcp or udp type which is off falls back to the ip type, so the class can
 * only differ from the ip class with 4-tuple. Returns 0 if the config can't be
 * expressed with the supported types. */
int
vnet_dev_rss_tuple_types (const vnet_dev_rss_config_t *cfg, vnet_dev_rss_tuple_types_t supported,
			  vnet_dev_rss_tuple_types_t *types)
{
  types->as_u8 = 0;

  for (u32 i = 0; i < ARRAY_LEN (tuple_families); i++)
    {
      u32 ip =
	vnet_dev_rss_class_fields (cfg, tuple_families[i].ip).as_u32 & VNET_DEV_RSS_FIELDS_2_TUPLE;

      if (ip && ip != VNET_DEV_RSS_FIELDS_2_TUPLE)
	return 0;
      if (ip)
	types->as_u8 |= tuple_families[i].ip_type.as_u8;

      for (u32 j = 0; j < 2; j++)
	{
	  u32 l4 = vnet_dev_rss_class_fields (cfg, tuple_families[i].l4[j]).as_u32 &
		   VNET_DEV_RSS_FIELDS_MASK;

	  if (l4 == VNET_DEV_RSS_FIELDS_4_TUPLE)
	    types->as_u8 |= tuple_families[i].l4_type[j].as_u8;
	  else if (l4 != ip)
	    return 0;
	}
    }

  return (types->as_u8 & ~supported.as_u8) == 0;
}
