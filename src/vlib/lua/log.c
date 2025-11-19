/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (c) 2025 Damjan Marion */

#include <vlib/vlib.h>
#include <vlib/log.h>
#include <vlua/vlua.h>

#define foreach_log_level_method                                              \
  _ (emerg, EMERG)                                                            \
  _ (alert, ALERT)                                                            \
  _ (crit, CRIT)                                                              \
  _ (err, ERR)                                                                \
  _ (warn, WARNING)                                                           \
  _ (notice, NOTICE)                                                          \
  _ (info, INFO)                                                              \
  _ (debug, DEBUG)

typedef struct
{
  vlib_log_class_t log_class;
} log_ctx_t;

static clib_error_t *
log_class_resolve (vlua_ns_resolver_fn_args_t *a)
{
  log_ctx_t *ctx = a->context;
  const vlua_val_t *args = a->args;
  char *cl;
  char *scl;

  ASSERT (ctx != 0);
  ASSERT (args && vec_len (args) > 0);

  cl = vec_dup (vlua_val_get_string (args, 0));
  vec_add1 (cl, 0);
  scl = 0;

  if (vec_len (args) > 1)
    {
      scl = vec_dup (vlua_val_get_string (args + 1, 0));
      vec_add1 (scl, 0);
    }

  ctx->log_class = vlib_log_get_class_by_name (cl, scl);
  if (ctx->log_class == VLIB_LOG_INVALID_CLASS)
    ctx->log_class = vlib_log_register_class (cl, scl);

  vec_free (cl);
  vec_free (scl);
  return 0;
}

static clib_error_t *
log_emit (vlua_method_fn_args_t *args, vlib_log_level_t level)
{
  const log_ctx_t *ctx = args->context;
  vlua_val_t *val = args->args;
  u32 msg_len;
  const u8 *msg;

  ASSERT (val && ctx && args->context_size >= sizeof (*ctx));
  msg_len = 0;
  msg = vlua_val_get_string (val, &msg_len);
  vlib_log (level, ctx->log_class, "%.*s", msg_len, msg);
  return 0;
}

static const vlua_val_t *
log_config_table_arg (vlua_val_t *vals)
{
  i32 i;
  i32 count;

  count = (i32) vec_len (vals);
  for (i = count - 1; i >= 0; --i)
    {
      if (vlua_val_type_is_table (&vals[i]))
	return &vals[i];
    }
  return 0;
}

static clib_error_t *
log_parse_level_value (const vlua_val_t *val, vlib_log_level_t *dst)
{
  clib_error_t *err = 0;
  unformat_input_t in;
  const u8 *v = vlua_val_get_string (val, 0);

  unformat_init_vector (&in, vec_dup (v));
  if (!unformat (&in, "%U", unformat_vlib_log_level, dst))
    err = clib_error_return (0, "unknown log level `%v`", v);

  unformat_free (&in);
  return err;
}

#define _(name, upper)                                                        \
  static clib_error_t *log_##name##_method (vlua_method_fn_args_t *args)      \
  {                                                                           \
    return log_emit (args, VLIB_LOG_LEVEL_##upper);                           \
  }
foreach_log_level_method;
#undef _

static clib_error_t *
log_clear_method (vlua_method_fn_args_t *args)
{
  vlib_log_clear (&log_main);
  return 0;
}

static clib_error_t *
log_get_config_method (vlua_method_fn_args_t *args)
{
  const log_ctx_t *ctx = args->context;
  vlib_log_subclass_data_t *sc;
  vlua_val_t *t;

  ASSERT (ctx && args->context_size >= sizeof (*ctx));

  sc = vlib_log_get_subclass_data (ctx->log_class);
  t = vlua_val_vec_add_table (&args->returns);
  vlua_val_table_add_string (t, "level", "%U", format_vlib_log_level,
			     sc->level);
  vlua_val_table_add_string (t, "syslog_level", "%U", format_vlib_log_level,
			     sc->syslog_level);
  vlua_val_table_add_integer (t, "rate_limit", sc->rate_limit);
  return 0;
}

static clib_error_t *
log_set_config_method (vlua_method_fn_args_t *args)
{
  const vlua_val_t *cfg;
  const log_ctx_t *ctx;
  vlib_log_subclass_data_t *sc;
  vlib_log_level_t new_level;
  vlib_log_level_t new_syslog;
  i64 new_rate;
  const vlua_val_t *val;
  clib_error_t *err;

  ASSERT (args->args);
  cfg = log_config_table_arg (args->args);
  if (!cfg)
    return clib_error_return (0, "log.set_config expects table");

  ctx = args->context;
  ASSERT (ctx && args->context_size >= sizeof (*ctx));

  sc = vlib_log_get_subclass_data (ctx->log_class);

  new_level = sc->level;
  new_syslog = sc->syslog_level;
  new_rate = sc->rate_limit;

  val = vlua_val_table_get_entry (cfg, "level");
  if (val)
    {
      if (!vlua_val_type_is_string (val))
	return clib_error_return (0, "level must be string");
      err = log_parse_level_value (val, &new_level);
      if (err)
	return err;
    }

  val = vlua_val_table_get_entry (cfg, "syslog_level");
  if (val)
    {
      if (!vlua_val_type_is_string (val))
	return clib_error_return (0, "syslog_level must be string");
      err = log_parse_level_value (val, &new_syslog);
      if (err)
	return err;
    }

  val = vlua_val_table_get_entry (cfg, "rate_limit");
  if (val)
    {
      if (!vlua_val_type_is_integer (val))
	return clib_error_return (0, "rate_limit must be integer");

      new_rate = vlua_val_get_integer (val);
      if (new_rate < 0)
	return clib_error_return (0, "rate_limit must be non-negative");
    }

  sc->level = new_level;
  sc->syslog_level = new_syslog;
  sc->rate_limit = new_rate;
  return 0;
}

static clib_error_t *
log_ns_init (vlua_handle_t h, vlua_init_fn_args_t *a)
{
  vlua_table_handle_t log_table = a->table_handles[0];
  vlua_table_handle_t class_table = a->table_handles[1];
  vlua_method_handle_t mh;
  vlua_ns_handle_t ns;

  ASSERT (vec_len (a->table_handles) >= 2);
  ASSERT (log_table && class_table);

  mh = vlua_method_add (h, log_table, "clear");
  vlua_method_add_call_args (mh, log_clear_method, 0);

  ns = vlua_ns_create (h, class_table, sizeof (log_ctx_t));
  vlua_ns_add_call_args (ns, log_class_resolve, 1, VLUA_T_STRING);
  vlua_ns_add_call_args (ns, log_class_resolve, 2, VLUA_T_STRING,
			 VLUA_T_STRING);

  mh = vlua_method_add (h, class_table, "get_config");
  vlua_method_add_call_args (mh, log_get_config_method, 0);
  vlua_method_add_call_args (mh, log_get_config_method, 1, VLUA_T_TABLE);

  mh = vlua_method_add (h, class_table, "set_config");
  vlua_method_add_call_args (mh, log_set_config_method, 1, VLUA_T_TABLE);
  vlua_method_add_call_args (mh, log_set_config_method, 2, VLUA_T_TABLE,
			     VLUA_T_TABLE);

#define _(name, upper)                                                        \
  do                                                                          \
    {                                                                         \
      vlua_method_handle_t _mh = vlua_method_add (h, class_table, #name);     \
      vlua_method_add_call_args (_mh, log_##name##_method, 1, VLUA_T_STRING); \
    }                                                                         \
  while (0);
  foreach_log_level_method
#undef _

    return 0;
}

VLUA_REGISTER_INIT_FN (log_ns) = {
  .init_fn = log_ns_init,
  .paths = VLUA_PATHS (".log", ".log.class"),
};
