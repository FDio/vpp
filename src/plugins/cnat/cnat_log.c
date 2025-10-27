#include <vppinfra/elog.h>
#include "cnat_session.h"
#include "cnat_log.h"

#define CNAT_LOG_IP4_FMT	   "%d.%d.%d.%d"
#define CNAT_LOG_IP4_FMT_ARGS	   "i1i1i1i1"
#define CNAT_LOG_PORT_FMT	   "%d"
#define CNAT_LOG_PORT_FMT_ARGS	   "i2"
#define CNAT_LOG_IP4_PORT_FMT	   CNAT_LOG_IP4_FMT ":" CNAT_LOG_PORT_FMT
#define CNAT_LOG_IP4_PORT_FMT_ARGS CNAT_LOG_IP4_FMT_ARGS CNAT_LOG_PORT_FMT_ARGS

#define CNAT_LOG_SESSION_FMT                                                  \
  "index %d proto %d return %d " CNAT_LOG_IP4_PORT_FMT                        \
  "->" CNAT_LOG_IP4_PORT_FMT
#define CNAT_LOG_SESSION_FMT_ARGS                                             \
  "i4i1i1" CNAT_LOG_IP4_PORT_FMT_ARGS CNAT_LOG_IP4_PORT_FMT_ARGS

cnat_log_main_t cnat_log_main;

static void
cnat_log_session (const cnat_session_t *s, elog_event_type_t *e)
{
  struct
  {
    u32 session_index;
    u8 ip_proto;
    u8 is_return;
    u32 ip1;
    u16 port1;
    u32 ip2;
    u16 port2;
  } __clib_packed *ed = ELOG_DATA (vlib_get_elog_main (), *e);
  ed->session_index = s->value.cs_session_index;
  ed->ip_proto = s->key.cs_5tuple.iproto;
  ed->is_return = !!(s->value.cs_flags & CNAT_SESSION_IS_RETURN);
  ed->ip1 = s->key.cs_5tuple.ip[VLIB_RX].ip4.as_u32;
  ed->port1 = clib_net_to_host_u16 (s->key.cs_5tuple.port[VLIB_RX]);
  ed->ip2 = s->key.cs_5tuple.ip[VLIB_TX].ip4.as_u32;
  ed->port2 = clib_net_to_host_u16 (s->key.cs_5tuple.port[VLIB_TX]);
}

void
cnat_log_session_create__ (const cnat_session_t *s)
{
  ELOG_TYPE_DECLARE (e) = {
    .format = "cnat-session-new: " CNAT_LOG_SESSION_FMT,
    .format_args = CNAT_LOG_SESSION_FMT_ARGS,
  };
  cnat_log_session (s, &e);
}

void
cnat_log_session_free__ (const cnat_session_t *s)
{
  ELOG_TYPE_DECLARE (e) = {
    .format = "cnat-session-free: " CNAT_LOG_SESSION_FMT,
    .format_args = CNAT_LOG_SESSION_FMT_ARGS,
  };
  cnat_log_session (s, &e);
}

void
cnat_log_session_overwrite__ (const cnat_session_t *s)
{
  ELOG_TYPE_DECLARE (e) = {
    .format = "cnat-session-overwrite: " CNAT_LOG_SESSION_FMT,
    .format_args = CNAT_LOG_SESSION_FMT_ARGS,
  };
  cnat_log_session (s, &e);
}

void
cnat_log_session_expire__ (const cnat_session_t *s)
{
  ELOG_TYPE_DECLARE (e) = {
    .format = "cnat-session-expire: " CNAT_LOG_SESSION_FMT,
    .format_args = CNAT_LOG_SESSION_FMT_ARGS,
  };
  cnat_log_session (s, &e);
}

static void
cnat_log_scanner__ (int i, elog_event_type_t *e)
{
  if (PREDICT_FALSE (cnat_log_main.enabled))
    ELOG (vlib_get_elog_main (), *e, i);
}

void
cnat_log_scanner_start (int i)
{
  ELOG_TYPE_DECLARE (e) = {
    .format = "cnat-scanner-start: %d",
    .format_args = "i4",
  };
  cnat_log_scanner__ (i, &e);
}

void
cnat_log_scanner_stop (int i)
{
  ELOG_TYPE_DECLARE (e) = {
    .format = "cnat-scanner-stop: %d",
    .format_args = "i4",
  };
  cnat_log_scanner__ (i, &e);
}

void
cnat_log_enable_disable (const ip46_address_t *ip, int enable)
{
  cnat_log_main_t *clm = &cnat_log_main;
  if (ip)
    clm->ip = *ip;
  else
    ip46_address_reset (&clm->ip);
  clm->enabled = enable;
}

static clib_error_t *
cnat_log_enable_disable_cli (vlib_main_t *vm, unformat_input_t *input,
			     vlib_cli_command_t *cmd)
{
  ip46_address_t ip = ip46_address_initializer;
  int enable = 1;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "enable"))
	enable = 1;
      else if (unformat (input, "disable"))
	enable = 0;
      else if (unformat (input, "ip %U", unformat_ip46_address, &ip,
			 IP46_TYPE_ANY))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  cnat_log_enable_disable (&ip, enable);
  return 0;
}

VLIB_CLI_COMMAND (cnat_log_enable_disable_cmd, static) = {
  .path = "cnat log",
  .function = cnat_log_enable_disable_cli,
  .short_help = "cnat log [enable|disable] [ip <ip>]",
  .is_mp_safe = 1,
};
