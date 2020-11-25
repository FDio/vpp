/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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
/**
 * @file syslog.h
 * RFC5424 syslog protocol declarations
 */
#ifndef __included_syslog_h__
#define __included_syslog_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip4_packet.h>

/* syslog message facilities */
#define foreach_syslog_facility                 \
  _(0, KERNEL, "kernel")                        \
  _(1, USER_LEVEL, "user-level")                \
  _(2, MAIL_SYSTEM, "mail-system")              \
  _(3, SYSTEM_DAEMONS, "system-daemons")        \
  _(4, SEC_AUTH, "security-authorization")      \
  _(5, SYSLOGD, "syslogd")                      \
  _(6, LINE_PRINTER, "line-printer")            \
  _(7, NETWORK_NEWS, "network-news")            \
  _(8, UUCP, "uucp")                            \
  _(9, CLOCK, "clock-daemon")                   \
  _(11, FTP, "ftp-daemon")                      \
  _(12, NTP, "ntp-subsystem")                   \
  _(13, LOG_AUDIT, "log-audit")                 \
  _(14, LOG_ALERT, "log-alert")                 \
  _(16, LOCAL0, "local0")                       \
  _(17, LOCAL1, "local1")                       \
  _(18, LOCAL2, "local2")                       \
  _(19, LOCAL3, "local3")                       \
  _(20, LOCAL4, "local4")                       \
  _(21, LOCAL5, "local5")                       \
  _(22, LOCAL6, "local6")                       \
  _(23, LOCAL7, "local7")

typedef enum
{
#define _(v, N, s) SYSLOG_FACILITY_##N = v,
  foreach_syslog_facility
#undef _
} syslog_facility_t;

/* syslog message severities */
#define foreach_syslog_severity        \
  _(0, EMERGENCY, "emergency")         \
  _(1, ALERT, "alert")                 \
  _(2, CRITICAL, "critical")           \
  _(3, ERROR, "error")                 \
  _(4, WARNING, "warning")             \
  _(5, NOTICE, "notice")               \
  _(6, INFORMATIONAL, "informational") \
  _(7, DEBUG, "debug")

typedef enum
{
#define _(v, N, s) SYSLOG_SEVERITY_##N = v,
  foreach_syslog_severity
#undef _
} syslog_severity_t;

/** syslog header */
typedef struct
{
  /** facility value, part of priority */
  syslog_facility_t facility;

  /** severity value, part of priority */
  syslog_severity_t severity;

  /** message timestamp */
  f64 timestamp;

  /** application that originated the message RFC5424 6.2.5. */
  char *app_name;

  /** identify the type of message RFC5424 6.2.7. */
  char *msgid;
} syslog_header_t;

/** syslog message */
typedef struct
{
  /** header */
  syslog_header_t header;

  /** structured data RFC5424 6.3. */
  u8 **structured_data;
  u32 curr_sd_index;

  /** free-form message RFC5424 6.4. */
  u8 *msg;
} syslog_msg_t;

typedef struct
{
  /** process ID RFC5424 6.2.6. */
  u32 procid;

  /** time offset */
  f64 time_offset;

  /** IPv4 address of remote host (destination) */
  ip4_address_t collector;

  /** UDP port number of remote host (destination) */
  u16 collector_port;

  /** IPv4 address of sender (source) */
  ip4_address_t src_address;

  /** FIB table index */
  u32 fib_index;

  /** message size limit */
  u32 max_msg_size;

  /** severity filter (specified severity and greater match) */
  syslog_severity_t severity_filter;

  /** ip4-lookup node index */
  u32 ip4_lookup_node_index;

  /** convenience variables */
  vnet_main_t *vnet_main;
} syslog_main_t;

extern syslog_main_t syslog_main;

/**
 * @brief Initialize syslog message header
 *
 * @param facility facility value
 * @param severity severity level
 * @param app_name application that originated message RFC424 6.2.5. (optional)
 * @param msgid identify the type of message RFC5424 6.2.7. (optional)
 */
void syslog_msg_init (syslog_msg_t * syslog_msg, syslog_facility_t facility,
		      syslog_severity_t severity, char *app_name,
		      char *msgid);
/**
 * @brief Initialize structured data element
 *
 * @param sd_id structured data element name RFC5424 6.3.2.
 */
void syslog_msg_sd_init (syslog_msg_t * syslog_msg, char *sd_id);

/**
 * @brief Add structured data elemnt parameter name-value pair RFC5424 6.3.3.
 */
void syslog_msg_add_sd_param (syslog_msg_t * syslog_msg, char *name,
			      char *fmt, ...);

/**
 * @brief Add free-form message RFC5424 6.4.
 */
void syslog_msg_add_msg (syslog_msg_t * syslog_msg, char *fmt, ...);

/**
 * @brief Send syslog message
 */
int syslog_msg_send (syslog_msg_t * syslog_msg);

/**
 * @brief Set syslog sender configuration
 *
 * @param collector IPv4 address of syslog collector (destination)
 * @param collector_port UDP port of syslog colector (destination)
 * @param src IPv4 address of syslog sender (source)
 * @param vrf_id VRF/FIB table ID
 * @param max_msg_size maximum message length
 */
vnet_api_error_t set_syslog_sender (ip4_address_t * collector,
				    u16 collector_port, ip4_address_t * src,
				    u32 vrf_id, u32 max_msg_size);

/**
 * @brief Check if syslog logging is enabled
 *
 * @return 1 if syslog logging is enabled, 0 otherwise
 */
always_inline int
syslog_is_enabled (void)
{
  syslog_main_t *sm = &syslog_main;

  return sm->collector.as_u32 ? 1 : 0;
}

/**
 * @brief Severity filter test
 *
 * @return 1 if message with specified severity is not selected to be logged
 */
always_inline int
syslog_severity_filter_block (syslog_severity_t s)
{
  syslog_main_t *sm = &syslog_main;

  return (sm->severity_filter < s);
}

#endif /* __included_syslog_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
