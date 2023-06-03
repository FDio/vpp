/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco Systems, Inc.
 */

#include "vlib/usb/usb_cdc.h"
#include "vppinfra/cache.h"
#include "vppinfra/error.h"
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <usbnet/usbnet.h>
#include <vlib/usb/usb.h>
#include <vnet/ethernet/ethernet.h>
#include "vlib/usb/usb_descriptors.h"

VLIB_REGISTER_LOG_CLASS (usbnet_dev, static) = {
  .class_name = "usbnet",
  .subclass_name = "mbim",
  .default_syslog_level = VLIB_LOG_LEVEL_DEBUG,
};

#define USB_TIMEOUT 1000

#define log_debug(d, fmt, ...)                                                \
  vlib_log_debug (usbnet_dev.class, "[%u/%u]: " fmt, d->busnum, d->devnum,    \
		  __VA_ARGS__)
#define log_notice(d, fmt, ...)                                               \
  vlib_log_notice (usbnet_dev.class, "[%u/%u]: " fmt, d->busnum, d->devnum,   \
		   __VA_ARGS__)
#define log_warn(d, fmt, ...)                                                 \
  vlib_log_warn (usbnet_dev.class, "[%u/%u]: " fmt, d->busnum, d->devnum,     \
		 __VA_ARGS__)
#define log_err(d, fmt, ...)                                                  \
  vlib_log_err (usbnet_dev.class, "[%u/%u]: " fmt, d->busnum, d->devnum,      \
		__VA_ARGS__)

#define CDC_MBIM_OPEN_MSG  0x01
#define CDC_MBIM_CLOSE_MSG 0x02

#define foreach_mbim_status                                                   \
  _ (0, SUCCESS)                                                              \
  _ (1, BUSY)                                                                 \
  _ (2, FAILURE)                                                              \
  _ (3, SIM_NOT_INSERTED)                                                     \
  _ (4, BAD_SIM)                                                              \
  _ (5, PIN_REQUIRED)                                                         \
  _ (6, PIN_DISABLED)                                                         \
  _ (7, NOT_REGISTERED)                                                       \
  _ (8, PROVIDERS_NOT_FOUND)                                                  \
  _ (9, NO_DEVICE_SUPPORT)                                                    \
  _ (10, PROVIDER_NOT_VISIBLE)                                                \
  _ (11, DATA_CLASS_NOT_AVAILABLE)                                            \
  _ (12, PACKET_SERVICE_DETACHED)                                             \
  _ (13, MAX_ACTIVATED_CONTEXTS)                                              \
  _ (14, NOT_INITIALIZED)                                                     \
  _ (15, VOICE_CALL_IN_PROGRESS)                                              \
  _ (16, CONTEXT_NOT_ACTIVATED)                                               \
  _ (17, SERVICE_NOT_ACTIVATED)                                               \
  _ (18, INVALID_ACCESS_STRING)                                               \
  _ (19, INVALID_USER_NAME_PWD)                                               \
  _ (20, RADIO_POWER_OFF)                                                     \
  _ (21, INVALID_PARAMETERS)                                                  \
  _ (22, READ_FAILURE)                                                        \
  _ (23, WRITE_FAILURE)                                                       \
  _ (25, NO_PHONEBOOK)                                                        \
  _ (26, PARAMETER_TOO_LONG)                                                  \
  _ (27, STK_BUSY)                                                            \
  _ (28, OPERATION_NOT_ALLOWED)                                               \
  _ (29, MEMORY_FAILURE)                                                      \
  _ (30, INVALID_MEMORY_INDEX)                                                \
  _ (31, MEMORY_FULL)                                                         \
  _ (32, FILTER_NOT_SUPPORTED)                                                \
  _ (33, DSS_INSTANCE_LIMIT)                                                  \
  _ (34, INVALID_DEVICE_SERVICE_OPERATION)                                    \
  _ (35, AUTH_INCORRECT_AUTN)                                                 \
  _ (36, AUTH_SYNC_FAILURE)                                                   \
  _ (37, AUTH_AMF_NOT_SET)                                                    \
  _ (38, CONTEXT_NOT_SUPPORTED)                                               \
  _ (100, SMS_UNKNOWN_SMSC_ADDRESS)                                           \
  _ (101, SMS_NETWORK_TIMEOUT)                                                \
  _ (102, SMS_LANG_NOT_SUPPORTED)                                             \
  _ (103, SMS_ENCODING_NOT_SUPPORTED)                                         \
  _ (104, SMS_FORMAT_NOT_SUPPORTED)

typedef enum
{
#define _(n, s) USBNET_MBIM_STATUS_##s = (n),
  foreach_mbim_status
#undef _
} usbnet_mbim_status_t;

typedef struct
{
  u32 MessageType;
  u32 MessageLength;
  u32 TransactionId;
} cdc_mbim_msg_hdr_t;
STATIC_ASSERT_SIZEOF (cdc_mbim_msg_hdr_t, 12);

typedef struct
{
  u32 MessageType;
  u32 MessageLength;
} cdc_mbim_frag_hdr_t;
STATIC_ASSERT_SIZEOF (cdc_mbim_frag_hdr_t, 8);

typedef struct
{
  cdc_mbim_msg_hdr_t hdr;
  u32 MaxControlTransfer;
} cdc_mbim_open_msg_t;
STATIC_ASSERT_SIZEOF (cdc_mbim_open_msg_t, 16);

typedef struct
{
  cdc_mbim_msg_hdr_t hdr;
  usbnet_mbim_status_t Status;
} cdc_mbim_open_done_t;
STATIC_ASSERT_SIZEOF (cdc_mbim_open_done_t, 16);

typedef struct
{
  cdc_mbim_msg_hdr_t hdr;
} cdc_mbim_close_msg_t;
STATIC_ASSERT_SIZEOF (cdc_mbim_close_msg_t, 12);

typedef struct
{
  cdc_mbim_msg_hdr_t hdr;
  usbnet_mbim_status_t Status;
} cdc_mbim_close_done_t;
STATIC_ASSERT_SIZEOF (cdc_mbim_close_done_t, 16);

typedef struct
{
  cdc_mbim_msg_hdr_t hdr;
  cdc_mbim_frag_hdr_t frag;
  uint8_t DeviceServiceId[16];
  u32 cid;
  u32 CommandType;
  u32 InformationBufferLength;
  uint8_t InformationBuffer[0];
} cdc_mbim_command_msg_t;
STATIC_ASSERT_SIZEOF (cdc_mbim_command_msg_t, 48);

u8 *
format_cdc_mbim_status (u8 *s, va_list *args)
{
  usbnet_mbim_status_t st = va_arg (*args, usbnet_mbim_status_t);
  char *strings[] = {
#define _(n, s) [n] = #s,
    foreach_mbim_status
#undef _
  };
  if (st >= ARRAY_LEN (strings) || strings[st] == 0)
    return format (s, "UNKNOWN_STATUS(%u)", st);

  return format (s, "%s", strings[st]);
}
u8 *
format_cdc_mbim_msg_hdr (u8 *s, va_list *args)
{
  cdc_mbim_msg_hdr_t *h = va_arg (*args, cdc_mbim_msg_hdr_t *);

  return format (s, "len %u type 0x%08x transaction_id %u", h->MessageLength,
		 h->MessageType, h->TransactionId);
}

static clib_error_t *
usbnet_mbim_send_recv (vlib_main_t *vm, usbnet_dev_t *ud, void *msg,
		       u32 msg_sz, void *resp, u32 resp_sz)
{
  clib_error_t *err;

  vlib_usb_ctrl_xfer_t send_cmd = {
    .req = { .bmRequestType = VLIB_USB_REQ_TYPE_CLASS_INTERFACE_OUT,
	     .bRequest = CDC_SEND_ENCAPSULATED_COMMAND,
	     .wIndex = ud->ctrl_if,
	     .wLength = msg_sz },
    .data = msg,
    .timeout = 0.5f
  };

  vlib_usb_ctrl_xfer_t get_resp = {
    .req = { .bmRequestType = VLIB_USB_REQ_TYPE_CLASS_INTERFACE_IN,
	     .bRequest = CDC_GET_ENCAPSULATED_RESPONSE,
	     .wIndex = ud->ctrl_if,
	     .wLength = resp_sz },
    .data = resp,
    .timeout = 0.5f
  };

  log_debug (ud, "send_cmd: %U", format_hexdump, msg, msg_sz);
  if ((err = vlib_usb_ctrl_xfer (vm, ud->dh, &send_cmd)))
    return err;

  if (1 && (err = vlib_usb_ctrl_xfer (vm, ud->dh, &get_resp)))
    return err;
  log_debug (ud, "get_resp: %U", format_hexdump, resp,
	     get_resp.bytes_received);
  return 0;
}

clib_error_t *
usbnet_mbim_reset (vlib_main_t *vm, usbnet_dev_t *ud)
{
  clib_error_t *err;

  vlib_usb_ctrl_xfer_t reset_cmd = {
    .req = { .bmRequestType = VLIB_USB_REQ_TYPE_CLASS_INTERFACE_OUT,
	     .bRequest = MBIM_CLASS_RESET_FUNCTION,
	     .wIndex = ud->ctrl_if },
    .timeout = 0.5f
  };

  log_debug (ud, "reset: if %u", ud->ctrl_if);
  if ((err = vlib_usb_ctrl_xfer (vm, ud->dh, &reset_cmd)))
    return err;

  return 0;
}

clib_error_t *
usbnet_mbim_open (vlib_main_t *vm, usbnet_dev_t *ud)
{
  clib_error_t *err;
  cdc_mbim_open_done_t resp;
  cdc_mbim_open_msg_t msg = { .hdr = { .MessageType = CDC_MBIM_OPEN_MSG,
				       .MessageLength = sizeof (msg),
				       .TransactionId = ++ud->mbim_trans_id },
			      .MaxControlTransfer = 0x1000 };

  if ((err = usbnet_mbim_send_recv (vm, ud, &msg, sizeof (msg), &resp,
				    sizeof (resp))))
    return err;

  log_debug (ud, "%U status %U", format_cdc_mbim_msg_hdr, &resp,
	     format_cdc_mbim_status, resp.Status);

  if (resp.Status != USBNET_MBIM_STATUS_SUCCESS)
    return clib_error_return (0, "failed, status: %U", format_cdc_mbim_status,
			      resp.Status);

  return 0;
}
clib_error_t *
usbnet_mbim_close (vlib_main_t *vm, usbnet_dev_t *ud)
{
  clib_error_t *err;
  cdc_mbim_close_done_t resp;
  cdc_mbim_close_msg_t msg = { .hdr.MessageType = CDC_MBIM_CLOSE_MSG,
			       .hdr.MessageLength = sizeof (msg),
			       .hdr.TransactionId = ++ud->mbim_trans_id };

  if ((err = usbnet_mbim_send_recv (vm, ud, &msg, sizeof (msg), &resp,
				    sizeof (resp))))
    return err;

  log_debug (ud, "%U status %U", format_cdc_mbim_msg_hdr, &resp,
	     format_cdc_mbim_status, resp.Status);

  if (resp.Status != USBNET_MBIM_STATUS_SUCCESS)
    return clib_error_return (0, "failed, status: %U", format_cdc_mbim_status,
			      resp.Status);

  return 0;
}
