/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Damjan Marion
 */

#include <vnet/vnet.h>
#include <vnet/dev/dev.h>
#include <qat.h>

VLIB_REGISTER_LOG_CLASS (qat_log, static) = {
  .class_name = "qat",
  .subclass_name = "pfvf",
};

#define QAT_PFVF_ACK_TIMEOUT  0.1
#define QAT_PFVF_RESP_TIMEOUT 0.1
#define QAT_PFVF_RETRIES      5
#define QAT_PFVF_POLL_DELAY   10e-6

static u8
qat_pfvf_crc8 (const u8 *buf, u32 len)
{
  u8 crc = 0xff;

  for (u32 i = 0; i < len; i++)
    {
      crc ^= buf[i];
      for (u32 b = 0; b < 8; b++)
	crc = crc & 0x80 ? (crc << 1) ^ QAT_BLKMSG_CRC8_POLY : crc << 1;
    }

  return crc;
}

/* returns 1 and acknowledges the message if the PF sent one */
static int
qat_pfvf_recv (vnet_dev_t *dev, u32 *type, u32 *data)
{
  qat_device_t *qd = vnet_dev_get_data (dev);

  if (qd->gen == QAT_GEN2)
    {
      u32 csr = qat_reg_read (qd->bar2, QAT_GEN2_VF_PFVF);
      qat_gen2_pfvf_msg_t m = { .as_u16 = csr };

      if (m.irq == 0)
	return 0;

      *type = m.type;
      *data = m.data;

      /* the PF leaves the in use pattern on notifications */
      if (qd->pf_version >= QAT_GEN2_PFVF_COMPAT_FAST_ACK && m.type != QAT_PF2VF_MSGTYPE_RESTARTING)
	csr &= ~(QAT_GEN2_PFVF_IN_USE_MASK << QAT_GEN2_PFVF_VF2PF_SHIFT);
      qat_reg_write (qd->bar2, QAT_GEN2_VF_PFVF, csr & ~1);

      /* legacy messages of user space PF drivers */
      return m.origin_system;
    }

  qat_pfvf_msg_t m = { .as_u32 = qat_reg_read (qd->bar2, QAT_GEN4_VF_PF2VM) };

  if (m.irq == 0)
    return 0;

  *type = m.type;
  *data = m.data;
  m.irq = 0;
  qat_reg_write (qd->bar2, QAT_GEN4_VF_PF2VM, m.as_u32);
  return 1;
}

static void
qat_pfvf_ack_pending (vnet_dev_t *dev)
{
  u32 type, data;

  if (qat_pfvf_recv (dev, &type, &data))
    log_debug (dev, "pf2vf %U data 0x%x dropped", format_qat_pf2vf_msgtype, type, data);
}

static vnet_dev_rv_t
qat_pfvf_gen2_send (vlib_main_t *vm, vnet_dev_t *dev, qat_vf2pf_msgtype_t type, u32 data)
{
  qat_device_t *qd = vnet_dev_get_data (dev);
  qat_gen2_pfvf_msg_t m = {
    .origin_system = 1,
    .type = type,
    .data = data,
  };
  u32 int_bit = 1 << QAT_GEN2_PFVF_VF2PF_SHIFT;
  u32 msg = (u32) m.as_u16 << QAT_GEN2_PFVF_VF2PF_SHIFT | QAT_GEN2_PFVF_IN_USE;
  u8 is_notification = type == QAT_VF2PF_MSGTYPE_INIT || type == QAT_VF2PF_MSGTYPE_SHUTDOWN;
  f64 end = vlib_time_now (vm) + QAT_PFVF_ACK_TIMEOUT;
  u32 csr;

  for (u32 retry = 0; retry < QAT_PFVF_RETRIES; retry++)
    {
      /* the PF marks our half in use while it sends */
      while (((csr = qat_reg_read (qd->bar2, QAT_GEN2_VF_PFVF)) >> QAT_GEN2_PFVF_VF2PF_SHIFT &
	      QAT_GEN2_PFVF_IN_USE_MASK) == QAT_GEN2_PFVF_IN_USE)
	{
	  if (vlib_time_now (vm) > end)
	    {
	      log_err (dev, "mailbox busy, %U not sent", format_qat_vf2pf_msgtype, type);
	      return VNET_DEV_ERR_TIMEOUT;
	    }
	  vlib_process_suspend (vm, QAT_PFVF_POLL_DELAY);
	}

      qat_reg_write (qd->bar2, QAT_GEN2_VF_PFVF, msg | int_bit);

      while ((csr = qat_reg_read (qd->bar2, QAT_GEN2_VF_PFVF)) & int_bit)
	{
	  if (vlib_time_now (vm) > end)
	    {
	      log_err (dev, "PF did not acknowledge %U", format_qat_vf2pf_msgtype, type);
	      return VNET_DEV_ERR_TIMEOUT;
	    }
	  vlib_process_suspend (vm, QAT_PFVF_POLL_DELAY);
	}

      /* the PF does not clear the in use pattern of a notification, a different value means
       * that a PF message overwrote it */
      if (is_notification && csr != msg)
	{
	  log_debug (dev, "collision sending %U, retrying", format_qat_vf2pf_msgtype, type);
	  continue;
	}

      if ((csr & QAT_GEN2_PFVF_IN_USE_MASK) == QAT_GEN2_PFVF_IN_USE)
	qat_reg_write (qd->bar2, QAT_GEN2_VF_PFVF, csr & ~QAT_GEN2_PFVF_IN_USE_MASK);
      return VNET_DEV_OK;
    }

  log_err (dev, "%U not delivered", format_qat_vf2pf_msgtype, type);
  return VNET_DEV_ERR_DEVICE_NO_REPLY;
}

static vnet_dev_rv_t
qat_pfvf_send (vlib_main_t *vm, vnet_dev_t *dev, qat_vf2pf_msgtype_t type, u32 data)
{
  qat_device_t *qd = vnet_dev_get_data (dev);
  qat_pfvf_msg_t m = {
    .irq = 1,
    .origin_system = 1,
    .type = type,
    .data = data,
  };
  f64 end = vlib_time_now (vm) + QAT_PFVF_ACK_TIMEOUT;

  if (type != QAT_VF2PF_MSGTYPE_SMALL_BLOCK_REQ)
    log_debug (dev, "vf2pf %U data 0x%x", format_qat_vf2pf_msgtype, type, data);

  if (qd->gen == QAT_GEN2)
    return qat_pfvf_gen2_send (vm, dev, type, data);

  qat_reg_write (qd->bar2, QAT_GEN4_VF_VM2PF, m.as_u32);

  /* the PF acknowledges reception by clearing the interrupt bit */
  while (vlib_time_now (vm) < end)
    {
      m.as_u32 = qat_reg_read (qd->bar2, QAT_GEN4_VF_VM2PF);
      if (m.irq == 0)
	return VNET_DEV_OK;
      vlib_process_suspend (vm, QAT_PFVF_POLL_DELAY);
    }

  log_err (dev, "PF did not acknowledge %U", format_qat_vf2pf_msgtype, type);
  return VNET_DEV_ERR_TIMEOUT;
}

static vnet_dev_rv_t
qat_pfvf_req (vlib_main_t *vm, vnet_dev_t *dev, qat_vf2pf_msgtype_t type, u32 data,
	      qat_pf2vf_msgtype_t resp_type, u32 *resp_data)
{
  vnet_dev_rv_t rv;

  for (u32 retry = 0; retry < QAT_PFVF_RETRIES; retry++)
    {
      f64 end;

      qat_pfvf_ack_pending (dev);

      rv = qat_pfvf_send (vm, dev, type, data);
      if (rv != VNET_DEV_OK)
	return rv;

      end = vlib_time_now (vm) + QAT_PFVF_RESP_TIMEOUT;
      while (vlib_time_now (vm) < end)
	{
	  u32 m_type, m_data;

	  if (qat_pfvf_recv (dev, &m_type, &m_data) == 0)
	    {
	      vlib_process_suspend (vm, QAT_PFVF_POLL_DELAY);
	      continue;
	    }

	  if (m_type != QAT_PF2VF_MSGTYPE_BLKMSG_RESP)
	    log_debug (dev, "pf2vf %U data 0x%x", format_qat_pf2vf_msgtype, m_type, m_data);

	  if (m_type == resp_type)
	    {
	      *resp_data = m_data;
	      return VNET_DEV_OK;
	    }

	  if (m_type == QAT_PF2VF_MSGTYPE_RESTARTING)
	    {
	      log_err (dev, "PF is restarting");
	      return VNET_DEV_ERR_NOT_READY;
	    }

	  if (m_type == QAT_PF2VF_MSGTYPE_FATAL_ERROR)
	    {
	      log_err (dev, "PF reported a fatal error");
	      return VNET_DEV_ERR_NOT_READY;
	    }

	  log_debug (dev, "unexpected pf2vf %U, waiting for %U", format_qat_pf2vf_msgtype, m_type,
		     format_qat_pf2vf_msgtype, resp_type);
	}

      log_debug (dev, "no response to %U, retrying", format_qat_vf2pf_msgtype, type);
    }

  log_err (dev, "no response from PF to %U", format_qat_vf2pf_msgtype, type);
  return VNET_DEV_ERR_DEVICE_NO_REPLY;
}

static vnet_dev_rv_t
qat_pfvf_blkmsg_byte (vlib_main_t *vm, vnet_dev_t *dev, u8 blk_type, u8 byte, u8 is_crc, u8 *val)
{
  qat_vf2pf_small_blkmsg_req_t req = {
    .type = blk_type,
    .byte = byte,
    .is_crc = is_crc,
  };
  qat_pf2vf_blkmsg_resp_t resp;
  vnet_dev_rv_t rv;

  rv = qat_pfvf_req (vm, dev, QAT_VF2PF_MSGTYPE_SMALL_BLOCK_REQ, req.as_u32,
		     QAT_PF2VF_MSGTYPE_BLKMSG_RESP, &resp.as_u32);
  if (rv != VNET_DEV_OK)
    return rv;

  if (resp.type != (is_crc ? QAT_PF2VF_BLKMSG_RESP_TYPE_CRC : QAT_PF2VF_BLKMSG_RESP_TYPE_DATA))
    {
      log_err (dev, "block message %U byte %u failed, response type %u data %u",
	       format_qat_blkmsg_type, blk_type, byte, resp.type, resp.data);
      return VNET_DEV_ERR_INVALID_DATA;
    }

  *val = resp.data;
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qat_pfvf_blkmsg (vlib_main_t *vm, vnet_dev_t *dev, u8 blk_type, u8 *buf, u32 buf_len, u32 *len)
{
  u32 msg_len;
  u8 crc;
  vnet_dev_rv_t rv;

  for (u32 i = 0; i < QAT_BLKMSG_HDR_SIZE; i++)
    if ((rv = qat_pfvf_blkmsg_byte (vm, dev, blk_type, i, 0, buf + i)) != VNET_DEV_OK)
      return rv;

  if (buf[0] == 0 || buf[1] == 0)
    {
      log_err (dev, "block message %U has version %u length %u", format_qat_blkmsg_type, blk_type,
	       buf[0], buf[1]);
      return VNET_DEV_ERR_INVALID_DATA;
    }

  msg_len = clib_min (QAT_BLKMSG_HDR_SIZE + buf[1], buf_len);
  msg_len = clib_min (msg_len, QAT_BLKMSG_SMALL_MAX_BYTE + 1);

  for (u32 i = QAT_BLKMSG_HDR_SIZE; i < msg_len; i++)
    if ((rv = qat_pfvf_blkmsg_byte (vm, dev, blk_type, i, 0, buf + i)) != VNET_DEV_OK)
      return rv;

  /* the CRC request carries the 0 based byte count */
  rv = qat_pfvf_blkmsg_byte (vm, dev, blk_type, msg_len - 1, 1, &crc);
  if (rv != VNET_DEV_OK)
    return rv;

  if (crc != qat_pfvf_crc8 (buf, msg_len))
    {
      log_err (dev, "block message %U CRC mismatch (remote 0x%02x local 0x%02x)",
	       format_qat_blkmsg_type, blk_type, crc, qat_pfvf_crc8 (buf, msg_len));
      return VNET_DEV_ERR_INVALID_DATA;
    }

  log_debug (dev, "block message %U version %u length %u data %U crc 0x%02x",
	     format_qat_blkmsg_type, blk_type, buf[0], buf[1], format_hex_bytes,
	     buf + QAT_BLKMSG_HDR_SIZE, msg_len - QAT_BLKMSG_HDR_SIZE, crc);

  *len = msg_len;
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qat_pfvf_ring_pair_reset (vlib_main_t *vm, vnet_dev_t *dev, u8 bank)
{
  vnet_dev_rv_t rv;
  u32 result;

  rv = qat_pfvf_req (vm, dev, QAT_VF2PF_MSGTYPE_RP_RESET, bank, QAT_PF2VF_MSGTYPE_RP_RESET_RESP,
		     &result);
  if (rv != VNET_DEV_OK)
    return rv;

  if (result != 0)
    {
      log_err (dev, "ring pair %u reset failed (result %u)", bank, result);
      return VNET_DEV_ERR_INTERNAL;
    }

  log_debug (dev, "ring pair %u reset", bank);

  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qat_pfvf_get_version (vlib_main_t *vm, vnet_dev_t *dev, u8 *version)
{
  qat_pf2vf_version_resp_t ver;
  vnet_dev_rv_t rv;

  rv = qat_pfvf_req (vm, dev, QAT_VF2PF_MSGTYPE_COMPAT_VER_REQ, QAT_PFVF_COMPAT_VERSION,
		     QAT_PF2VF_MSGTYPE_VERSION_RESP, &ver.as_u32);
  if (rv != VNET_DEV_OK)
    return rv;

  log_debug (dev, "PF/VF protocol version %u (requested %u), %U", ver.version,
	     QAT_PFVF_COMPAT_VERSION, format_qat_pf2vf_compat, ver.result);

  if (ver.result == QAT_PF2VF_VF_INCOMPATIBLE ||
      (ver.result == QAT_PF2VF_VF_COMPAT_UNKNOWN && ver.version < QAT_PFVF_COMPAT_VERSION))
    {
      log_err (dev, "PF (version %u) is not compatible with this driver", ver.version);
      return VNET_DEV_ERR_UNSUPPORTED_DEVICE_VER;
    }

  *version = ver.version;
  return VNET_DEV_OK;
}

static vnet_dev_rv_t
qat_pfvf_get_ring_to_svc_map (vlib_main_t *vm, vnet_dev_t *dev, qat_ring_to_svc_map_t *map)
{
  u8 buf[QAT_BLKMSG_SMALL_MAX_BYTE + 1];
  vnet_dev_rv_t rv;
  u32 len;

  rv = qat_pfvf_blkmsg (vm, dev, QAT_BLKMSG_REQ_RING_SVC_MAP, buf, sizeof (buf), &len);
  if (rv != VNET_DEV_OK)
    return rv;

  if (len < QAT_BLKMSG_HDR_SIZE + sizeof (u16))
    {
      log_err (dev, "ring to service map message too short (%u bytes)", len);
      return VNET_DEV_ERR_INVALID_DATA;
    }

  map->as_u16 = clib_mem_unaligned (buf + QAT_BLKMSG_HDR_SIZE, u16);
  log_debug (dev, "ring to service map 0x%04x: %U", map->as_u16, format_qat_ring_to_svc_map,
	     map->as_u16);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qat_pfvf_get_caps (vlib_main_t *vm, vnet_dev_t *dev, qat_blkmsg_caps_t *caps)
{
  u8 buf[QAT_BLKMSG_SMALL_MAX_BYTE + 1] = {};
  vnet_dev_rv_t rv;
  u32 len;

  rv = qat_pfvf_blkmsg (vm, dev, QAT_BLKMSG_REQ_CAP_SUMMARY, buf, sizeof (buf), &len);
  if (rv != VNET_DEV_OK)
    return rv;

  /* fields not sent by older PF versions stay zero */
  *caps = (qat_blkmsg_caps_t) {};
  clib_memcpy_fast (caps, buf, clib_min (len, sizeof (*caps)));

  log_debug (dev, "capabilities version %u, ext dc caps 0x%x", caps->version, caps->ext_dc_caps);
  if (caps->len >= QAT_BLKMSG_CAPS_V2_LEN)
    log_debug (dev, "capabilities 0x%08x: %U", caps->capabilities, format_qat_capabilities,
	       caps->capabilities);
  if (caps->len >= QAT_BLKMSG_CAPS_V3_LEN)
    log_debug (dev, "engine clock %u MHz", caps->frequency / 1000000);
  return VNET_DEV_OK;
}

vnet_dev_rv_t
qat_pfvf_init (vlib_main_t *vm, vnet_dev_t *dev)
{
  qat_device_t *qd = vnet_dev_get_data (dev);
  vnet_dev_rv_t rv;
  u8 version;

  if ((rv = qat_pfvf_get_version (vm, dev, &version)) != VNET_DEV_OK)
    return rv;
  qd->pf_version = version;

  /* gen2 ring services are fixed */
  if (qd->gen == QAT_GEN4)
    {
      rv = qat_pfvf_get_ring_to_svc_map (vm, dev, &qd->ring_to_svc_map);
      if (rv != VNET_DEV_OK)
	return rv;
    }

  rv = qat_pfvf_send (vm, dev, QAT_VF2PF_MSGTYPE_INIT, 0);
  if (rv != VNET_DEV_OK)
    return rv;

  qd->pfvf_initialized = 1;
  log_debug (dev, "PF/VF protocol version %u, initialized", version);
  return VNET_DEV_OK;
}

void
qat_pfvf_shutdown (vlib_main_t *vm, vnet_dev_t *dev)
{
  qat_device_t *qd = vnet_dev_get_data (dev);

  if (qd->pfvf_initialized == 0)
    return;

  qat_pfvf_send (vm, dev, QAT_VF2PF_MSGTYPE_SHUTDOWN, 0);
  qd->pfvf_initialized = 0;
}
