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

/*
 *   WARNING!
 *   This driver is not intended for production use and it is unsupported.
 *   It is provided for educational use only.
 *   Please use supported DPDK driver instead.
 */


#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>

#include <mlx5/mlx5.h>

u8 *
format_mlx5_bits (u8 * s, va_list * args)
{
  void *ptr = va_arg (*args, void *);
  u32 offset = va_arg (*args, u32);
  u32 sb = va_arg (*args, u32);
  u32 eb = va_arg (*args, u32);

  if (sb == 63 && eb == 0)
    {
      u64 x = mlx5_get_u64 (ptr, offset);
      return format (s, "0x%lx", x);
    }

  u32 x = mlx5_get_bits (ptr, offset, sb, eb);
  s = format (s, "%d", x);
  if (x > 9)
    s = format (s, " (0x%x)", x);
  return s;
}

u8 *
format_mlx5_field (u8 * s, va_list * args)
{
  void *ptr = va_arg (*args, void *);
  u32 offset = va_arg (*args, u32);
  u32 sb = va_arg (*args, u32);
  u32 eb = va_arg (*args, u32);
  char *name = va_arg (*args, char *);

  u8 *tmp = 0;

  tmp = format (0, "0x%02x %s ", offset, name);
  if (sb == eb)
    tmp = format (tmp, "[%u]", sb);
  else
    tmp = format (tmp, "[%u:%u]", sb, eb);
  s = format (s, "%-45v = %U", tmp, format_mlx5_bits, ptr, offset, sb, eb);
  vec_free (tmp);

  return s;
}

u8 *
format_mlx5_device_name (u8 * s, va_list * args)
{
  u32 i = va_arg (*args, u32);
  vlib_main_t *vm = vlib_get_main ();
  mlx5_main_t *mm = &mlx5_main;
  mlx5_device_t *md = vec_elt_at_index (mm->devices, i);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (vm, md->pci_dev_handle);

  s = format (s, "mlx5-%x/%x/%x/%x",
	      addr->domain, addr->bus, addr->slot, addr->function);
  return s;
}

u8 *
format_mlx5_device_flags (u8 * s, va_list * args)
{
  mlx5_device_t *md = va_arg (*args, mlx5_device_t *);
  u8 *t = 0;

  if (0);
#define _(a, b, c) else if (md->flags & (1 << a)) \
  t = format (t, "%s%s", t ? " ":"", c);
  foreach_mlx5_device_flags
#undef _
    s = format (s, "%v", t);
  vec_free (t);
  return s;
}

u8 *
format_mlx5_ppcnt_counter (u8 * s, va_list * args)
{
  u8 *d = va_arg (*args, u8 *);
  int verbose = va_arg (*args, int);
  uword indent = format_get_indent (s);
  u8 grp = mlx5_get_bits (d, 0x00, 5, 0);

#define _(a, b) { u64 r = mlx5_get_u64 (d, 0x08 + a); if (r || verbose > 1) \
  s = format (s, "\n%U%-35U%lu", format_white_space, indent + 2, format_c_identifier, #b, r); }

  if (grp == 0x00)
    {
      s = format (s, "Ethernet 802.3 Counters:");
    foreach_reg_ppcmt_802_3_counter}
  else if (grp == 0x06)
    {
      s = format (s, "Ethernet Discard Counters:");
    foreach_reg_ppcmt_discard_counter}
  else if (grp == 0x16)
    {
      s = format (s, "Ethernet Physical Layer Counters:");
    foreach_reg_ppcmt_phy_layer_counter}
#undef _

  return s;
}

u8 *
format_mlx5_device (u8 * s, va_list * args)
{
  u32 dev_instance = va_arg (*args, u32);
  int verbose = va_arg (*args, int);
  uword indent = format_get_indent (s);
  clib_error_t *error;
  vlib_main_t *vm = vlib_get_main ();
  mlx5_main_t *mm = &mlx5_main;
  mlx5_device_t *md = vec_elt_at_index (mm->devices, dev_instance);
  vlib_pci_addr_t *addr = vlib_pci_get_addr (vm, md->pci_dev_handle);
  mlx5_nic_vport_state_t state;
  vlib_pci_device_info_t *di;
  u8 ctx[MLX5_NIC_VPORT_CTX_SZ];
  u8 ppcnt[mlx5_sizeof_reg (MLX5_REG_PPCNT)];
  u8 pddr[mlx5_sizeof_reg (MLX5_REG_PDDR)];
  u8 *t = 0;

  di = vlib_pci_get_device_info (vm, addr, 0);

  mlx5_cmdq_t *cmdq = mlx5_get_cmdq (md);
  if ((error = mlx5_cmd_query_nic_vport_state (md, cmdq, &state)))
    goto error;
  if ((error = mlx5_cmd_query_nic_vport_context (md, cmdq, ctx)))
    goto error;

  memset (ppcnt, 0, mlx5_sizeof_reg (MLX5_REG_PPCNT));
  mlx5_set_bits (ppcnt, 0, 23, 16, 1);	/* port 1 */
  if ((error = mlx5_cmd_access_register (md, cmdq, MLX5_REG_RW_READ,
					 MLX5_REG_PPCNT, 0, ppcnt)))
    goto error;

  memset (pddr, 0, sizeof (pddr));
  mlx5_set_bits (pddr, 0, 23, 16, 1);
  mlx5_set_bits (pddr, 4, 7, 0, 3);
  error = mlx5_cmd_access_register (md, cmdq, MLX5_REG_RW_READ, MLX5_REG_PDDR,
				    0, pddr);


  s = format (s, "Mellanox %s", di->product_name);
  s = format (s, "\n%Umtu %u link %s admin %s",
	      format_white_space, indent + 2,
	      mlx5_get_nic_vport_ctx_field (ctx, mtu),
	      state.state ? "up" : "down", state.admin_state ? "up" : "down");
  s = format (s, "\n%Uflags %U",
	      format_white_space, indent + 2, format_mlx5_device_flags, md);
  if (state.state)
    {
      if (state.max_tx_speed < 10)
	s = format (s, "\n%Uspeed %umbps", format_white_space, indent + 2,
		    state.max_tx_speed * 100);
      else
	s = format (s, "\n%Uspeed %ugbps", format_white_space, indent + 2,
		    state.max_tx_speed / 10);
    }

  /* Ethernet 802.3 Counters */
  memset (ppcnt, 0, mlx5_sizeof_reg (MLX5_REG_PPCNT));
  mlx5_set_bits (ppcnt, 0, 23, 16, 1);	/* port 1 */
  mlx5_set_bits (ppcnt, 0, 5, 0, 0);	/* Ethernet  802.3 Counters */
  if ((error = mlx5_cmd_access_register (md, cmdq, MLX5_REG_RW_READ,
					 MLX5_REG_PPCNT, 0, ppcnt)))
    goto error;
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_mlx5_ppcnt_counter, ppcnt, verbose);
  vec_reset_length (t);

  /* Ethernet Discard Counters */
  memset (ppcnt, 0, mlx5_sizeof_reg (MLX5_REG_PPCNT));
  mlx5_set_bits (ppcnt, 0, 23, 16, 1);	/* port 1 */
  mlx5_set_bits (ppcnt, 0, 5, 0, 6);	/* Ethernet Discard Counters */
  if ((error = mlx5_cmd_access_register (md, cmdq, MLX5_REG_RW_READ,
					 MLX5_REG_PPCNT, 0, ppcnt)))
    goto error;
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_mlx5_ppcnt_counter, ppcnt, verbose);
  vec_reset_length (t);

  /* Ethernet Physical Layer Counters */
  memset (ppcnt, 0, mlx5_sizeof_reg (MLX5_REG_PPCNT));
  mlx5_set_bits (ppcnt, 0, 23, 16, 1);	/* port 1 */
  mlx5_set_bits (ppcnt, 0, 5, 0, 0x16);	/* Ethernet Phy Layer Counters */
  if ((error = mlx5_cmd_access_register (md, cmdq, MLX5_REG_RW_READ,
					 MLX5_REG_PPCNT, 0, ppcnt)))
    goto error;
  s = format (s, "\n%U%U",
	      format_white_space, indent,
	      format_mlx5_ppcnt_counter, ppcnt, verbose);
  vec_reset_length (t);

  s = format (s, "\n%Udevice info:", format_white_space, indent);
  s = format (s, "\n%U%-35s%u.%u.%u", format_white_space, indent + 2,
	      "firmware version", md->fw_rev_major, md->fw_rev_minor,
	      md->fw_rev_subminor);
  s = format (s, "\n%U%-35s%U", format_white_space, indent + 2,
	      "pci address", format_vlib_pci_addr, addr);
  s = format (s, "\n%U%-35s%U", format_white_space, indent + 2,
	      "pci speed", format_vlib_pci_link_speed, di);
  s = format (s, "\n%U%-35s%U", format_white_space, indent + 2,
	      "part number", format_vlib_pci_vpd, di->vpd_r, "PN");
  s = format (s, "\n%U%-35s%U", format_white_space, indent + 2,
	      "serial number", format_vlib_pci_vpd, di->vpd_r, "SN");
  s = format (s, "\n%Umodule info:\n%U%U",
	      format_white_space, indent,
	      format_white_space, indent + 2,
	      format_mlx5_pddr_module_info, pddr);
  vlib_pci_free_device_info (di);
  mlx5_put_cmdq (cmdq);
  vec_free (t);
  return s;
error:
  mlx5_put_cmdq (cmdq);
  s = format (s, "  Error: %U", format_clib_error, error);
  clib_error_free (error);
  return s;
}

u8 *
format_mlx5_counters (u8 * s, va_list * args)
{
  mlx5_device_t *md = va_arg (*args, mlx5_device_t *);
  clib_error_t *error;
  mlx5_cmdq_t *cmdq;
  u8 buff[256] = { 0 };

  cmdq = mlx5_get_cmdq (md);
  mlx5_set_bits (buff, 0, 23, 16, 1);	/* port 1 */

  if ((error =
       mlx5_cmd_access_register (md, cmdq, MLX5_REG_RW_READ, MLX5_REG_PPCNT,
				 0, buff)))
    goto error;

  mlx5_put_cmdq (cmdq);

#define _(a, b) { u64 r = mlx5_get_u64 (buff, 0x08 + a); if (r) \
  s = format (s, "%-32s%d\n", #b, r); }
  foreach_reg_ppcmt_802_3_counter
#undef _
    return s;

error:
  mlx5_put_cmdq (cmdq);
  clib_error_report (error);
  return format (s, "error");
}


u8 *
format_mlx5_hca_cap_cur_max (u8 * s, va_list * args)
{
  mlx5_device_t *md = va_arg (*args, mlx5_device_t *);
  mlx5_cmdq_t *cmdq = va_arg (*args, mlx5_cmdq_t *);
  int type = va_arg (*args, int);
  clib_error_t *error;
  u8 cur_hca_cap[MLX5_HCA_CAP_SZ];
  u8 max_hca_cap[MLX5_HCA_CAP_SZ];
  u8 *hdr = 0;

  if ((error = mlx5_cmd_query_hca_cap (md, cmdq, 0, type, max_hca_cap)))
    goto error;

  if ((error = mlx5_cmd_query_hca_cap (md, cmdq, 1, type, cur_hca_cap)))
    goto error;

  hdr = format (hdr, "             %-32s%-20s%s\n",
		"Field", "Current", "Max");

#define _(a, b, c, d) { \
    u32 cur = mlx5_get_bits (cur_hca_cap, a, b, c);			\
    u32 max = mlx5_get_bits (max_hca_cap, a, b, c);			\
    s = format (s, "0x%02x [%2d:%2d] %-32s%-20U", a, b, c, #d,		\
		format_mlx5_bits, cur_hca_cap, a, b, c);		\
    if (cur != max)							\
      s = format (s, "%U", format_mlx5_bits, max_hca_cap, a, b, c);	\
    s = format (s, "\n");						\
} while (0);

  if (type == MLX5_HCA_CAP_TYPE_DEVICE)
    {
      s = format (s, "General Device Capabilities:\n%v", hdr);
    foreach_hca_general_dev_cap}
  else if (type == MLX5_HCA_CAP_TYPE_NET_OFFLOAD)
    {
      s = format (s, "Per-protocol Network Offload Capabilities:\n%v", hdr);
    foreach_hca_net_offload_cap}
  else if (type == MLX5_HCA_CAP_TYPE_QOS)
    {
      s = format (s, "Quality of Service Capabilities:\n%v", hdr);
    foreach_hca_qos_cap}
#undef _
  vec_free (hdr);
  return s;
error:
  return format (s, "error");
}

u8 *
format_mlx5_nic_vport_ctx (u8 * s, va_list * args)
{
  void *ctx = va_arg (*args, void *);
  uword indent = format_get_indent (s);
#define _(a, b, c, d) s = format (s, "%U%U\n",				\
				    format_white_space, indent + 2,	\
				    format_mlx5_field, ctx, a, b, c, #d);
  foreach_nic_vport_ctx_field
#undef _
    return s;
}


u8 *
format_mlx5_eq_ctx (u8 * s, va_list * args)
{
  void *ctx = va_arg (*args, void *);
  uword indent = format_get_indent (s);
#define _(a, b, c, d) s = format (s, "%U%U\n",				\
				    format_white_space, indent + 2,	\
				    format_mlx5_field, ctx, a, b, c, #d);
  foreach_eq_ctx_field
#undef _
    return s;
}

u8 *
format_mlx5_cq_ctx (u8 * s, va_list * args)
{
  void *ctx = va_arg (*args, void *);
  uword indent = format_get_indent (s);

#define _(a, b, c, d) s = format (s, "%U%U\n",				\
				    format_white_space, indent + 2,	\
				    format_mlx5_field, ctx, a, b, c, #d);
  foreach_cq_ctx_field
#undef _
    return s;
}

u8 *
format_mlx5_sq_ctx (u8 * s, va_list * args)
{
  void *ctx = va_arg (*args, void *);
  uword indent = format_get_indent (s);

#define _(a, b, c, d) s = format (s, "%U%U\n",				\
				    format_white_space, indent + 2,	\
				    format_mlx5_field, ctx, a, b, c, #d);
  foreach_sq_ctx_field
#undef _
    return s;
}

u8 *
format_mlx5_wq_ctx (u8 * s, va_list * args)
{
  void *ctx = va_arg (*args, void *);
  uword indent = format_get_indent (s);

#define _(a, b, c, d) s = format (s, "%U%U\n",				\
				    format_white_space, indent + 2,	\
				    format_mlx5_field, ctx, a, b, c, #d);
  foreach_wq_ctx_field
#undef _
    return s;
}

u8 *
format_mlx5_rq_ctx (u8 * s, va_list * args)
{
  void *ctx = va_arg (*args, void *);
  uword indent = format_get_indent (s);
#define _(a, b, c, d) s = format (s, "%U%U\n",				\
				    format_white_space, indent + 2,	\
				    format_mlx5_field, ctx, a, b, c, #d);
  foreach_rq_ctx_field
#undef _
    return s;
}

u8 *
format_mlx5_pddr_module_info (u8 * s, va_list * args)
{
  u8 *d = va_arg (*args, void *);
  uword indent = format_get_indent (s);
  u32 r;
  int i;
  u8 *t = 0;
  int is_qsfp = 0;
  int line = 0;

  /* data starts at offset 0x08 */
  d += 0x08;

#define _(a,b,c)  s = format (s, "%U%-35s" a "\n", format_white_space, line++ ? indent : 0, c, b);
  /* cable identifier */
  char *cable_identifier[] =
    { "QSFP28", "QSFP+", "SFP28/SFP+", "QSA (QSFP->SFP)",
    "backplane"
  };
  r = mlx5_get_bits (d, 0x04, 15, 8);
  if (r < sizeof (cable_identifier) / sizeof (char *))
    _("%s", cable_identifier[r], "cable identifier");

  if (r < 2)
    is_qsfp = 1;

  /* cable technology */
  char *transmitter_tech[] =
    { "850 nm VCSEL", "1310 nm VCSEL", "1550 nm VCSEL",
    "1310 nm FP", "1310 nm DFB", "1550 nm DFB", "1310 nm EML", "1550 nm EML",
    "other / undefined", "1490 nm DFB", "copper cable unequalized",
    "copper cable passive equalized",
    "copper cable, near and far end limiting active equalizers",
    "copper cable, far end limiting active equalizers",
    "copper cable, near end limiting active equalizers",
    "copper cable, linear active equalizers"
  };

  if (is_qsfp)
    {
      r = mlx5_get_bits (d, 0x00, 31, 28);
      _("%s", transmitter_tech[r], "transmitter technology");

      r = mlx5_get_bits (d, 0x00, 27, 24);
      t = format (t, "%s %s %s %s",
		  r & (1 << 0) ? "active-wavelength" : "no-wavelength",
		  r & (1 << 1) ? "cooled-transmitter" :
		  "uncooled-transmitter",
		  r & (1 << 2) ? "pin-detector" : "apd-detector",
		  r & (1 << 3) ? "tunable" : "non-tunable");
      _("%v", t, "device technology");
      vec_reset_length (t);

      /* eth compliance */
      r = mlx5_get_bits (d, 0x00, 7, 0);
      if (r & (1 << 0))
	t = format (t, "40G Active Cable (XLPPI) ");
      if (r & (1 << 1))
	t = format (t, "40GBASE-LR4 ");
      if (r & (1 << 2))
	t = format (t, "40GBASE-SR4 ");
      if (r & (1 << 3))
	t = format (t, "40GBASE-CR4 ");
      if (r & (1 << 4))
	t = format (t, "10GBASE-SR ");
      if (r & (1 << 5))
	t = format (t, "10GBASE-LR ");
      if (r & (1 << 6))
	t = format (t, "10GBASE-LRM ");
      if (r & (1 << 7))
	{
	  r = mlx5_get_bits (d, 0x00, 15, 8);
	  switch (r)
	    {
	    case 0x00:
	      t = format (t, "unspecified");
	      break;
	    case 0x01:
	      t = format (t, "100G AOC");
	      break;
	    case 0x02:
	      t = format (t, "100GBASE-SR4 or 25GBASE-SR");
	      break;
	    case 0x03:
	      t = format (t, "100GBASE-LR4 or 25GBASE-LR");
	      break;
	    case 0x04:
	      t = format (t, "100GBASE-ER4 or 25GBASE-ER");
	      break;
	    case 0x05:
	      t = format (t, "100GBASE-SR10");
	      break;
	    case 0x06:
	      t = format (t, "100G CWDM4");
	      break;
	    case 0x07:
	      t = format (t, "100G PSM4");
	      break;
	    case 0x08:
	      t = format (t, "100G ACC");
	      break;
	    case 0x0b:
	      t = format (t, "100GBASE-CR4/25GBASE-CR CA-L");
	      break;
	    case 0x0c:
	      t = format (t, "25GBASE-CR CA-S");
	      break;
	    case 0x0d:
	      t = format (t, "25GBASE-CR CA-N");
	      break;
	    case 0x10:
	      t = format (t, "40GBASE-ER4");
	      break;
	    case 0x11:
	      t = format (t, "4x10GBASE-SR");
	      break;
	    case 0x17:
	      t = format (t, "100G CLR4");
	      break;
	    default:
	      t = format (t, "unknown (0x%02x)", r);
	    };
	}
      _("%v", t, "ethernet compliance");
      vec_reset_length (t);

    }
  /* cable type */
  char *cable_type[] =
    { "unidentified", "active cable (active copper / optics)",
    "optical module (separated)", "passive copper cable", "cable unplugged"
  };
  r = mlx5_get_bits (d, 0x04, 31, 28);
  if (r < sizeof (cable_type) / sizeof (char *))
    _("%s", cable_type[r], "cable type");

  /*cable length */
  _("%d m", mlx5_get_bits (d, 0x04, 23, 16), "cable length");

  /* cable power class */
  r = mlx5_get_bits (d, 0x04, 7, 0);
  t = format (t, "Power Class %d (%0.1f W max)", r, 1.0 + r * 0.5);
  _("%v", t, "cable power class");
  vec_reset_length (t);

  /* vendor name */
  i = 0x14;
  while (i < 0x24 && d[i] != 0)
    vec_add1 (t, d[i++]);
  _("%v", t, "vendor name");
  vec_reset_length (t);

  /* vendor pn */
  i = 0x24;
  while (i < 0x34 && d[i] != 0)
    vec_add1 (t, d[i++]);
  _("%v", t, "vendor pn");
  vec_reset_length (t);

  /* vendor rev */
  _("%d", mlx5_get_u32 (d, 0x34), "vendor rev");

  /* vendor sn */
  i = 0x3c;
  while (i < 0x4c && d[i] != 0)
    vec_add1 (t, d[i++]);
  _("%v", t, "vendor sn");
  vec_reset_length (t);

  /* temperature */
  if ((r = mlx5_get_bits (d, 0x4c, 31, 16)))
    _("%0.1f degC", 1.0 / 256 * r, "temperature");

  /* voltage */
  if ((r = mlx5_get_bits (d, 0x4c, 15, 0)))
    _("%0.1f V", 1e-5 * r, "voltage");


#undef _

  vec_free (t);
  return s;
}

u8 *
format_mlx5_eqe (u8 * s, va_list * args)
{
  void *eqe = va_arg (*args, void *);
  u8 type = mlx5_get_bits (eqe, 0x00, 23, 16);
  u8 sub_type = mlx5_get_bits (eqe, 0x00, 7, 0);
  void *data = eqe + 0x20;

  if (type == 0x09)
    {
      s = format (s, "Port State Change port=%d sub_type=0x%x",
		  mlx5_get_bits (data, 0x08, 31, 28), sub_type);
    }
  else if (type == 0x16)
    {
      s = format (s, "Port Module module=%d module_status=0x%x "
		  "error_type=0x%x",
		  mlx5_get_bits (data, 0x00, 23, 16),
		  mlx5_get_bits (data, 0x00, 3, 0),
		  mlx5_get_bits (data, 0x04, 11, 8));
    }
  else
    s = format (s, "unknown event (type=0x%02x sub_type=0x%02x data=%U)\n",
		type, sub_type, format_hex_bytes, data, 28);

  return s;
}


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
