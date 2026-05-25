# Set Interface Speed via VPP API

## 1. Why This Is Needed

SONiC expects the SAI implementation to support `SAI_PORT_ATTR_SPEED` as a read-write attribute:

- **Read path**: When SONiC queries `SAI_PORT_ATTR_SPEED`, the SAI layer returns the operational link speed from STATE_DB (in Mbps). The VPP SAI backend reads this from the `link_speed` field on `vnet_hw_interface_t` (stored in Kbps).

- **Write path**: When an operator configures port speed (e.g., `config interface speed Ethernet0 10000`), SONiC calls `sai_port_api->set_port_attribute()` with `SAI_PORT_ATTR_SPEED`. The SAI layer must propagate this to the underlying dataplane so the NIC driver can reconfigure the PHY/link accordingly.

Without a VPP API for setting speed, `SAI_PORT_ATTR_SPEED` set operations silently fail, and the port remains at whatever speed was auto-negotiated by the driver.

## 2. VPP API Added

Defined in `src/vnet/interface.api`:

```c
/** \brief Set interface link speed (override)
    @param client_index - opaque cookie to identify the sender
    @param context - sender context, to match reply w/ request
    @param sw_if_index - index of the interface
    @param link_speed - link speed in Kbps (0 means unknown / auto)
*/
autoreply define sw_interface_set_link_speed
{
  u32 client_index;
  u32 context;
  vl_api_interface_index_t sw_if_index;
  u32 link_speed;
};
```

The handler in `interface_api.c`:

```c
static void
vl_api_sw_interface_set_link_speed_t_handler (
  vl_api_sw_interface_set_link_speed_t *mp)
{
  vl_api_sw_interface_set_link_speed_reply_t *rmp;
  vnet_main_t *vnm = vnet_get_main ();
  int rv = 0;
  u32 sw_if_index, link_speed;

  VALIDATE_SW_IF_INDEX (mp);

  sw_if_index = ntohl (mp->sw_if_index);
  link_speed = ntohl (mp->link_speed);

  vnet_sw_interface_t *swif = vnet_get_sw_interface (vnm, sw_if_index);
  rv = vnet_hw_interface_change_link_speed (vnm, swif->hw_if_index, link_speed);

  BAD_SW_IF_INDEX_LABEL;
  REPLY_MACRO (VL_API_SW_INTERFACE_SET_LINK_SPEED_REPLY);
}
```

Units: **Kbps** (consistent with `vnet_hw_interface_t.link_speed` and how DPDK reports it).

**Note:** All VPP binary APIs have corresponding CLI commands registered via `VLIB_CLI_COMMAND`. For example:

```
vppctl set interface link-speed <interface> <speed-kbps>
vppctl show interface link-speed-capa <interface>
```

## 3. Speed Bitmap Enum

Speeds are represented internally as a bitmapped enum for efficient storage, validation, and auto-generated format/unformat functions:

```c
#define foreach_vnet_hw_if_speed \
  _ (UNKNOWN, 0x0000, 0)         \
  _ (1G,      0x0001, 1000)      \
  _ (2_5G,    0x0002, 2500)      \
  _ (5G,      0x0004, 5000)      \
  _ (10G,     0x0008, 10000)     \
  _ (20G,     0x0010, 20000)     \
  _ (25G,     0x0020, 25000)     \
  _ (40G,     0x0040, 40000)     \
  _ (50G,     0x0080, 50000)     \
  _ (56G,     0x0100, 56000)     \
  _ (100G,    0x0200, 100000)    \
  _ (200G,    0x0400, 200000)    \
  _ (400G,    0x0800, 400000)    \
  _ (800G,    0x1000, 800000)

typedef enum
{
#define _(name, bit, mbps) VNET_HW_IF_SPEED_##name = bit,
  foreach_vnet_hw_if_speed
#undef _
} vnet_hw_if_speed_t;
```

### 3.1 Conversion Helpers

```c
/* Kbps → single speed enum bit (returns UNKNOWN if no match) */
always_inline vnet_hw_if_speed_t
vnet_hw_if_speed_from_kbps (u32 speed_kbps)
{
  u32 speed_mbps = speed_kbps / 1000;
#define _(name, bit, mbps) if (speed_mbps == mbps) return bit;
  foreach_vnet_hw_if_speed
#undef _
  return VNET_HW_IF_SPEED_UNKNOWN;
}

/* Single speed enum bit → Kbps */
always_inline u32
vnet_hw_if_speed_to_kbps (vnet_hw_if_speed_t speed)
{
#define _(name, bit, mbps) if (speed == bit) return mbps * 1000;
  foreach_vnet_hw_if_speed
#undef _
  return 0;
}
```

`VNET_HW_IF_SPEED_UNKNOWN` (value 0) serves as a sentinel: it indicates the requested speed doesn't map to any known enum value, and is used by `vnet_hw_interface_change_link_speed()` to reject invalid requests.

### 3.2 Hardware Interface Fields

```c
typedef struct vnet_hw_interface_t {
  ...
  u32 link_speed;                   /* actual operational speed in Kbps (unchanged) */
  u32 supported_link_speeds;        /* bitmask of vnet_hw_if_speed_t (new) */
  ...
};
```

- `link_speed` — unchanged; drivers report actual PHY speed here in Kbps
- `supported_link_speeds` — new; populated by driver at init time (e.g., DPDK maps from `rte_eth_dev_info.speed_capa`)

## 4. Driver Callback for Setting Interface Speed

A `vnet_hw_interface_change_link_speed()` function routes the speed-change request through the device driver. The existing `vnet_hw_interface_set_link_speed()` remains unchanged — drivers use it to **report** the actual PHY speed after negotiation.

A **device class callback** is added to `vnet_device_class_t`:

```c
/* Function to set link speed on the physical device.
 * Receives the speed as a bitmap enum value.
 * The driver is responsible for calling vnet_hw_interface_set_link_speed()
 * when the PHY settles at the new speed. */
clib_error_t *(*set_link_speed_function) (struct vnet_main_t *vnm,
                                          u32 hw_if_index,
                                          vnet_hw_if_speed_t speed);
```

The function used by the API handler performs Kbps→enum conversion and validates against capabilities before calling the driver:

```c
always_inline int
vnet_hw_interface_change_link_speed (vnet_main_t *vnm, u32 hw_if_index,
                                     u32 link_speed_kbps)
{
  vnet_hw_interface_t *hw = vnet_get_hw_interface (vnm, hw_if_index);
  vnet_device_class_t *dc = vnet_get_device_class (vnm, hw->dev_class_index);

  if (!dc->set_link_speed_function)
    return VNET_API_ERROR_UNIMPLEMENTED;

  vnet_hw_if_speed_t speed = vnet_hw_if_speed_from_kbps (link_speed_kbps);
  if (speed == VNET_HW_IF_SPEED_UNKNOWN)
    return VNET_API_ERROR_INVALID_VALUE;

  if (hw->supported_link_speeds && !(hw->supported_link_speeds & speed))
    return VNET_API_ERROR_INVALID_VALUE;

  clib_error_t *err = dc->set_link_speed_function (vnm, hw_if_index, speed);
  if (err)
    {
      clib_error_free (err);
      return VNET_API_ERROR_SYSCALL_ERROR_1;
    }

  return 0;
}
```

Note: `hw->link_speed` is **not** written here. Only the driver updates it (via `vnet_hw_interface_set_link_speed()`) after the PHY completes negotiation and the actual speed is known.

## 5. Get Speed Capabilities API

```c
define sw_interface_get_speed_capa
{
  u32 client_index;
  u32 context;
  vl_api_interface_index_t sw_if_index;
};

define sw_interface_get_speed_capa_reply
{
  u32 context;
  i32 retval;
  u32 count;
  u32 speeds[count];    /* supported speeds in Kbps */
};
```

The handler iterates bits in `hw->supported_link_speeds` and converts each to Kbps for the reply. This maps to SAI's `SAI_PORT_ATTR_SUPPORTED_SPEED` attribute.

## 6. Backward Compatibility

If a driver does **not** implement `set_link_speed_function` (i.e., the callback is `NULL`):

- The API returns `VNET_API_ERROR_UNIMPLEMENTED` to the caller.
- `hw->link_speed` is **not** modified — only the driver (as the authority on actual PHY state) should update it.
- The SAI layer treats the error as "speed setting not supported" and lets SONiC fall back to the configured speed in CONFIG_DB.

If `hw->supported_link_speeds` is 0 (driver did not populate capabilities):

- Validation is skipped — the request is passed directly to the driver callback.
- This allows drivers that support set-speed but haven't yet populated capabilities to still function.

For the current SONiC-VPP deployment (DPDK + vhost-user + tap interfaces):

| Interface Type | Callback | Behavior |
|---|---|---|
| DPDK physical port | Implemented | Validates against capabilities; reconfigures PHY |
| tap/vhost-user | NULL | Returns UNIMPLEMENTED; speed stays at driver-reported value |
| host-interface | NULL | Returns UNIMPLEMENTED; speed stays at driver-reported value |

## 7. Future: Lane/Breakout Support

Higher-speed ports (100G, 400G, 800G) use multiple SerDes lanes. A physical port's lane count determines the per-lane signaling rate:

| Aggregate Speed | Lanes | Per-Lane Rate |
|---|---|---|
| 100G | 4 | 25G NRZ |
| 100G | 2 | 50G PAM4 |
| 400G | 8 | 50G PAM4 |
| 400G | 4 | 100G PAM4 |
| 800G | 8 | 100G PAM4 |

**No impact to the set-speed API.** Lane configuration is orthogonal to speed setting:

- **Breakout** (lane assignment) is handled by SAI via `SAI_PORT_ATTR_HW_LANE_LIST`. In SONiC, `config interface breakout` deletes the original port object and creates new port objects with the desired lane mapping. This happens *before* speed is set.

- **Speed setting** operates on an already-created port with a fixed lane count. The driver internally derives the per-lane rate as `aggregate_speed / num_lanes` and configures the SerDes accordingly.

- **The API only carries aggregate speed** (in Kbps). The driver knows the port's lane count from hardware/configuration and selects the appropriate SerDes encoding (NRZ vs PAM4) and per-lane rate.

Example flow for a 400G→4×100G breakout followed by speed set:

```
1. config interface breakout Ethernet0 4x100G
   → SAI deletes port(lanes=0,1,2,3,4,5,6,7)
   → SAI creates port0(lanes=0,1), port1(lanes=2,3),
                  port2(lanes=4,5), port3(lanes=6,7)

2. config interface speed Ethernet0 100000
   → SAI set_port_attribute(port0, SPEED=100000)
   → sw_interface_set_link_speed(sw_if_index, 100000000 Kbps)
   → Driver: 100G on 2 lanes → 50G PAM4 per lane
```

This separation means the set-speed API remains simple (single `u32 link_speed` field) regardless of lane topology.

## 8. Summary of Boundaries

```
External API (Kbps)          Internal (bitmap enum)        Driver/PHY
─────────────────────────    ─────────────────────────     ──────────────────────
set_link_speed(10000000)  →  kbps_to_enum(SPEED_10G)   →  dc->set_link_speed(SPEED_10G)
                             validate vs supported_*          │
                                                              v
                                                          PHY negotiates
                                                              │
get_speed_capa()          ←  iterate hw->supported_*    ←  Driver populates at init
  → [10G, 25G, 100G]          (0x0020|0x0080|0x0800)

hw->link_speed (Kbps)     ←  Driver calls                ←  rte_eth_link_get()
  (10000000)                  vnet_hw_interface_set_link_speed()
```

- External APIs speak **Kbps** — no change for SAI, SaiVppXlate, or SONiC
- Internal driver interface uses **bitmap enum** — compact, validateable, format/unformat-friendly
- `hw->link_speed` remains `u32` Kbps — zero impact to existing code
