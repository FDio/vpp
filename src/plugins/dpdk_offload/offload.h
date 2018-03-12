
typedef struct
{
  uword num_rx_queues;
  clib_bitmap_t *workers;
} dpdk_offload_workers_config_t;

typedef struct
{
  dpdk_offload_workers_config_t conf;
  dpdk_queue_range_t q_range;
  clib_bitmap_t *enabled;	//by sw_if_index
  u32 n_enabled;
  void **flows;
} dpdk_offload_state_t;

typedef struct
{
  dpdk_offload_state_t vxlan_rx;
} dpdk_offload_device_config_t;

typedef struct
{
  dpdk_offload_device_config_t * dev_confs;
  uword * conf_index_by_pci_addr;
  /* conf by device index - resolved during dpdk plugin int */
  uword * conf_index_by_device_index;
  /* hw device the sw_if_index has been offloaded to */
  uword * hw_if_index_by_sw_if_index;
} offload_main_t;

extern offload_main_t offload_main;
extern vlib_node_registration_t dpdk_vxlan_offload_input_node;

dpdk_offload_device_config_t * dpdk_offload_get_device_config (dpdk_device_t * xd);

