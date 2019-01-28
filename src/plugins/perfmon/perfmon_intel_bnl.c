
#include <perfmon/perfmon_intel.h>

static perfmon_intel_pmc_cpu_model_t cpu_model_table[] = {
  {0x1C, 0x00, 0},
  {0x26, 0x00, 0},
  {0x27, 0x00, 0},
  {0x36, 0x00, 0},
  {0x35, 0x00, 0},

};

static perfmon_intel_pmc_event_t event_table[] = {
  {
   .event_code = {0x2},
   .umask = 0x83,
   .event_name = "store_forwards.any",
   },
  {
   .event_code = {0x2},
   .umask = 0x81,
   .event_name = "store_forwards.good",
   },
  {
   .event_code = {0x3},
   .umask = 0x7F,
   .event_name = "reissue.any",
   },
  {
   .event_code = {0x3},
   .umask = 0xFF,
   .event_name = "reissue.any.ar",
   },
  {
   .event_code = {0x5},
   .umask = 0xF,
   .event_name = "misalign_mem_ref.split",
   },
  {
   .event_code = {0x5},
   .umask = 0x9,
   .event_name = "misalign_mem_ref.ld_split",
   },
  {
   .event_code = {0x5},
   .umask = 0xA,
   .event_name = "misalign_mem_ref.st_split",
   },
  {
   .event_code = {0x5},
   .umask = 0x8F,
   .event_name = "misalign_mem_ref.split.ar",
   },
  {
   .event_code = {0x5},
   .umask = 0x89,
   .event_name = "misalign_mem_ref.ld_split.ar",
   },
  {
   .event_code = {0x5},
   .umask = 0x8A,
   .event_name = "misalign_mem_ref.st_split.ar",
   },
  {
   .event_code = {0x5},
   .umask = 0x8C,
   .event_name = "misalign_mem_ref.rmw_split",
   },
  {
   .event_code = {0x5},
   .umask = 0x97,
   .event_name = "misalign_mem_ref.bubble",
   },
  {
   .event_code = {0x5},
   .umask = 0x91,
   .event_name = "misalign_mem_ref.ld_bubble",
   },
  {
   .event_code = {0x5},
   .umask = 0x92,
   .event_name = "misalign_mem_ref.st_bubble",
   },
  {
   .event_code = {0x5},
   .umask = 0x94,
   .event_name = "misalign_mem_ref.rmw_bubble",
   },
  {
   .event_code = {0x6},
   .umask = 0x80,
   .event_name = "segment_reg_loads.any",
   },
  {
   .event_code = {0x7},
   .umask = 0x81,
   .event_name = "prefetch.prefetcht0",
   },
  {
   .event_code = {0x7},
   .umask = 0x82,
   .event_name = "prefetch.prefetcht1",
   },
  {
   .event_code = {0x7},
   .umask = 0x84,
   .event_name = "prefetch.prefetcht2",
   },
  {
   .event_code = {0x7},
   .umask = 0x86,
   .event_name = "prefetch.sw_l2",
   },
  {
   .event_code = {0x7},
   .umask = 0x88,
   .event_name = "prefetch.prefetchnta",
   },
  {
   .event_code = {0x7},
   .umask = 0x10,
   .event_name = "prefetch.hw_prefetch",
   },
  {
   .event_code = {0x7},
   .umask = 0xF,
   .event_name = "prefetch.software_prefetch",
   },
  {
   .event_code = {0x7},
   .umask = 0x8F,
   .event_name = "prefetch.software_prefetch.ar",
   },
  {
   .event_code = {0x8},
   .umask = 0x7,
   .event_name = "data_tlb_misses.dtlb_miss",
   },
  {
   .event_code = {0x8},
   .umask = 0x5,
   .event_name = "data_tlb_misses.dtlb_miss_ld",
   },
  {
   .event_code = {0x8},
   .umask = 0x9,
   .event_name = "data_tlb_misses.l0_dtlb_miss_ld",
   },
  {
   .event_code = {0x8},
   .umask = 0x6,
   .event_name = "data_tlb_misses.dtlb_miss_st",
   },
  {
   .event_code = {0x8},
   .umask = 0xA,
   .event_name = "data_tlb_misses.l0_dtlb_miss_st",
   },
  {
   .event_code = {0x9},
   .umask = 0x20,
   .event_name = "dispatch_blocked.any",
   },
  {
   .event_code = {0xC},
   .umask = 0x3,
   .event_name = "page_walks.walks",
   },
  {
   .event_code = {0xC},
   .umask = 0x3,
   .event_name = "page_walks.cycles",
   },
  {
   .event_code = {0xC},
   .umask = 0x1,
   .event_name = "page_walks.d_side_walks",
   },
  {
   .event_code = {0xC},
   .umask = 0x1,
   .event_name = "page_walks.d_side_cycles",
   },
  {
   .event_code = {0xC},
   .umask = 0x2,
   .event_name = "page_walks.i_side_walks",
   },
  {
   .event_code = {0xC},
   .umask = 0x2,
   .event_name = "page_walks.i_side_cycles",
   },
  {
   .event_code = {0x10},
   .umask = 0x1,
   .event_name = "x87_comp_ops_exe.any.s",
   },
  {
   .event_code = {0x10},
   .umask = 0x81,
   .event_name = "x87_comp_ops_exe.any.ar",
   },
  {
   .event_code = {0x10},
   .umask = 0x2,
   .event_name = "x87_comp_ops_exe.fxch.s",
   },
  {
   .event_code = {0x10},
   .umask = 0x82,
   .event_name = "x87_comp_ops_exe.fxch.ar",
   },
  {
   .event_code = {0x11},
   .umask = 0x1,
   .event_name = "fp_assist.s",
   },
  {
   .event_code = {0x11},
   .umask = 0x81,
   .event_name = "fp_assist.ar",
   },
  {
   .event_code = {0x12},
   .umask = 0x1,
   .event_name = "mul.s",
   },
  {
   .event_code = {0x12},
   .umask = 0x81,
   .event_name = "mul.ar",
   },
  {
   .event_code = {0x13},
   .umask = 0x1,
   .event_name = "div.s",
   },
  {
   .event_code = {0x13},
   .umask = 0x81,
   .event_name = "div.ar",
   },
  {
   .event_code = {0x14},
   .umask = 0x1,
   .event_name = "cycles_div_busy",
   },
  {
   .event_code = {0x21},
   .umask = 0x40,
   .event_name = "l2_ads.self",
   },
  {
   .event_code = {0x22},
   .umask = 0x40,
   .event_name = "l2_dbus_busy.self",
   },
  {
   .event_code = {0x23},
   .umask = 0x40,
   .event_name = "l2_dbus_busy_rd.self",
   },
  {
   .event_code = {0x24},
   .umask = 0x70,
   .event_name = "l2_lines_in.self.any",
   },
  {
   .event_code = {0x24},
   .umask = 0x40,
   .event_name = "l2_lines_in.self.demand",
   },
  {
   .event_code = {0x24},
   .umask = 0x50,
   .event_name = "l2_lines_in.self.prefetch",
   },
  {
   .event_code = {0x25},
   .umask = 0x40,
   .event_name = "l2_m_lines_in.self",
   },
  {
   .event_code = {0x26},
   .umask = 0x70,
   .event_name = "l2_lines_out.self.any",
   },
  {
   .event_code = {0x26},
   .umask = 0x40,
   .event_name = "l2_lines_out.self.demand",
   },
  {
   .event_code = {0x26},
   .umask = 0x50,
   .event_name = "l2_lines_out.self.prefetch",
   },
  {
   .event_code = {0x27},
   .umask = 0x70,
   .event_name = "l2_m_lines_out.self.any",
   },
  {
   .event_code = {0x27},
   .umask = 0x40,
   .event_name = "l2_m_lines_out.self.demand",
   },
  {
   .event_code = {0x27},
   .umask = 0x50,
   .event_name = "l2_m_lines_out.self.prefetch",
   },
  {
   .event_code = {0x28},
   .umask = 0x44,
   .event_name = "l2_ifetch.self.e_state",
   },
  {
   .event_code = {0x28},
   .umask = 0x41,
   .event_name = "l2_ifetch.self.i_state",
   },
  {
   .event_code = {0x28},
   .umask = 0x48,
   .event_name = "l2_ifetch.self.m_state",
   },
  {
   .event_code = {0x28},
   .umask = 0x42,
   .event_name = "l2_ifetch.self.s_state",
   },
  {
   .event_code = {0x28},
   .umask = 0x4F,
   .event_name = "l2_ifetch.self.mesi",
   },
  {
   .event_code = {0x29},
   .umask = 0x74,
   .event_name = "l2_ld.self.any.e_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x71,
   .event_name = "l2_ld.self.any.i_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x78,
   .event_name = "l2_ld.self.any.m_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x72,
   .event_name = "l2_ld.self.any.s_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x7F,
   .event_name = "l2_ld.self.any.mesi",
   },
  {
   .event_code = {0x29},
   .umask = 0x44,
   .event_name = "l2_ld.self.demand.e_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x41,
   .event_name = "l2_ld.self.demand.i_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x48,
   .event_name = "l2_ld.self.demand.m_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x42,
   .event_name = "l2_ld.self.demand.s_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x4F,
   .event_name = "l2_ld.self.demand.mesi",
   },
  {
   .event_code = {0x29},
   .umask = 0x54,
   .event_name = "l2_ld.self.prefetch.e_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x51,
   .event_name = "l2_ld.self.prefetch.i_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x58,
   .event_name = "l2_ld.self.prefetch.m_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x52,
   .event_name = "l2_ld.self.prefetch.s_state",
   },
  {
   .event_code = {0x29},
   .umask = 0x5F,
   .event_name = "l2_ld.self.prefetch.mesi",
   },
  {
   .event_code = {0x2A},
   .umask = 0x44,
   .event_name = "l2_st.self.e_state",
   },
  {
   .event_code = {0x2A},
   .umask = 0x41,
   .event_name = "l2_st.self.i_state",
   },
  {
   .event_code = {0x2A},
   .umask = 0x48,
   .event_name = "l2_st.self.m_state",
   },
  {
   .event_code = {0x2A},
   .umask = 0x42,
   .event_name = "l2_st.self.s_state",
   },
  {
   .event_code = {0x2A},
   .umask = 0x4F,
   .event_name = "l2_st.self.mesi",
   },
  {
   .event_code = {0x2B},
   .umask = 0x44,
   .event_name = "l2_lock.self.e_state",
   },
  {
   .event_code = {0x2B},
   .umask = 0x41,
   .event_name = "l2_lock.self.i_state",
   },
  {
   .event_code = {0x2B},
   .umask = 0x48,
   .event_name = "l2_lock.self.m_state",
   },
  {
   .event_code = {0x2B},
   .umask = 0x42,
   .event_name = "l2_lock.self.s_state",
   },
  {
   .event_code = {0x2B},
   .umask = 0x4F,
   .event_name = "l2_lock.self.mesi",
   },
  {
   .event_code = {0x2C},
   .umask = 0x44,
   .event_name = "l2_data_rqsts.self.e_state",
   },
  {
   .event_code = {0x2C},
   .umask = 0x41,
   .event_name = "l2_data_rqsts.self.i_state",
   },
  {
   .event_code = {0x2C},
   .umask = 0x48,
   .event_name = "l2_data_rqsts.self.m_state",
   },
  {
   .event_code = {0x2C},
   .umask = 0x42,
   .event_name = "l2_data_rqsts.self.s_state",
   },
  {
   .event_code = {0x2C},
   .umask = 0x4F,
   .event_name = "l2_data_rqsts.self.mesi",
   },
  {
   .event_code = {0x2D},
   .umask = 0x44,
   .event_name = "l2_ld_ifetch.self.e_state",
   },
  {
   .event_code = {0x2D},
   .umask = 0x41,
   .event_name = "l2_ld_ifetch.self.i_state",
   },
  {
   .event_code = {0x2D},
   .umask = 0x48,
   .event_name = "l2_ld_ifetch.self.m_state",
   },
  {
   .event_code = {0x2D},
   .umask = 0x42,
   .event_name = "l2_ld_ifetch.self.s_state",
   },
  {
   .event_code = {0x2D},
   .umask = 0x4F,
   .event_name = "l2_ld_ifetch.self.mesi",
   },
  {
   .event_code = {0x2E},
   .umask = 0x74,
   .event_name = "l2_rqsts.self.any.e_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x71,
   .event_name = "l2_rqsts.self.any.i_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x78,
   .event_name = "l2_rqsts.self.any.m_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x72,
   .event_name = "l2_rqsts.self.any.s_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x7F,
   .event_name = "l2_rqsts.self.any.mesi",
   },
  {
   .event_code = {0x2E},
   .umask = 0x44,
   .event_name = "l2_rqsts.self.demand.e_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x48,
   .event_name = "l2_rqsts.self.demand.m_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x42,
   .event_name = "l2_rqsts.self.demand.s_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x54,
   .event_name = "l2_rqsts.self.prefetch.e_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x51,
   .event_name = "l2_rqsts.self.prefetch.i_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x58,
   .event_name = "l2_rqsts.self.prefetch.m_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x52,
   .event_name = "l2_rqsts.self.prefetch.s_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x5F,
   .event_name = "l2_rqsts.self.prefetch.mesi",
   },
  {
   .event_code = {0x2E},
   .umask = 0x41,
   .event_name = "l2_rqsts.self.demand.i_state",
   },
  {
   .event_code = {0x2E},
   .umask = 0x4F,
   .event_name = "l2_rqsts.self.demand.mesi",
   },
  {
   .event_code = {0x30},
   .umask = 0x74,
   .event_name = "l2_reject_busq.self.any.e_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x71,
   .event_name = "l2_reject_busq.self.any.i_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x78,
   .event_name = "l2_reject_busq.self.any.m_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x72,
   .event_name = "l2_reject_busq.self.any.s_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x7F,
   .event_name = "l2_reject_busq.self.any.mesi",
   },
  {
   .event_code = {0x30},
   .umask = 0x44,
   .event_name = "l2_reject_busq.self.demand.e_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x41,
   .event_name = "l2_reject_busq.self.demand.i_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x48,
   .event_name = "l2_reject_busq.self.demand.m_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x42,
   .event_name = "l2_reject_busq.self.demand.s_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x4F,
   .event_name = "l2_reject_busq.self.demand.mesi",
   },
  {
   .event_code = {0x30},
   .umask = 0x54,
   .event_name = "l2_reject_busq.self.prefetch.e_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x51,
   .event_name = "l2_reject_busq.self.prefetch.i_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x58,
   .event_name = "l2_reject_busq.self.prefetch.m_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x52,
   .event_name = "l2_reject_busq.self.prefetch.s_state",
   },
  {
   .event_code = {0x30},
   .umask = 0x5F,
   .event_name = "l2_reject_busq.self.prefetch.mesi",
   },
  {
   .event_code = {0x32},
   .umask = 0x40,
   .event_name = "l2_no_req.self",
   },
  {
   .event_code = {0x3A},
   .umask = 0x0,
   .event_name = "eist_trans",
   },
  {
   .event_code = {0x3B},
   .umask = 0xC0,
   .event_name = "thermal_trip",
   },
  {
   .event_code = {0x3C},
   .umask = 0x0,
   .event_name = "cpu_clk_unhalted.core_p",
   },
  {
   .event_code = {0x3C},
   .umask = 0x1,
   .event_name = "cpu_clk_unhalted.bus",
   },
  {
   .event_code = {0xA},
   .umask = 0x0,
   .event_name = "cpu_clk_unhalted.core",
   },
  {
   .event_code = {0xA},
   .umask = 0x0,
   .event_name = "cpu_clk_unhalted.ref",
   },
  {
   .event_code = {0x40},
   .umask = 0xA1,
   .event_name = "l1d_cache.ld",
   },
  {
   .event_code = {0x40},
   .umask = 0xA2,
   .event_name = "l1d_cache.st",
   },
  {
   .event_code = {0x40},
   .umask = 0x83,
   .event_name = "l1d_cache.all_ref",
   },
  {
   .event_code = {0x40},
   .umask = 0xA3,
   .event_name = "l1d_cache.all_cache_ref",
   },
  {
   .event_code = {0x40},
   .umask = 0x8,
   .event_name = "l1d_cache.repl",
   },
  {
   .event_code = {0x40},
   .umask = 0x48,
   .event_name = "l1d_cache.replm",
   },
  {
   .event_code = {0x40},
   .umask = 0x10,
   .event_name = "l1d_cache.evict",
   },
  {
   .event_code = {0x60},
   .umask = 0xE0,
   .event_name = "bus_request_outstanding.all_agents",
   },
  {
   .event_code = {0x60},
   .umask = 0x40,
   .event_name = "bus_request_outstanding.self",
   },
  {
   .event_code = {0x61},
   .umask = 0x20,
   .event_name = "bus_bnr_drv.all_agents",
   },
  {
   .event_code = {0x61},
   .umask = 0x0,
   .event_name = "bus_bnr_drv.this_agent",
   },
  {
   .event_code = {0x62},
   .umask = 0x20,
   .event_name = "bus_drdy_clocks.all_agents",
   },
  {
   .event_code = {0x62},
   .umask = 0x0,
   .event_name = "bus_drdy_clocks.this_agent",
   },
  {
   .event_code = {0x63},
   .umask = 0xE0,
   .event_name = "bus_lock_clocks.all_agents",
   },
  {
   .event_code = {0x63},
   .umask = 0x40,
   .event_name = "bus_lock_clocks.self",
   },
  {
   .event_code = {0x64},
   .umask = 0x40,
   .event_name = "bus_data_rcv.self",
   },
  {
   .event_code = {0x65},
   .umask = 0xE0,
   .event_name = "bus_trans_brd.all_agents",
   },
  {
   .event_code = {0x65},
   .umask = 0x40,
   .event_name = "bus_trans_brd.self",
   },
  {
   .event_code = {0x66},
   .umask = 0xE0,
   .event_name = "bus_trans_rfo.all_agents",
   },
  {
   .event_code = {0x66},
   .umask = 0x40,
   .event_name = "bus_trans_rfo.self",
   },
  {
   .event_code = {0x67},
   .umask = 0xE0,
   .event_name = "bus_trans_wb.all_agents",
   },
  {
   .event_code = {0x67},
   .umask = 0x40,
   .event_name = "bus_trans_wb.self",
   },
  {
   .event_code = {0x68},
   .umask = 0xE0,
   .event_name = "bus_trans_ifetch.all_agents",
   },
  {
   .event_code = {0x68},
   .umask = 0x40,
   .event_name = "bus_trans_ifetch.self",
   },
  {
   .event_code = {0x69},
   .umask = 0xE0,
   .event_name = "bus_trans_inval.all_agents",
   },
  {
   .event_code = {0x69},
   .umask = 0x40,
   .event_name = "bus_trans_inval.self",
   },
  {
   .event_code = {0x6A},
   .umask = 0xE0,
   .event_name = "bus_trans_pwr.all_agents",
   },
  {
   .event_code = {0x6A},
   .umask = 0x40,
   .event_name = "bus_trans_pwr.self",
   },
  {
   .event_code = {0x6B},
   .umask = 0xE0,
   .event_name = "bus_trans_p.all_agents",
   },
  {
   .event_code = {0x6B},
   .umask = 0x40,
   .event_name = "bus_trans_p.self",
   },
  {
   .event_code = {0x6C},
   .umask = 0xE0,
   .event_name = "bus_trans_io.all_agents",
   },
  {
   .event_code = {0x6C},
   .umask = 0x40,
   .event_name = "bus_trans_io.self",
   },
  {
   .event_code = {0x6D},
   .umask = 0xE0,
   .event_name = "bus_trans_def.all_agents",
   },
  {
   .event_code = {0x6D},
   .umask = 0x40,
   .event_name = "bus_trans_def.self",
   },
  {
   .event_code = {0x6E},
   .umask = 0xE0,
   .event_name = "bus_trans_burst.all_agents",
   },
  {
   .event_code = {0x6E},
   .umask = 0x40,
   .event_name = "bus_trans_burst.self",
   },
  {
   .event_code = {0x6F},
   .umask = 0xE0,
   .event_name = "bus_trans_mem.all_agents",
   },
  {
   .event_code = {0x6F},
   .umask = 0x40,
   .event_name = "bus_trans_mem.self",
   },
  {
   .event_code = {0x70},
   .umask = 0xE0,
   .event_name = "bus_trans_any.all_agents",
   },
  {
   .event_code = {0x70},
   .umask = 0x40,
   .event_name = "bus_trans_any.self",
   },
  {
   .event_code = {0x77},
   .umask = 0xB,
   .event_name = "ext_snoop.this_agent.any",
   },
  {
   .event_code = {0x77},
   .umask = 0x1,
   .event_name = "ext_snoop.this_agent.clean",
   },
  {
   .event_code = {0x77},
   .umask = 0x2,
   .event_name = "ext_snoop.this_agent.hit",
   },
  {
   .event_code = {0x77},
   .umask = 0x8,
   .event_name = "ext_snoop.this_agent.hitm",
   },
  {
   .event_code = {0x77},
   .umask = 0x2B,
   .event_name = "ext_snoop.all_agents.any",
   },
  {
   .event_code = {0x77},
   .umask = 0x21,
   .event_name = "ext_snoop.all_agents.clean",
   },
  {
   .event_code = {0x77},
   .umask = 0x22,
   .event_name = "ext_snoop.all_agents.hit",
   },
  {
   .event_code = {0x77},
   .umask = 0x28,
   .event_name = "ext_snoop.all_agents.hitm",
   },
  {
   .event_code = {0x7A},
   .umask = 0x20,
   .event_name = "bus_hit_drv.all_agents",
   },
  {
   .event_code = {0x7A},
   .umask = 0x0,
   .event_name = "bus_hit_drv.this_agent",
   },
  {
   .event_code = {0x7B},
   .umask = 0x20,
   .event_name = "bus_hitm_drv.all_agents",
   },
  {
   .event_code = {0x7B},
   .umask = 0x0,
   .event_name = "bus_hitm_drv.this_agent",
   },
  {
   .event_code = {0x7D},
   .umask = 0x40,
   .event_name = "busq_empty.self",
   },
  {
   .event_code = {0x7E},
   .umask = 0xE0,
   .event_name = "snoop_stall_drv.all_agents",
   },
  {
   .event_code = {0x7E},
   .umask = 0x40,
   .event_name = "snoop_stall_drv.self",
   },
  {
   .event_code = {0x7F},
   .umask = 0x40,
   .event_name = "bus_io_wait.self",
   },
  {
   .event_code = {0x80},
   .umask = 0x3,
   .event_name = "icache.accesses",
   },
  {
   .event_code = {0x80},
   .umask = 0x1,
   .event_name = "icache.hit",
   },
  {
   .event_code = {0x80},
   .umask = 0x2,
   .event_name = "icache.misses",
   },
  {
   .event_code = {0x82},
   .umask = 0x1,
   .event_name = "itlb.hit",
   },
  {
   .event_code = {0x82},
   .umask = 0x4,
   .event_name = "itlb.flush",
   },
  {
   .event_code = {0x82},
   .umask = 0x2,
   .event_name = "itlb.misses",
   },
  {
   .event_code = {0x86},
   .umask = 0x1,
   .event_name = "cycles_icache_mem_stalled.icache_mem_stalled",
   },
  {
   .event_code = {0x87},
   .umask = 0x1,
   .event_name = "decode_stall.pfb_empty",
   },
  {
   .event_code = {0x87},
   .umask = 0x2,
   .event_name = "decode_stall.iq_full",
   },
  {
   .event_code = {0x88},
   .umask = 0x1,
   .event_name = "br_inst_type_retired.cond",
   },
  {
   .event_code = {0x88},
   .umask = 0x2,
   .event_name = "br_inst_type_retired.uncond",
   },
  {
   .event_code = {0x88},
   .umask = 0x4,
   .event_name = "br_inst_type_retired.ind",
   },
  {
   .event_code = {0x88},
   .umask = 0x8,
   .event_name = "br_inst_type_retired.ret",
   },
  {
   .event_code = {0x88},
   .umask = 0x10,
   .event_name = "br_inst_type_retired.dir_call",
   },
  {
   .event_code = {0x88},
   .umask = 0x20,
   .event_name = "br_inst_type_retired.ind_call",
   },
  {
   .event_code = {0x88},
   .umask = 0x41,
   .event_name = "br_inst_type_retired.cond_taken",
   },
  {
   .event_code = {0x89},
   .umask = 0x1,
   .event_name = "br_missp_type_retired.cond",
   },
  {
   .event_code = {0x89},
   .umask = 0x2,
   .event_name = "br_missp_type_retired.ind",
   },
  {
   .event_code = {0x89},
   .umask = 0x4,
   .event_name = "br_missp_type_retired.return",
   },
  {
   .event_code = {0x89},
   .umask = 0x8,
   .event_name = "br_missp_type_retired.ind_call",
   },
  {
   .event_code = {0x89},
   .umask = 0x11,
   .event_name = "br_missp_type_retired.cond_taken",
   },
  {
   .event_code = {0xAA},
   .umask = 0x1,
   .event_name = "macro_insts.non_cisc_decoded",
   },
  {
   .event_code = {0xAA},
   .umask = 0x2,
   .event_name = "macro_insts.cisc_decoded",
   },
  {
   .event_code = {0xAA},
   .umask = 0x3,
   .event_name = "macro_insts.all_decoded",
   },
  {
   .event_code = {0xB0},
   .umask = 0x0,
   .event_name = "simd_uops_exec.s",
   },
  {
   .event_code = {0xB0},
   .umask = 0x80,
   .event_name = "simd_uops_exec.ar",
   },
  {
   .event_code = {0xB1},
   .umask = 0x0,
   .event_name = "simd_sat_uop_exec.s",
   },
  {
   .event_code = {0xB1},
   .umask = 0x80,
   .event_name = "simd_sat_uop_exec.ar",
   },
  {
   .event_code = {0xB3},
   .umask = 0x1,
   .event_name = "simd_uop_type_exec.mul.s",
   },
  {
   .event_code = {0xB3},
   .umask = 0x81,
   .event_name = "simd_uop_type_exec.mul.ar",
   },
  {
   .event_code = {0xB3},
   .umask = 0x2,
   .event_name = "simd_uop_type_exec.shift.s",
   },
  {
   .event_code = {0xB3},
   .umask = 0x82,
   .event_name = "simd_uop_type_exec.shift.ar",
   },
  {
   .event_code = {0xB3},
   .umask = 0x4,
   .event_name = "simd_uop_type_exec.pack.s",
   },
  {
   .event_code = {0xB3},
   .umask = 0x84,
   .event_name = "simd_uop_type_exec.pack.ar",
   },
  {
   .event_code = {0xB3},
   .umask = 0x8,
   .event_name = "simd_uop_type_exec.unpack.s",
   },
  {
   .event_code = {0xB3},
   .umask = 0x88,
   .event_name = "simd_uop_type_exec.unpack.ar",
   },
  {
   .event_code = {0xB3},
   .umask = 0x10,
   .event_name = "simd_uop_type_exec.logical.s",
   },
  {
   .event_code = {0xB3},
   .umask = 0x90,
   .event_name = "simd_uop_type_exec.logical.ar",
   },
  {
   .event_code = {0xB3},
   .umask = 0x20,
   .event_name = "simd_uop_type_exec.arithmetic.s",
   },
  {
   .event_code = {0xB3},
   .umask = 0xA0,
   .event_name = "simd_uop_type_exec.arithmetic.ar",
   },
  {
   .event_code = {0xC0},
   .umask = 0x0,
   .event_name = "inst_retired.any_p",
   },
  {
   .event_code = {0xA},
   .umask = 0x0,
   .event_name = "inst_retired.any",
   },
  {
   .event_code = {0xC2},
   .umask = 0x10,
   .event_name = "uops_retired.any",
   },
  {
   .event_code = {0xC2},
   .umask = 0x10,
   .event_name = "uops_retired.stalled_cycles",
   },
  {
   .event_code = {0xC2},
   .umask = 0x10,
   .event_name = "uops_retired.stalls",
   },
  {
   .event_code = {0xA9},
   .umask = 0x1,
   .event_name = "uops.ms_cycles",
   },
  {
   .event_code = {0xC3},
   .umask = 0x1,
   .event_name = "machine_clears.smc",
   },
  {
   .event_code = {0xC4},
   .umask = 0x0,
   .event_name = "br_inst_retired.any",
   },
  {
   .event_code = {0xC4},
   .umask = 0x1,
   .event_name = "br_inst_retired.pred_not_taken",
   },
  {
   .event_code = {0xC4},
   .umask = 0x2,
   .event_name = "br_inst_retired.mispred_not_taken",
   },
  {
   .event_code = {0xC4},
   .umask = 0x4,
   .event_name = "br_inst_retired.pred_taken",
   },
  {
   .event_code = {0xC4},
   .umask = 0x8,
   .event_name = "br_inst_retired.mispred_taken",
   },
  {
   .event_code = {0xC4},
   .umask = 0xC,
   .event_name = "br_inst_retired.taken",
   },
  {
   .event_code = {0xC4},
   .umask = 0xF,
   .event_name = "br_inst_retired.any1",
   },
  {
   .event_code = {0xC5},
   .umask = 0x0,
   .event_name = "br_inst_retired.mispred",
   },
  {
   .event_code = {0xC6},
   .umask = 0x1,
   .event_name = "cycles_int_masked.cycles_int_masked",
   },
  {
   .event_code = {0xC6},
   .umask = 0x2,
   .event_name = "cycles_int_masked.cycles_int_pending_and_masked",
   },
  {
   .event_code = {0xC7},
   .umask = 0x1,
   .event_name = "simd_inst_retired.packed_single",
   },
  {
   .event_code = {0xC7},
   .umask = 0x2,
   .event_name = "simd_inst_retired.scalar_single",
   },
  {
   .event_code = {0xC7},
   .umask = 0x8,
   .event_name = "simd_inst_retired.scalar_double",
   },
  {
   .event_code = {0xC7},
   .umask = 0x10,
   .event_name = "simd_inst_retired.vector",
   },
  {
   .event_code = {0xC8},
   .umask = 0x0,
   .event_name = "hw_int_rcv",
   },
  {
   .event_code = {0xCA},
   .umask = 0x1,
   .event_name = "simd_comp_inst_retired.packed_single",
   },
  {
   .event_code = {0xCA},
   .umask = 0x2,
   .event_name = "simd_comp_inst_retired.scalar_single",
   },
  {
   .event_code = {0xCA},
   .umask = 0x8,
   .event_name = "simd_comp_inst_retired.scalar_double",
   },
  {
   .event_code = {0xCB},
   .umask = 0x1,
   .event_name = "mem_load_retired.l2_hit",
   },
  {
   .event_code = {0xCB},
   .umask = 0x2,
   .event_name = "mem_load_retired.l2_miss",
   },
  {
   .event_code = {0xCB},
   .umask = 0x4,
   .event_name = "mem_load_retired.dtlb_miss",
   },
  {
   .event_code = {0xCD},
   .umask = 0x0,
   .event_name = "simd_assist",
   },
  {
   .event_code = {0xCE},
   .umask = 0x0,
   .event_name = "simd_instr_retired",
   },
  {
   .event_code = {0xCF},
   .umask = 0x0,
   .event_name = "simd_sat_instr_retired",
   },
  {
   .event_code = {0xDC},
   .umask = 0x2,
   .event_name = "resource_stalls.div_busy",
   },
  {
   .event_code = {0xE0},
   .umask = 0x1,
   .event_name = "br_inst_decoded",
   },
  {
   .event_code = {0xE4},
   .umask = 0x1,
   .event_name = "bogus_br",
   },
  {
   .event_code = {0xE6},
   .umask = 0x1,
   .event_name = "baclears.any",
   },
  {
   .event_code = {0x3},
   .umask = 0x1,
   .event_name = "reissue.overlap_store",
   },
  {
   .event_code = {0x3},
   .umask = 0x81,
   .event_name = "reissue.overlap_store.ar",
   },
  {
   .event_name = 0,
   },
};

PERFMON_REGISTER_INTEL_PMC (cpu_model_table, event_table);

