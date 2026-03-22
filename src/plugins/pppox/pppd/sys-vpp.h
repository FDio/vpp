/*
 * sys-vpp.h - declarations for sys-vpp.c
 */
#ifndef _SYS_VPP_H_
#define _SYS_VPP_H_

extern void pppd_calltimeout (void);
extern void new_phase (int unit, int p);
extern void channel_cleanup (int unit);
extern int ppp_send_config (int unit, int mtu, int accm, int pcomp, int accomp);
extern int ppp_recv_config (int unit, int mru, int accm, int pcomp, int accomp);
extern void netif_set_mtu (int unit, int mtu);
extern int netif_get_mtu (int unit);
extern void lcp_open (int unit);
extern void lcp_close (int unit, char *reason);
extern void start_link (int unit);
extern void auth_reset (int unit);

#endif /* _SYS_VPP_H_ */
