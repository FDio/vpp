/*
 * IPTFS functions called by ipsec
 */
extern uword unformat_iptfs_config (unformat_input_t *input, va_list *args);
extern u8 *format_iptfs_config (u8 *s, va_list *args);
extern u8 *format_iptfs_data (u8 *s, va_list *args);
extern int iptfs_add_del_sa (u32 sa_index, void *tfs_config, u8 is_add, clib_error_t **pce);
extern clib_error_t * iptfs_add_del_policy (u32 sa_index, u8 is_add);
extern void iptfs_tunnel_feature_set (void *_itp, u8 enabled);
