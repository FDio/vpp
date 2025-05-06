u8 *
get_pcapng_shb_vec ();

u8 *
get_pcapng_idb (u8 **orig_block, u32 if_index, const char *if_name);

int
vec_add_pcapng_epb (u8 **vec_out, void *context, u32 if_index, u64 timestamp,
                       u32 orig_len, void *packet_data, u32 packet_len);

