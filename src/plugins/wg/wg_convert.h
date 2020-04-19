/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2015-2020 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 */

#ifndef __included_wg_convert_h__
#define __included_wg_convert_h__

#include <wg/wg.h>

bool key_from_base64 (u8 key[NOISE_PUBLIC_KEY_LEN], const char *base64);
void key_to_base64 (char base64[NOISE_KEY_LEN_BASE64],
		    const uint8_t key[NOISE_PUBLIC_KEY_LEN]);

#endif /* __included_wg_convert_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
