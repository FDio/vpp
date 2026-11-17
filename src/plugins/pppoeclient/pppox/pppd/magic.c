/* SPDX-License-Identifier: BSD-Attribution-HPND-disclaimer */
/*
 * magic.c - PPP Magic Number routines.
 *
 * Copyright (c) 1984-2000 Carnegie Mellon University. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define RCSID "$Id: magic.c,v 1.11 2003/06/11 23:56:26 paulus Exp $"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <vppinfra/random.h>

#include "pppd.h"
#include "magic.h"

/* static const char rcsid[] = RCSID; */

static u32 magic_seed = 0x9e3779b9;

/*
 * magic_init - Initialize the magic number generator.
 */
void
magic_init (void)
{
  u32 seed;

  seed = (u32) get_host_seed () ^ random_default_seed () ^ (u32) getpid ();
  magic_seed = seed ? seed : 0x9e3779b9;
}

/*
 * magic - Returns the next magic number.
 */
u_int32_t
magic (void)
{
  return (u_int32_t) random_u32 (&magic_seed);
}

/*
 * random_bytes - Fill a buffer with random bytes.
 */
void
random_bytes (unsigned char *buf, int len)
{
  int i;

  for (i = 0; i < len; ++i)
    buf[i] = (unsigned char) (random_u32 (&magic_seed) >> 24);
}
