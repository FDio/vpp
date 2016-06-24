/* 
 * math64.h provides the 64 bit unsigned integer add, multiply followed by  modulo operation
 * The linux/math64.h provides divide and multiply 64 bit integers but:
 * 1. multiply: mul_u64_u64_shr - only returns 64 bits of the result and has to be called
 *                     twice to get the complete 128 bits of the result.
 * 2. Modulo operation of the result of  addition and multiplication of u64 that may result 
 *                        in integers > 64 bits is not supported
 * Hence this header to combine add/multiply followed by modulo of u64 integrers
 * always resulting in u64.
 * 
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
#ifndef include_vnet_math64_h
#define include_vnet_math64_h
#include <stdint.h>

/* 
 * multiplies and returns result in hi and lo 
 */
static inline void mul64by64(u64 a, u64 b, u64 * hi, u64 * lo)
{
    u64 a_lo = (u64) (uint32_t) a;
    u64 a_hi = a >> 32;
    u64 b_lo = (u64) (u32) b;
    u64 b_hi = b >> 32;

    u64 p0 = a_lo * b_lo;
    u64 p1 = a_lo * b_hi;
    u64 p2 = a_hi * b_lo;
    u64 p3 = a_hi * b_hi;

    u32 cy = (u32) (((p0 >> 32) + (u32) p1 + (u32) p2) >> 32);

    *lo = p0 + (p1 << 32) + (p2 << 32);
    *hi = p3 + (p1 >> 32) + (p2 >> 32) + cy;
    return;
}

#define TWO64 18446744073709551616.0

static inline u64 mod128by64(u64 x, u64 y, u64 m, double di)
{
    u64 q1, q2, q;
    u64 p1, p0;
    double dq;

    /* calculate quotient first pass 53 bits */
    dq = (TWO64 * (double)x + (double)y) * di;

    if (dq >= TWO64)
        q1 = 0xfffffffffffff800L;
    else
        q1 = dq;

    /* q1 * m to compare the product to the dividend.  */
    mul64by64(q1, m, &p1, &p0);

    /* Adjust quotient. is it > actual result: */
    if (x < p1 || (x == p1 && y < p0))
    {
        /* q1 > quotient.  calculate abs remainder */
        x = p1 - (x + (p0 < y));
        y = p0 - y;

        /* use the remainder as new dividend to adjust quotient */
        q2 = (u64) ((TWO64 * (double)x + (double)y) * di);
        mul64by64(q2, m, &p1, &p0);

        q = q1 - q2;
        if (x < p1 || (x == p1 && y <= p0))
        {
            y = p0 - y;
        }
        else
        {
            y = p0 - y;
            y += m;
            q--;
        }
    }
    else
    {
        x = x - (p1 + (y < p0));
        y = y - p0;

        q2 = (u64) ((TWO64 * (double)x + (double)y) * di);
        mul64by64(q2, m, &p1, &p0);

        q = q1 + q2;
        if (x < p1 || (x == p1 && y < p0))
        {
            y = y - p0;
            y += m;
            q--;
        }
        else
        {
            y = y - p0;
            if (y >= m)
            {
                y -= m;
                q++;
            }
        }
    }

    return y;
}

/* 
 * returns a % p
 */
static inline u64 mod64by64(u64 a, u64 p, u64 primeinv)
{
    return (mod128by64(0, a, p, primeinv));
}

static inline void add64(u64 a, u64 b, u64 * whi, u64 * wlo)
{
    *wlo = a + b;
    if (*wlo < a)
        *whi = 1;

}

/* 
 * returns (a + b)%p
 */
static inline u64 add64_mod(u64 a, u64 b, u64 p, double pi)
{
    u64 shi = 0, slo = 0;

    add64(a, b, &shi, &slo);
    return (mod128by64(shi, slo, p, pi));
}

/* 
 * returns (ab) % p
 */
static inline u64 mul64_mod(u64 a, u64 b, u64 p, double pi)
{
    u64 phi = 0, plo = 0;

    mul64by64(a, b, &phi, &plo);
    return (mod128by64(phi, plo, p, pi));
}

#endif
