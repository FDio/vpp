/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#include <vppinfra/cpt.h>

typedef struct v6_addr_t_
{
  u8 data[16];
} v6_addr_t;

#define TEST_CPT(_expr, _fmt, _args...)                  \
  {                                                      \
    if ((_expr))                                         \
      {                                                  \
        fformat(stdout, "PASS: " _fmt "\n" , ##_args);   \
      }                                                  \
    else                                                 \
      {                                                  \
        fformat(stdout, "FAIL: " _fmt "\n" , ##_args);   \
        ASSERT(0);                                       \
      }                                                  \
  }                                                      \

int
test_cpt_main (void)
{
  cpt_128_t cpt;

  cpt_init(&cpt);
  
  fformat(stdout, "%U", format_cpt, &cpt);

  /*
   * the default route ::/0
   */
  const v6_addr_t pfx_0_s_0 = {
  };

  cpt_insert(&cpt, pfx_0_s_0.data, 0, 100);
  fformat(stdout, "%U", format_cpt, &cpt);

  TEST_CPT(100 == cpt_search(&cpt, pfx_0_s_0.data), "Find default route");

  /*
   * A longer mask prefix - 1::/4
   */
  const v6_addr_t pfx_1_s_4 = {
    .data[15] = 0x10,
  };

  cpt_insert(&cpt, pfx_1_s_4.data, 4, 200);
  fformat(stdout, "%U", format_cpt, &cpt);

  TEST_CPT(200 == cpt_search(&cpt, pfx_1_s_4.data), "Find 1::/4");

  /*
   * A prefix inserted between the default route and 1::/4 - 4::/2
   */
  const v6_addr_t pfx_4_s_2 = {
    .data[15] = 0x40,
  };

  cpt_insert(&cpt, pfx_4_s_2.data, 2, 300);
  fformat(stdout, "%U", format_cpt, &cpt);

  TEST_CPT(300 == cpt_search(&cpt, pfx_4_s_2.data), "Find 4::/2");
  TEST_CPT(200 == cpt_search(&cpt, pfx_1_s_4.data), "Find 1::/4");
  TEST_CPT(100 == cpt_search(&cpt, pfx_0_s_0.data), "Find default route");

  /*
   * A longer mask prefix - 1::/8
   */
  const v6_addr_t pfx_1_s_8 = {
    .data[15] = 0x10,
  };

  cpt_insert(&cpt, pfx_1_s_8.data, 8, 400);
  fformat(stdout, "%U", format_cpt, &cpt);

  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_8.data), "Find 1::/8");
  TEST_CPT(300 == cpt_search(&cpt, pfx_4_s_2.data), "Find 4::/2");
  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_4.data), "Find 1::/4");
  TEST_CPT(100 == cpt_search(&cpt, pfx_0_s_0.data), "Find default route");

  TEST_CPT(400 == cpt_search_exact(&cpt, pfx_1_s_8.data, 8), "Exact Find 1::/8");
  TEST_CPT(300 == cpt_search_exact(&cpt, pfx_4_s_2.data, 2), "Exact Find 4::/2");
  TEST_CPT(200 == cpt_search_exact(&cpt, pfx_1_s_4.data, 4), "Exact Find 1::/4");
  TEST_CPT(100 == cpt_search_exact(&cpt, pfx_0_s_0.data, 0), "Exact Find default route");

  /*
   * insert shorter mask prefix - 1::/7
   */
  const v6_addr_t pfx_1_s_7 = {
    .data[15] = 0x10,
  };

  cpt_insert(&cpt, pfx_1_s_7.data, 7, 500);
  fformat(stdout, "%U", format_cpt, &cpt);

  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_7.data), "Find 1::/7");
  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_8.data), "Find 1::/8");
  TEST_CPT(300 == cpt_search(&cpt, pfx_4_s_2.data), "Find 4::/2");
  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_4.data), "Find 1::/4");
  TEST_CPT(100 == cpt_search(&cpt, pfx_0_s_0.data), "Find default route");

  TEST_CPT(500 == cpt_search_exact(&cpt, pfx_1_s_7.data, 7), "Exact Find 1::/7");
  TEST_CPT(400 == cpt_search_exact(&cpt, pfx_1_s_8.data, 8), "Exact Find 1::/8");
  TEST_CPT(300 == cpt_search_exact(&cpt, pfx_4_s_2.data, 2), "Exact Find 4::/2");
  TEST_CPT(200 == cpt_search_exact(&cpt, pfx_1_s_4.data, 4), "Exact Find 1::/4");
  TEST_CPT(100 == cpt_search_exact(&cpt, pfx_0_s_0.data, 0), "Exact Find default route");

  /*
   * Add other child of 1::/7 - 1:1::/8
   */
  const v6_addr_t pfx_1_1_s_8 = {
    .data[15] = 0x11,
  };

  cpt_insert(&cpt, pfx_1_1_s_8.data, 8, 600);
  fformat(stdout, "%U", format_cpt, &cpt);

  TEST_CPT(600 == cpt_search(&cpt, pfx_1_1_s_8.data), "Find 1:1::/8");
  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_7.data), "Find 1::/7");
  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_8.data), "Find 1::/8");
  TEST_CPT(300 == cpt_search(&cpt, pfx_4_s_2.data), "Find 4::/2");
  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_4.data), "Find 1::/4");
  TEST_CPT(100 == cpt_search(&cpt, pfx_0_s_0.data), "Find default route");

  TEST_CPT(600 == cpt_search_exact(&cpt, pfx_1_1_s_8.data, 8), "Exact Find 1:1::/8");
  TEST_CPT(500 == cpt_search_exact(&cpt, pfx_1_s_7.data, 7), "Exact Find 1::/7");
  TEST_CPT(400 == cpt_search_exact(&cpt, pfx_1_s_8.data, 8), "Exact Find 1::/8");
  TEST_CPT(300 == cpt_search_exact(&cpt, pfx_4_s_2.data, 2), "Exact Find 4::/2");
  TEST_CPT(200 == cpt_search_exact(&cpt, pfx_1_s_4.data, 4), "Exact Find 1::/4");
  TEST_CPT(100 == cpt_search_exact(&cpt, pfx_0_s_0.data, 0), "Exact Find default route");

  /*
   * insert between ::/0 - (4::/2 and 1::/4) = ::/2
   */
  const v6_addr_t pfx_0_s_2 = {
    .data[15] = 0x0,
  };

  cpt_insert(&cpt, pfx_0_s_2.data, 2, 700);
  fformat(stdout, "%U", format_cpt, &cpt);

  TEST_CPT(600 == cpt_search(&cpt, pfx_1_1_s_8.data), "Find 1:1::/8");
  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_7.data), "Find 1::/7");
  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_8.data), "Find 1::/8");
  TEST_CPT(300 == cpt_search(&cpt, pfx_4_s_2.data), "Find 4::/2");
  TEST_CPT(400 == cpt_search(&cpt, pfx_1_s_4.data), "Find 1::/4");
  TEST_CPT(700 == cpt_search(&cpt, pfx_0_s_0.data), "Find default route");

  TEST_CPT(700 == cpt_search_exact(&cpt, pfx_0_s_2.data, 2), "Exact Find ::/2");
  TEST_CPT(600 == cpt_search_exact(&cpt, pfx_1_1_s_8.data, 8), "Exact Find 1:1::/8");
  TEST_CPT(500 == cpt_search_exact(&cpt, pfx_1_s_7.data, 7), "Exact Find 1::/7");
  TEST_CPT(400 == cpt_search_exact(&cpt, pfx_1_s_8.data, 8), "Exact Find 1::/8");
  TEST_CPT(300 == cpt_search_exact(&cpt, pfx_4_s_2.data, 2), "Exact Find 4::/2");
  TEST_CPT(200 == cpt_search_exact(&cpt, pfx_1_s_4.data, 4), "Exact Find 1::/4");
  TEST_CPT(100 == cpt_search_exact(&cpt, pfx_0_s_0.data, 0), "Exact Find default route");

  /*
   * 4 /64s all covered by the same /62, but don't insert the /62
   */
  const v6_addr_t pfx_1_s_64 = {
    .data[15] = 0x10,
  };

  cpt_insert(&cpt, pfx_1_s_64.data, 64, 800);
  fformat(stdout, "%U", format_cpt, &cpt);

  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_64.data), "Find 1::/64");
  TEST_CPT(600 == cpt_search(&cpt, pfx_1_1_s_8.data), "Find 1:1::/8");
  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_7.data), "Find 1::/7");
  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_8.data), "Find 1::/8");
  TEST_CPT(300 == cpt_search(&cpt, pfx_4_s_2.data), "Find 4::/2");
  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_4.data), "Find 1::/4");
  TEST_CPT(700 == cpt_search(&cpt, pfx_0_s_0.data), "Find default route");

  TEST_CPT(800 == cpt_search_exact(&cpt, pfx_1_s_64.data, 64), "Exact Find ::/2");
  TEST_CPT(700 == cpt_search_exact(&cpt, pfx_0_s_2.data, 2), "Exact Find ::/2");
  TEST_CPT(600 == cpt_search_exact(&cpt, pfx_1_1_s_8.data, 8), "Exact Find 1:1::/8");
  TEST_CPT(500 == cpt_search_exact(&cpt, pfx_1_s_7.data, 7), "Exact Find 1::/7");
  TEST_CPT(400 == cpt_search_exact(&cpt, pfx_1_s_8.data, 8), "Exact Find 1::/8");
  TEST_CPT(300 == cpt_search_exact(&cpt, pfx_4_s_2.data, 2), "Exact Find 4::/2");
  TEST_CPT(200 == cpt_search_exact(&cpt, pfx_1_s_4.data, 4), "Exact Find 1::/4");
  TEST_CPT(100 == cpt_search_exact(&cpt, pfx_0_s_0.data, 0), "Exact Find default route");

  const v6_addr_t pfx_1_1_s_64 = {
    .data[15] = 0x10,
    .data[8] = 0x01,
  };

  cpt_insert(&cpt, pfx_1_1_s_64.data, 64, 900);
  fformat(stdout, "%U", format_cpt, &cpt);

  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_64.data), "Find 1::/64");
  TEST_CPT(900 == cpt_search(&cpt, pfx_1_1_s_64.data), "Find 1::1/64");
  TEST_CPT(600 == cpt_search(&cpt, pfx_1_1_s_8.data), "Find 1:1::/8");
  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_7.data), "Find 1::/7");
  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_8.data), "Find 1::/8");
  TEST_CPT(300 == cpt_search(&cpt, pfx_4_s_2.data), "Find 4::/2");
  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_4.data), "Find 1::/4");
  TEST_CPT(700 == cpt_search(&cpt, pfx_0_s_0.data), "Find default route");

  TEST_CPT(800 == cpt_search_exact(&cpt, pfx_1_s_64.data, 64), "Exact Find ::/2");
  TEST_CPT(700 == cpt_search_exact(&cpt, pfx_0_s_2.data, 2), "Exact Find ::/2");
  TEST_CPT(600 == cpt_search_exact(&cpt, pfx_1_1_s_8.data, 8), "Exact Find 1:1::/8");
  TEST_CPT(500 == cpt_search_exact(&cpt, pfx_1_s_7.data, 7), "Exact Find 1::/7");
  TEST_CPT(400 == cpt_search_exact(&cpt, pfx_1_s_8.data, 8), "Exact Find 1::/8");
  TEST_CPT(300 == cpt_search_exact(&cpt, pfx_4_s_2.data, 2), "Exact Find 4::/2");
  TEST_CPT(200 == cpt_search_exact(&cpt, pfx_1_s_4.data, 4), "Exact Find 1::/4");
  TEST_CPT(100 == cpt_search_exact(&cpt, pfx_0_s_0.data, 0), "Exact Find default route");

  const v6_addr_t pfx_1_2_s_64 = {
    .data[15] = 0x10,
    .data[8] = 0x02,
  };

  cpt_insert(&cpt, pfx_1_2_s_64.data, 64, 1000);
  fformat(stdout, "%U", format_cpt, &cpt);

  TEST_CPT(1000 == cpt_search(&cpt, pfx_1_s_64.data), "Find 1:2::/64");
  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_64.data), "Find 1::/64");
  TEST_CPT(900 == cpt_search(&cpt, pfx_1_1_s_64.data), "Find 1::1/64");
  TEST_CPT(600 == cpt_search(&cpt, pfx_1_1_s_8.data), "Find 1:1::/8");
  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_7.data), "Find 1::/7");
  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_8.data), "Find 1::/8");
  TEST_CPT(300 == cpt_search(&cpt, pfx_4_s_2.data), "Find 4::/2");
  TEST_CPT(800 == cpt_search(&cpt, pfx_1_s_4.data), "Find 1::/4");
  TEST_CPT(700 == cpt_search(&cpt, pfx_0_s_0.data), "Find default route");

  TEST_CPT(800 == cpt_search_exact(&cpt, pfx_1_s_64.data, 64), "Exact Find ::/2");
  TEST_CPT(700 == cpt_search_exact(&cpt, pfx_0_s_2.data, 2), "Exact Find ::/2");
  TEST_CPT(600 == cpt_search_exact(&cpt, pfx_1_1_s_8.data, 8), "Exact Find 1:1::/8");
  TEST_CPT(500 == cpt_search_exact(&cpt, pfx_1_s_7.data, 7), "Exact Find 1::/7");
  TEST_CPT(400 == cpt_search_exact(&cpt, pfx_1_s_8.data, 8), "Exact Find 1::/8");
  TEST_CPT(300 == cpt_search_exact(&cpt, pfx_4_s_2.data, 2), "Exact Find 4::/2");
  TEST_CPT(200 == cpt_search_exact(&cpt, pfx_1_s_4.data, 4), "Exact Find 1::/4");
  TEST_CPT(100 == cpt_search_exact(&cpt, pfx_0_s_0.data, 0), "Exact Find default route");

  return 0;
}

#ifdef CLIB_UNIX
int
main (int argc, char *argv[])
{
  int ret;

  clib_mem_init (0, 3ULL << 30);

  ret = test_cpt_main ();

  return ret;
}
#endif /* CLIB_UNIX */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
