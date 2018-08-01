/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vlib/vlib.h>

static clib_error_t *
test_crash_command_fn (vlib_main_t * vm,
		       unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u64 *p = (u64 *) 0xdefec8ed;

  /* *INDENT-OFF* */
  ELOG_TYPE_DECLARE (e) =
    {
      .format = "deliberate crash: touching %x",
      .format_args = "i4",
    };
  /* *INDENT-ON* */
  elog (&vm->elog_main, &e, 0xdefec8ed);

  *p = 0xdeadbeef;

  /* Not so much... */
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_crash_command, static) =
{
  .path = "test crash",
  .short_help = "crash the bus!",
  .function = test_crash_command_fn,
};
/* *INDENT-ON* */

#define pf(i)                                                   \
do {                                                            \
  CLIB_PREFETCH (baseva + offsets[i], CLIB_CACHE_LINE_BYTES,    \
                 STORE);                                        \
} while (0);

#define st(i) (baseva + offsets[i])[0] = i;

#define barrier __sync_synchronize(); 

static clib_error_t *
test_lsu_command_fn (vlib_main_t * vm,
		     unformat_input_t * input, vlib_cli_command_t * cmd)
{
  u64 size = 1 << 30;
  u8 *baseva;
  u64 **timestamps = 0;
  u64 *deltas = 0;
  int i, j;
  int niter = 20;
  u64 seed = 0xdeaddabeULL;
  u64 * offsets = 0;
  uword offset;
  int verbose = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "niter %d", &niter))
        ;
      else if (unformat (input, "size %U", unformat_memory_size, &size))
        ;
      else if (unformat (input, "seed %lld", &seed))
        ;
      else if (unformat (input, "verbose %|", &verbose))
        ;
      else
        break;
    }

  /* Pick 256 random unique cache line offsets within the arena */
  for (i = 0; i < 256; i++)
    {
    again:
      offset = random_u64 (&seed);
      offset %= (size / CLIB_CACHE_LINE_BYTES);
      
      for (j = 0; j < i; j++)
        {
          if (offsets[j] == offset)
            goto again;
        } 
      vec_add1 (offsets, offset * CLIB_CACHE_LINE_BYTES);
    }

  baseva = mmap (0, size, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, 0 /* fd */ ,
		 0 /* offset */ );

  if (baseva == MAP_FAILED)
    return clib_error_return_unix (0, "mmap failure");

  /* Make sure vectors are big enough... */
  vec_validate (timestamps, niter - 1);
  vec_validate (deltas, 17);
  for (i = 0; i < niter; i++)
    {
      u64 *this_ts = 0;
      vec_validate (this_ts, 35);
      timestamps[i] = this_ts;
    }

  for (i = 0; i < niter; i++)
    {
      /* Chill the cache */
      for (offset = 0; offset < size; offset += CLIB_CACHE_LINE_BYTES)
	(baseva + offset)[0] = 0xFF;

      /* 1 */
      timestamps[i][0] = __builtin_ia32_rdtsc ();
      pf (0);
      timestamps[i][1] = __builtin_ia32_rdtsc ();
      st (0);
      barrier;

      /* 2 */
      timestamps[i][2] = __builtin_ia32_rdtsc ();
      pf (1);
      pf (2);
      timestamps[i][3] = __builtin_ia32_rdtsc ();
      st (1);
      st (2);
      barrier;

      /* 3 */
      timestamps[i][4] = __builtin_ia32_rdtsc ();
      pf (3);
      pf (4);
      pf (5);
      timestamps[i][5] = __builtin_ia32_rdtsc ();
      st (3);
      st (4);
      st (5);
      barrier;

      /* 4 */
      timestamps[i][6] = __builtin_ia32_rdtsc ();
      pf (6);
      pf (7);
      pf (8);
      pf (9);
      timestamps[i][7] = __builtin_ia32_rdtsc ();
      st (6);
      st (7);
      st (8);
      st (9);
      barrier;

      /* 5 */
      timestamps[i][8] = __builtin_ia32_rdtsc ();
      pf (10);
      pf (11);
      pf (12);
      pf (13);
      pf (14);
      timestamps[i][9] = __builtin_ia32_rdtsc ();
      st (10);
      st (11);
      st (12);
      st (13);
      st (14);
      barrier;

      /* 6 */
      timestamps[i][10] = __builtin_ia32_rdtsc ();
      pf (15);
      pf (16);
      pf (17);
      pf (18);
      pf (19);
      pf (20);
      timestamps[i][11] = __builtin_ia32_rdtsc ();
      st (15);
      st (16);
      st (17);
      st (18);
      st (19);
      st (20);
      barrier;

      /* 7 */
      timestamps[i][12] = __builtin_ia32_rdtsc ();
      pf (21);
      pf (22);
      pf (23);
      pf (24);
      pf (25);
      pf (26);
      pf (27);
      timestamps[i][13] = __builtin_ia32_rdtsc ();
      st (21);
      st (22);
      st (23);
      st (24);
      st (25);
      st (26);
      st (27);
      barrier;

      /* 8  */
      timestamps[i][14] = __builtin_ia32_rdtsc ();
      pf (28);
      pf (29);
      pf (30);
      pf (31);
      pf (32);
      pf (33);
      pf (34);
      pf (35);
      timestamps[i][15] = __builtin_ia32_rdtsc ();
      st (28);
      st (29);
      st (30);
      st (31);
      st (32);
      st (33);
      st (34);
      st (35);
      barrier;

      /* 9  */
      timestamps[i][16] = __builtin_ia32_rdtsc ();
      pf (36);
      pf (37);
      pf (38);
      pf (39);
      pf (40);
      pf (41);
      pf (42);
      pf (43);
      pf (44);

      timestamps[i][17] = __builtin_ia32_rdtsc ();
      st (36);
      st (37);
      st (38);
      st (39);
      st (40);
      st (41);
      st (42);
      st (43);
      st (44);
      barrier;

      /* 10  */
      timestamps[i][18] = __builtin_ia32_rdtsc ();
      pf (45);
      pf (46);
      pf (47);
      pf (48);
      pf (49);
      pf (50);
      pf (51);
      pf (52);
      pf (53);
      pf (54);
      timestamps[i][19] = __builtin_ia32_rdtsc ();
      st (45);
      st (46);
      st (47);
      st (48);
      st (49);
      st (50);
      st (51);
      st (52);
      st (53);
      st (54);
      barrier;

      /* 11  */
      timestamps[i][20] = __builtin_ia32_rdtsc ();
      pf (55);
      pf (56);
      pf (57);
      pf (58);
      pf (59);
      pf (60);
      pf (61);
      pf (62);
      pf (63);
      pf (64);
      pf (65);
      timestamps[i][21] = __builtin_ia32_rdtsc ();
      st (55);
      st (56);
      st (57);
      st (58);
      st (59);
      st (60);
      st (61);
      st (62);
      st (63);
      st (64);
      st (65);
      barrier;

      /* 12  */
      timestamps[i][22] = __builtin_ia32_rdtsc ();
      pf (66);
      pf (67);
      pf (68);
      pf (69);
      pf (70);
      pf (71);
      pf (72);
      pf (73);
      pf (74);
      pf (75);
      pf (76);
      pf (77);
      timestamps[i][23] = __builtin_ia32_rdtsc ();
      st (66);
      st (67);
      st (68);
      st (69);
      st (70);
      st (71);
      st (72);
      st (73);
      st (74);
      st (75);
      st (76);
      st (77);
      barrier;

      /* 13  */
      timestamps[i][24] = __builtin_ia32_rdtsc ();
      pf (78);
      pf (79);
      pf (80);
      pf (81);
      pf (82);
      pf (83);
      pf (84);
      pf (85);
      pf (86);
      pf (87);
      pf (88);
      pf (89);
      pf (90);
      timestamps[i][25] = __builtin_ia32_rdtsc ();
      st (78);
      st (79);
      st (80);
      st (81);
      st (82);
      st (83);
      st (84);
      st (85);
      st (86);
      st (87);
      st (88);
      st (89);
      st (90);
      barrier;

      /* 14  */
      timestamps[i][26] = __builtin_ia32_rdtsc ();
      pf (91);
      pf (92);
      pf (93);
      pf (94);
      pf (95);
      pf (96);
      pf (97);
      pf (98);
      pf (99);
      pf (100);
      pf (101);
      pf (102);
      pf (103);
      pf (104);
      timestamps[i][27] = __builtin_ia32_rdtsc ();
      st (91);
      st (92);
      st (93);
      st (94);
      st (95);
      st (96);
      st (97);
      st (98);
      st (99);
      st (100);
      st (101);
      st (102);
      st (103);
      st (104);
      barrier;

      /* 15  */
      timestamps[i][28] = __builtin_ia32_rdtsc ();
      pf (105);
      pf (106);
      pf (107);
      pf (108);
      pf (109);
      pf (110);
      pf (111);
      pf (112);
      pf (113);
      pf (114);
      pf (115);
      pf (116);
      pf (117);
      pf (118);
      pf (119);
      timestamps[i][29] = __builtin_ia32_rdtsc ();
      st (105);
      st (106);
      st (107);
      st (108);
      st (109);
      st (110);
      st (111);
      st (112);
      st (113);
      st (114);
      st (115);
      st (116);
      st (117);
      st (118);
      st (119);
      barrier;

      /* 16 */
      timestamps[i][30] = __builtin_ia32_rdtsc ();
      pf (120);
      pf (121);
      pf (122);
      pf (123);
      pf (124);
      pf (125);
      pf (126);
      pf (127);
      pf (128);
      pf (129);
      pf (130);
      pf (131);
      pf (132);
      pf (133);
      pf (134);
      pf (135);
      timestamps[i][31] = __builtin_ia32_rdtsc ();
      st (120);
      st (121);
      st (122);
      st (123);
      st (124);
      st (125);
      st (126);
      st (127);
      st (128);
      st (129);
      st (130);
      st (131);
      st (132);
      st (133);
      st (134);
      st (135);
      barrier;

      /* 17 */
      timestamps[i][32] = __builtin_ia32_rdtsc ();
      pf (136);
      pf (137);
      pf (138);
      pf (139);
      pf (140);
      pf (141);
      pf (142);
      pf (143);
      pf (144);
      pf (145);
      pf (146);
      pf (147);
      pf (148);
      pf (149);
      pf (150);
      pf (151);
      pf (152);
      timestamps[i][33] = __builtin_ia32_rdtsc ();
      st (136);
      st (137);
      st (138);
      st (139);
      st (140);
      st (141);
      st (142);
      st (143);
      st (144);
      st (145);
      st (146);
      st (147);
      st (148);
      st (149);
      st (150);
      st (151);
      st (152);
      barrier;

      /* 18 */
      timestamps[i][34] = __builtin_ia32_rdtsc ();
      pf (153);
      pf (154);
      pf (155);
      pf (156);
      pf (157);
      pf (158);
      pf (159);
      pf (160);
      pf (161);
      pf (162);
      pf (163);
      pf (164);
      pf (165);
      pf (166);
      pf (167);
      pf (168);
      pf (169);
      pf (170);
      timestamps[i][35] = __builtin_ia32_rdtsc ();
      st (153);
      st (154);
      st (155);
      st (156);
      st (157);
      st (158);
      st (159);
      st (160);
      st (161);
      st (162);
      st (163);
      st (164);
      st (165);
      st (166);
      st (167);
      st (168);
      st (169);
      st (170);
      barrier;
    }

  if (verbose)
    {
      for (i = 0; i < vec_len (offsets); i++)
        vlib_cli_output (vm, "%16llx", offsets[i]);
    }

  for (i = 0; i < niter; i++)
    {
      for (j = 0; j < vec_len (timestamps[0]); j += 2)
	{
	  u64 delta;

	  delta = timestamps[i][j + 1] - timestamps[i][j];
	  deltas[j >> 1] += delta;
	}
    }

  for (i = 0; i < vec_len (deltas); i++)
    {
      int npref = i + 1;
      vlib_cli_output (vm, "%d prefetches in %.2f clocks",
		       npref, (f64) (deltas[i]) / (f64) niter);
    }

  munmap (baseva, size);
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (test_lsu, static) =
{
  .path = "test lsu",
  .short_help = "test lsu [niter NN]",
  .function = test_lsu_command_fn,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
