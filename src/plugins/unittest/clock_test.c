/*
 * Copyright (c) 2022 Cisco
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
#include <time.h>
#include <sys/auxv.h>
#include <string.h>
#include <elf.h>

#define ROUNDS 10000000

#define foreach_clocks                                                        \
  _ (CLOCK_REALTIME)                                                          \
  _ (CLOCK_MONOTONIC)                                                         \
  _ (CLOCK_MONOTONIC_COARSE)                                                  \
  _ (CLOCK_MONOTONIC_RAW)

typedef int (*clock_gettime__) (clockid_t, struct timespec *);

static const void *
vdso_sym (const char *const name)
{
  const u8 *vdso_addr = (void *) getauxval (AT_SYSINFO_EHDR);
  const Elf64_Ehdr *elf_header = (void *) vdso_addr;
  const Elf64_Shdr *section_header =
    (void *) (vdso_addr + elf_header->e_shoff);
  const char *dynstr = 0;
  const void *ret = 0;

  for (int i = 0; i < elf_header->e_shnum; i++)
    {
      const Elf64_Shdr *s = &section_header[i];
      const Elf64_Shdr *ss = &section_header[elf_header->e_shstrndx];
      const char *n = (void *) (vdso_addr + ss->sh_offset + s->sh_name);
      if (strcmp (n, ".dynstr") == 0)
	{
	  dynstr = (void *) (vdso_addr + s->sh_offset);
	  break;
	}
    }

  for (int i = 0; i < elf_header->e_shnum; i++)
    {
      const Elf64_Shdr *s = &section_header[i];
      const Elf64_Shdr *ss = &section_header[elf_header->e_shstrndx];
      const char *n = (void *) (vdso_addr + ss->sh_offset + s->sh_name);
      if (strcmp (n, ".dynsym") == 0)
	{
	  for (int si = 0; si < (s->sh_size / s->sh_entsize); si++)
	    {
	      const Elf64_Sym *sym =
		&((Elf64_Sym *) (vdso_addr + s->sh_offset))[si];
	      const char *n = dynstr + sym->st_name;
	      if (strcmp (n, name) == 0)
		{
		  ret = vdso_addr + sym->st_value;
		  goto out;
		}
	    }
	}
    }

out:
  return ret;
}

static clib_error_t *
test_clock_vlib (vlib_main_t *vm)
{
  f64 start, stop;

  /* warmup */
  for (int i = 0; i < 100; i++)
    {
      vlib_time_now (vm);
    }

  CLIB_COMPILER_BARRIER ();

  start = vlib_time_now (vm);

  CLIB_COMPILER_BARRIER ();

  for (int i = 0; i < ROUNDS; i++)
    {
      f64 now = vlib_time_now (vm);
      asm volatile("" ::"r"(now) : "memory");
    }

  CLIB_COMPILER_BARRIER ();

  stop = vlib_time_now (vm);

  CLIB_COMPILER_BARRIER ();

  stop -= start;
  vlib_cli_output (vm, "vlib_time_now(): %.6g s (%.2g calls/s)\n", stop,
		   ROUNDS / stop);
  return 0;
}

static clib_error_t *
test_clock_os (vlib_main_t *vm, const clock_gettime__ cgt, clockid_t clkid,
	       const char *clkname)
{
  int err = 0;
  f64 start, stop, res;
  struct timespec ts;

  /* warmup */
  for (int i = 0; i < 100; i++)
    if (cgt (clkid, &ts))
      return clib_error_return_unix (
	0, "clock_gettime(%s) failed, skipping test", clkname);

  CLIB_COMPILER_BARRIER ();

  start = vlib_time_now (vm);

  CLIB_COMPILER_BARRIER ();

  for (int i = 0; i < ROUNDS; i++)
    {
      err |= cgt (clkid, &ts);
      asm volatile("" ::"r"(&ts) : "memory");
    }

  CLIB_COMPILER_BARRIER ();

  stop = vlib_time_now (vm);

  CLIB_COMPILER_BARRIER ();

  if (err)
    return clib_error_return_unix (
      0, "clock_gettime(%s) failed, skipping test", clkname);

  if (clock_getres (clkid, &ts))
    res = 0x1.fffffffffffffp-1; /* NaN */
  else
    res = ts.tv_sec * 1e9 + ts.tv_nsec;

  stop -= start;
  vlib_cli_output (vm, "%s: %.6g s (%.2g calls/s) - resolution %g ns", clkname,
		   stop, ROUNDS / stop, res);
  return 0;
}

static clib_error_t *
test_clock_command_fn (vlib_main_t *vm, unformat_input_t *input,
		       vlib_cli_command_t *cmd)
{
  clib_error_t *err;

  test_clock_vlib (vm);

  const clock_gettime__ cgt = vdso_sym ("__vdso_clock_gettime");
#define _(clkid)                                                              \
  if ((err = test_clock_os (vm, cgt, clkid, #clkid)))                         \
    clib_error_report (err);
  foreach_clocks
#undef _
    return 0;
}

VLIB_CLI_COMMAND (test_pool_command, static) = {
  .path = "test clock",
  .short_help = "OS clock_gettime() perf test",
  .function = test_clock_command_fn,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
