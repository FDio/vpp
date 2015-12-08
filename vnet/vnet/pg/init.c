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
/*
 * pg_init.c: VLIB packet generator
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <vlib/vlib.h>
#include <vnet/pg/pg.h>

/* Global main structure. */
pg_main_t pg_main;

static clib_error_t * pg_init (vlib_main_t * vm)
{
  clib_error_t * error;
  pg_main_t * pg = &pg_main;
  int i, j;

  pg->vlib_main = vm;

  if ((error = vlib_call_init_function (vm, vnet_main_init)))
    goto done;

  if ((error = vlib_call_init_function (vm, pg_cli_init)))
    goto done;

  /* Create/free interfaces so that they exist and can be
     used as a destination interface for streams.  Also, create
     a fixed number of pg interfaces so that interface numbering can
     be made to be deterministic (at least if <= 4 streams are ever used). */
  for (i = 0; i < 4; i++)
    {
      j = pg_interface_find_free (pg, i);
      ASSERT (j == i);
    }

  /* Free interfaces. */
  for (i = j; i >= 0; i--)
    vec_add1 (pg->free_interfaces, i);

 done:
  return error;
}

VLIB_INIT_FUNCTION (pg_init);
