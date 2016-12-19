/* (X,Y) coordinates. */

/*
  Copyright (c) 2008 Eliot Dresselhaus

  Permission is hereby granted, free of charge, to any person obtaining
  a copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to
  permit persons to whom the Software is furnished to do so, subject to
  the following conditions:

  The above copyright notice and this permission notice shall be
  included in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#ifndef included_clib_xy_h
#define included_clib_xy_h

#include <vppinfra/types.h>

/* Basic definitions: coordinates and points. */
typedef double xy_float_t;
typedef __complex__ double xy_t;
typedef __complex__ int ixy_t;

typedef __complex__ char i8xy_t;
typedef __complex__ short i16xy_t;
typedef __complex__ int i32xy_t;

/* X/Y components of a point: can be used as either rvalue/lvalue. */
#define xy_x(x) __real__ (x)
#define xy_y(x) __imag__ (x)

/* Unit vectors in x/y directions. */
#define xy_x_unit_vector (1)
#define xy_y_unit_vector (1I)

#endif /* included_clib_xy_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
