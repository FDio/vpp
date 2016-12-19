/* 
 *------------------------------------------------------------------
 * Copyright (c) 2006-2016 Cisco and/or its affiliates.
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

/* see "Numerical Recipies in C, 2nd ed." p 665 */

#include <stdio.h>
#include <math.h>

/*
 * linreg
 * Linear regression of (xi, yi), returns parameters for least-squares
 * fit y = a + bx.  Also, compute Pearson's R.
 */
void linreg (double *x, double *y, int nitems, double *a, double *b,
             double *minp, double *maxp, double *meanp, double *r)
{
    double sx = 0.0;
    double sy = 0.0;
    double st2 = 0.0;
    double min = y[0];
    double max = 0.0;
    double ss, meanx, meany, t;
    double errx, erry, prodsum, sqerrx, sqerry;
    int i;

    *b = 0.0;
    
    for (i = 0; i < nitems; i++) {
        sx += x[i];
        sy += y[i];
        if (y[i] < min)
            min = y[i];
        if (y[i] > max)
            max = y[i];
    }
    ss = nitems;
    meanx = sx / ss;
    meany = *meanp = sy / ss;
    *minp = min;
    *maxp = max;

    for (i = 0; i < nitems; i++) {
        t = x[i] - meanx;
        st2 += t*t;
        *b += t*y[i];
    }

    *b /= st2;
    *a = (sy-sx*(*b))/ss;

    prodsum = 0.0;
    sqerrx = 0.0;
    sqerry = 0.0;

    /* Compute numerator of Pearson's R */
    for (i = 0; i < nitems; i++) {
        errx = x[i] - meanx;
        erry = y[i] - meany;
        prodsum += errx * erry;
        sqerrx += errx*errx;
        sqerry += erry*erry;
    }

    *r = prodsum / (sqrt(sqerrx)*sqrt(sqerry));
}
