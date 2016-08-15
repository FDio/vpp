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
 * Imported into CLIB by Eliot Dresselhaus from:
 *
 *  This file is part of
 *	MakeIndex - A formatter and format independent index processor
 *
 *  This file is public domain software donated by
 *  Nelson Beebe (beebe@science.utah.edu).
 *
 *  modifications copyright (c) 2003 Cisco Systems, Inc.
 */

#include <vppinfra/clib.h>

/*
 * qsort.c: Our own version of the system qsort routine which is faster by an
 * average of 25%, with lows and highs of 10% and 50%. The THRESHold below is
 * the insertion sort threshold, and has been adjusted for records of size 48
 * bytes. The MTHREShold is where we stop finding a better median.
 */

#define THRESH  4		/* threshold for insertion */
#define MTHRESH 6		/* threshold for median */

typedef struct
{
  word qsz;			/* size of each record */
  word thresh;			/* THRESHold in chars */
  word mthresh;			/* MTHRESHold in chars */
  int (*qcmp) (const void *, const void *);	/* the comparison routine */
} qst_t;

static void qst (qst_t * q, char *base, char *max);

/*
 * qqsort: First, set up some global parameters for qst to share.
 * Then, quicksort with qst(), and then a cleanup insertion sort ourselves.
 * Sound simple?  It's not...
 */

void
qsort (void *base, uword n, uword size,
       int (*compar) (const void *, const void *))
{
  char *i;
  char *j;
  char *lo;
  char *hi;
  char *min;
  char c;
  char *max;
  qst_t _q, *q = &_q;

  if (n <= 1)
    return;

  q->qsz = size;
  q->qcmp = compar;
  q->thresh = q->qsz * THRESH;
  q->mthresh = q->qsz * MTHRESH;
  max = base + n * q->qsz;
  if (n >= THRESH)
    {
      qst (q, base, max);
      hi = base + q->thresh;
    }
  else
    {
      hi = max;
    }
  /*
   * First put smallest element, which must be in the first THRESH, in the
   * first position as a sentinel.  This is done just by searching the
   * first THRESH elements (or the first n if n < THRESH), finding the min,
   * and swapping it into the first position.
   */
  for (j = lo = base; (lo += q->qsz) < hi;)
    {
      if ((*compar) (j, lo) > 0)
	j = lo;
    }
  if (j != base)
    {				/* swap j into place */
      for (i = base, hi = base + q->qsz; i < hi;)
	{
	  c = *j;
	  *j++ = *i;
	  *i++ = c;
	}
    }
  /*
   * With our sentinel in place, we now run the following hyper-fast
   * insertion sort. For each remaining element, min, from [1] to [n-1],
   * set hi to the index of the element AFTER which this one goes. Then, do
   * the standard insertion sort shift on a character at a time basis for
   * each element in the frob.
   */
  for (min = base; (hi = min += q->qsz) < max;)
    {
      while ((*q->qcmp) (hi -= q->qsz, min) > 0);
      if ((hi += q->qsz) != min)
	{
	  for (lo = min + q->qsz; --lo >= min;)
	    {
	      c = *lo;
	      for (i = j = lo; (j -= q->qsz) >= hi; i = j)
		*i = *j;
	      *i = c;
	    }
	}
    }
}



/*
 * qst: Do a quicksort.  First, find the median element, and put that one in
 * the first place as the discriminator.  (This "median" is just the median
 * of the first, last and middle elements).  (Using this median instead of
 * the first element is a big win). Then, the usual partitioning/swapping,
 * followed by moving the discriminator into the right place.  Then, figure
 * out the sizes of the two partions, do the smaller one recursively and the
 * larger one via a repeat of this code.  Stopping when there are less than
 * THRESH elements in a partition and cleaning up with an insertion sort (in
 * our caller) is a huge win. All data swaps are done in-line, which is
 * space-losing but time-saving. (And there are only three places where this
 * is done).
 */

static void
qst (qst_t * q, char *base, char *max)
{
  char *i;
  char *j;
  char *jj;
  char *mid;
  int ii;
  char c;
  char *tmp;
  int lo;
  int hi;
  int qsz = q->qsz;

  lo = (int) (max - base);	/* number of elements as chars */
  do
    {
      /*
       * At the top here, lo is the number of characters of elements in the
       * current partition.  (Which should be max - base). Find the median
       * of the first, last, and middle element and make that the middle
       * element.  Set j to largest of first and middle.  If max is larger
       * than that guy, then it's that guy, else compare max with loser of
       * first and take larger.  Things are set up to prefer the middle,
       * then the first in case of ties.
       */
      mid = i = base + qsz * ((unsigned) (lo / qsz) >> 1);
      if (lo >= q->mthresh)
	{
	  j = ((*q->qcmp) ((jj = base), i) > 0 ? jj : i);
	  if ((*q->qcmp) (j, (tmp = max - qsz)) > 0)
	    {
	      /* switch to first loser */
	      j = (j == jj ? i : jj);
	      if ((*q->qcmp) (j, tmp) < 0)
		j = tmp;
	    }
	  if (j != i)
	    {
	      ii = qsz;
	      do
		{
		  c = *i;
		  *i++ = *j;
		  *j++ = c;
		}
	      while (--ii);
	    }
	}
      /* Semi-standard quicksort partitioning/swapping */
      for (i = base, j = max - qsz;;)
	{
	  while (i < mid && (*q->qcmp) (i, mid) <= 0)
	    i += qsz;
	  while (j > mid)
	    {
	      if ((*q->qcmp) (mid, j) <= 0)
		{
		  j -= qsz;
		  continue;
		}
	      tmp = i + qsz;	/* value of i after swap */
	      if (i == mid)
		{		/* j <-> mid, new mid is j */
		  mid = jj = j;
		}
	      else
		{		/* i <-> j */
		  jj = j;
		  j -= qsz;
		}
	      goto swap;
	    }
	  if (i == mid)
	    {
	      break;
	    }
	  else
	    {			/* i <-> mid, new mid is i */
	      jj = mid;
	      tmp = mid = i;	/* value of i after swap */
	      j -= qsz;
	    }
	swap:
	  ii = qsz;
	  do
	    {
	      c = *i;
	      *i++ = *jj;
	      *jj++ = c;
	    }
	  while (--ii);
	  i = tmp;
	}
      /*
       * Look at sizes of the two partitions, do the smaller one first by
       * recursion, then do the larger one by making sure lo is its size,
       * base and max are update correctly, and branching back. But only
       * repeat (recursively or by branching) if the partition is of at
       * least size THRESH.
       */
      i = (j = mid) + qsz;
      if ((lo = (int) (j - base)) <= (hi = (int) (max - i)))
	{
	  if (lo >= q->thresh)
	    qst (q, base, j);
	  base = i;
	  lo = hi;
	}
      else
	{
	  if (hi >= q->thresh)
	    qst (q, i, max);
	  max = j;
	}
    }
  while (lo >= q->thresh);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
