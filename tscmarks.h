#include <stdio.h>

#ifndef TSC_CLOCK_MHZ
#define TSC_CLOCK_MHZ 2700
#endif

#define TSC_N_MARKS 256

typedef struct
{
  unsigned long long last_print __attribute__ ((aligned (64)));
  unsigned long long marks[TSC_N_MARKS];
  char *mark_names[TSC_N_MARKS];
  unsigned int next;
} tsc_mark_data_t;

static __thread tsc_mark_data_t __tsc_mark_data = { 0 };

static inline void __attribute__ ((__always_inline__)) tsc_mark (char *name)
{
  tsc_mark_data_t *d = &__tsc_mark_data;
  if (name)
    d->mark_names[d->next] = name;
  d->marks[d->next++] = __builtin_ia32_rdtsc ();
}

static inline void __attribute__ ((__always_inline__))
tsc_print_one (int a, int b, int ops, int is_sum)
{
  tsc_mark_data_t *d = &__tsc_mark_data;
  unsigned long long delta = d->marks[b] - d->marks[a];
  printf ("T%u - T%u: %9llu clks", a, b, delta);
  if (ops)
    printf (" (%7.3f clks/op)", (double) delta / ops);
  if (!is_sum && d->mark_names[a])
    printf (" [ %s ]", d->mark_names[a]);
  printf ("\n");
}

static inline int __attribute__ ((__always_inline__))
tsc_print (double interval, unsigned int ops)
{
  tsc_mark_data_t *d = &__tsc_mark_data;
  unsigned long long t;
  unsigned int i = 1;
  unsigned int cpuid;
  unsigned int count = d->next;

  t = __builtin_ia32_rdtscp (&cpuid);
  d->next = 0;
  if (d->last_print + interval * TSC_CLOCK_MHZ * 1000000 > t)
    return 0;
  d->last_print = t;

  printf ("operations %u, cpu %u\n", ops, cpuid);
  for (i = 1; i < count; i++)
    tsc_print_one (i - 1, i, ops, 0);
  tsc_print_one (0, count - 1, ops, 1);
  for (i = 0; i < count; i++)
    d->marks[i] = 0;
  return 1;
}
