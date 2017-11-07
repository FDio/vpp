/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

 */

#ifndef __included_warnings_h__
#define __included_warnings_h__

/* Macros to check compiler version */
#if defined(__GNUC__)
#define COMPILER_VERSION_GTE(major, minor) \
  (__GNUC__ > (major) || (__GNUC__ == (major) && __GNUC_MINOR__ >= (minor)))
#elif defined(__clang__)
#define COMPILER_VERSION_GTE(major, minor) \
  (__clang_major__ > (major) ||            \
   (__clang_major__ == (major) && __clang_minor__ >= (minor)))
#else /* disable all warning customization for all other compilers */
#define COMPILER_VERSION_GTE(maj, min) 0
#endif

/* '#' needs to preceed a macro parameter */
#define WARN_TOSTR(x) #x

/*
 * Macros to toggle off/on warnings
 *
 * Start by silenging pragma warnings so that we can explicitely silence
 * a warning introduced on some compiler version and not get a warning on older
 * versions of that same compiler.
 *
 * gcc corresponding warnign is "Wpargma"
 * clang corresponding warnign is "Wunknown-warning-option"
 *
 * For example, Wtautological-compare is introduced in gcc-6 and this would
 * trigger a Wpargma warning on gcc-5.
 *
 * Example usage to disable -Wtautological-compare warning:
 *   WARN_OFF(tautological-compare)
 *   if (...) {
 *   WARN_ON(tautological-compare)
 *     ; // conditional code
 *   }
 */
#if defined(__GNUC__) && COMPILER_VERSION_GTE(4, 6)
/*
 * GCC option to locally ignore warning was introduced in gcc-4.6
 * gcc.gnu.org/gcc-4.6/changes.html
 */
#define WARN_PRAGMA(x) _Pragma (WARN_TOSTR (GCC diagnostic x))
#define WARN_OFF(x)                                    \
  WARN_PRAGMA (push) WARN_PRAGMA (ignored "-Wpragmas") \
  WARN_PRAGMA (push) WARN_PRAGMA (ignored WARN_TOSTR (-W##x))
#define WARN_ON(x)  \
  WARN_PRAGMA (pop) \
  WARN_PRAGMA (pop)

#elif defined(__clang__) && COMPILER_VERSION_GTE(3, 3)
/*
 * clang option to locally ignore warning was introduced in clang-3.3
 * releases.llvm.org/3.3/tools/clang/docs/UsersManual.html#controlling-diagnostics-via-pragmas
 */
#define WARN_PRAGMA(x) _Pragma (WARN_TOSTR (clang diagnostic x))
#define WARN_OFF(x)                                                   \
  WARN_PRAGMA (push) WARN_PRAGMA (ignored "-Wunknown-warning-option") \
  WARN_PRAGMA (push) WARN_PRAGMA (ignored WARN_TOSTR (-W##x))
#define WARN_ON(x)  \
  WARN_PRAGMA (pop) \
  WARN_PRAGMA (pop)
#else
/* Ignore WARN_* instruction for all other compilers */
#define WARN_OFF(x)
#define WARN_ON(x)
#endif

/*
 * Clang supports a wider range of warnings than gcc.
 * Use those specific macros for the warnings that are only supported by clang
 */
#ifdef __clang__
#define WARN_OFF_CLANG(x) WARN_OFF (x)
#define WARN_ON_CLANG(x) WARN_ON (x)
#else
#define WARN_OFF_CLANG(x)
#define WARN_ON_CLANG(x)
#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
#endif /* __included_warnings_h__ */
