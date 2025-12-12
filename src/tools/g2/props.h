/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 1997-2016 Cisco and/or its affiliates.
 */

extern char *getprop (char *name);
extern char *getprop_default (char *name, char *def);
extern void addprop (char *name, char *value);
extern int readprops (char *filename);
extern int writeprops (char *filename);
