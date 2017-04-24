/*
 *------------------------------------------------------------------
 * node.h - definitions for an API generator
 *
 * Copyright (c) 2004-2009 Cisco and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef _node_h_
#define _node_h_

/*
 * Global prototypes
 */

char *sxerox (const char *s);

enum node_subclass {  /* WARNING: indices must match the vft... */
    NODE_ILLEGAL=0,
    NODE_U8,
    NODE_U16,
    NODE_U32,
    NODE_U64,
    NODE_I8,
    NODE_I16,
    NODE_I32,
    NODE_I64,
    NODE_F64,
    NODE_PACKED,
    NODE_DEFINE,
    NODE_UNION,
    NODE_SCALAR,
    NODE_VECTOR,
    NODE_COMPLEX,
    NODE_NOVERSION,
    NODE_UWORD,
    NODE_N_TYPES,  /* number of node types with VFT's */

    /* pseudo-node(s) used in the lexer keyword table, but
       NOT in need of a VFT... */
    NODE_TYPEONLY,
    NODE_MANUAL_PRINT,
    NODE_MANUAL_ENDIAN,
    NODE_DONT_TRACE,
    NODE_AUTOREPLY,
};

enum passid {
    TYPEDEF_PASS=1,
    UNION_DEF_PASS,
    ENDIANFUN_PASS,
    PRINTFUN_PASS,
    PYTHON_PASS,
    JSON_PASS,
};

extern void *make_node (enum node_subclass type);

typedef struct node_ {
    enum node_subclass type;
    struct node_ *peer;
    struct node_ *deeper;
    int flags;
    void *data[4];
} node_t;

/* To shut up gcc-4.2.x warnings */
#define CDATA0 ((char *)(this->data[0]))
#define IDATA1 ((int)(uword)(this->data[1]))
#define CDATA2 ((char *)(this->data[2]))
#define CDATA3 ((char *)(this->data[3]))

#define NODE_FLAG_MANUAL_PRINT (1<<0)
#define NODE_FLAG_MANUAL_ENDIAN (1<<1)
#define NODE_FLAG_TYPEONLY (1<<3)
#define NODE_FLAG_DONT_TRACE (1<<4)
#define NODE_FLAG_AUTOREPLY (1<<5)

typedef struct node_vft_ {
    void (*print)(struct node_ *);
    void (*generate)(struct node_ *, enum passid id, FILE *ofp);
    char *endian_converter;
} node_vft_t;    

#endif /* _node_h */
