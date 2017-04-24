/*
 *------------------------------------------------------------------
 * lex.h - definitions for the api generator's lexical
 * analyzer.
 *
 * Copyright (c) 1996-2009 Cisco and/or its affiliates.
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

#ifndef _LEX_H_
#define _LEX_H_ 1

extern int yylex (void);
extern void yyerror (char *);
extern int yyparse (void);
extern void autoreply (void *);

#ifndef YYSTYPE
#define YYSTYPE void *
#endif

#include "tools/vppapigen/gram.h"

enum lex_state {
    START_STATE = 1,
    NAME_STATE,
    NUMBER_STATE,
    C_COMMENT_STATE,
    CPP_COMMENT_STATE,
    STRING_STATE,
    HELPER_STATE,
    LINE_PRAGMA_STATE,
};

#define MAXNAME 64000

extern unsigned long input_crc;
extern unsigned long message_crc;

#endif /* _LEX_H_ */
