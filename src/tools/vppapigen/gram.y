%{
/*
 * gram.y - message definition language
 *
 * Copyright (c) 2009 Cisco and/or its affiliates.
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

extern void yyerror (char *s);
extern int yylex (void);
    
#define YYSTYPE void *
    
void generate (YYSTYPE);
 YYSTYPE add_slist(YYSTYPE, YYSTYPE);
 YYSTYPE add_define(YYSTYPE, YYSTYPE);
 YYSTYPE suppress_version(void);
 YYSTYPE add_defbody(YYSTYPE, YYSTYPE);
 YYSTYPE add_primtype(YYSTYPE, YYSTYPE, YYSTYPE);
 YYSTYPE add_complex(YYSTYPE, YYSTYPE);
 YYSTYPE add_union(YYSTYPE, YYSTYPE);
 YYSTYPE add_scalar_vbl(YYSTYPE);
 YYSTYPE add_vector_vbl(YYSTYPE, YYSTYPE);
 YYSTYPE add_variable_length_vector_vbl(YYSTYPE, YYSTYPE);
 YYSTYPE set_flags(YYSTYPE, YYSTYPE);
 YYSTYPE add_version(YYSTYPE, YYSTYPE, YYSTYPE);
%}

%token NAME RPAR LPAR SEMI LBRACK RBRACK NUMBER PRIMTYPE BARF
%token TPACKED DEFINE LCURLY RCURLY STRING UNION
%token HELPER_STRING COMMA DOT VL_API_VERSION
%token NOVERSION MANUAL_PRINT MANUAL_ENDIAN TYPEONLY DONT_TRACE AUTOREPLY

%%

pgm:	  slist                 {generate ($1);}
          ;

slist:	  slist stmt            {$$ = add_slist ($1, $2);}
        | stmt                  {$$ = $1;}
          ;

stmt:     flist defn            {$$ = set_flags($1, $2);}
        | defn                  {$$ = $1;}
        | api_version           {$$ = $1;}
          ;

flist:    flist flag            {$$ = (YYSTYPE)(unsigned long)
                                     ((unsigned long) $1 
                                    | (unsigned long) $2);}
        | flag                  {$$ = $1;}
          ;

flag:   
          MANUAL_PRINT          {$$ = $1;}
        | MANUAL_ENDIAN         {$$ = $1;}
        | DONT_TRACE            {$$ = $1;}
        | TYPEONLY              {$$ = $1;}
        | AUTOREPLY             {$$ = $1;}
          ;

defn:     DEFINE NAME LCURLY defbody RCURLY SEMI 
                                {$$ = add_define($2, $4);}

        | NOVERSION SEMI
                                {$$ = suppress_version();}
          ;

defbody:  defbody onedef        {$$ = add_defbody($1, $2);}
        | onedef                {$$ = $1;}
          ;

onedef:   PRIMTYPE vbl SEMI      {$$ = add_primtype($1, $2, 0);}
        | TPACKED PRIMTYPE vbl SEMI {$$ = add_primtype($1, $2, $3);}
        | NAME vbl SEMI          {$$ = add_complex($1, $2);}
        | UNION NAME LCURLY defbody RCURLY SEMI 
                                 {$$ = add_union($2, $4);}
          ;

vbl:      NAME                      {$$ = add_scalar_vbl($1);}
        | NAME LBRACK NUMBER RBRACK {$$ = add_vector_vbl($1, $3);}
        | NAME LBRACK NAME RBRACK {$$ = add_variable_length_vector_vbl($1, $3);}
          ;

api_version:  VL_API_VERSION NUMBER DOT NUMBER DOT NUMBER 
                                    {$$ = add_version ($2, $4, $6);}
