%{
#include "tools/vppapigen/lex.h"
#include "tools/vppapigen/gram.h" 
#define YY_DECL int yylex_1 (void)
#define YY_NO_UNPUT /* erase compile warning */
#define YY_NO_INPUT /* erase compile warning */
extern void set_name_buf(char*);
extern int name_check (const char *s, YYSTYPE *token_value);
extern int lex_input_char(FILE* ifp); 
#define YY_INPUT(buf,result,max_size) \
    { \
    int c = lex_input_char(yyin); \
    result = (c == EOF) ? YY_NULL : (buf[0] = c, 1); \
    }
   
%}
%x c_comment
%x cpp_comment
%option noyywrap
U8 "u8"
U16 "u16"
U32 "u32"
U64 "u64"
I8  "i8"
I16 "i16"
I32 "i32"
I64 "i64"
F64 "f64"
UWORD "uword"
PRIMARY_TYPE {U8}|{U16}|{U32}|{U64}|{I8}|{I16}|{I32}|{I64}|{F64}|{UWORD}

%%

"/*"         BEGIN(c_comment);
<c_comment>"*/"        BEGIN(INITIAL);
<c_comment>.|\n  /* eat any char in comment */
"//"         BEGIN(cpp_comment);
<cpp_comment>"\n" BEGIN(INITIAL);
<cpp_comment>.|\n  /* eat any char in comment */

"{"          {return LCURLY;}
"}"          {return RCURLY;}
";"          {return SEMI;}
"["          {return LBRACK;}
"]"          {return RBRACK;}
"."          {return DOT;}
"define"        |
"manual_endian" |
"manual_print"  |
"noversion"     |
"typeonly"      |
"dont_trace"    |
"autoreply"     |
"union"         |
"packed"        |
{PRIMARY_TYPE}  |
"vl_api_version" |
[[:alpha:]_][[:alnum:]_]* {set_name_buf(yytext) ;return name_check(yytext,&yylval);}
[0-9]+ {set_name_buf(yytext); yylval=(void*)atol(yytext);return (NUMBER);}

<<EOF>> {return EOF;}
.|\n  /* eat any other char*/


