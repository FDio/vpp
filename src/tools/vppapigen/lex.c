/* 
 *------------------------------------------------------------------
 * lex.c - API generator lexical analyzer
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

#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "lex.h"
#include "node.h"
#include "tools/vppapigen/gram.h"
#include <vppinfra/clib.h>
#include <vppinfra/fifo.h>
#include <vppinfra/format.h>

FILE *ifp, *ofp, *pythonfp, *jsonfp;
char *vlib_app_name = "vpp";
int dump_tree;
time_t starttime;
char *input_filename;
char *current_filename;
int current_filename_allocated;
unsigned long input_crc;
unsigned long message_crc;
int yydebug;
char *push_input_fifo;
char saved_ungetc_char;
char have_ungetc_char;

/*
 * lexer variable definitions 
 */

static const char *version = "0.1";
static int the_lexer_linenumber = 1;
static enum lex_state the_lexer_state = START_STATE;

/*
 * private prototypes
 */
static void usage (char *);
static int name_check (const char *, YYSTYPE *);
static int name_compare (const char *, const char *);
extern int yydebug;
extern YYSTYPE yylval;

unsigned int crc32c_table[256] = { 
  0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,  
  0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,  
  0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,  
  0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,  
  0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,  
  0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,  
  0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,  
  0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,  
  0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,  
  0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,  
  0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,  
  0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,  
  0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,  
  0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,  
  0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,  
  0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,  
  0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,  
  0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,  
  0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,  
  0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,  
  0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,  
  0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,  
  0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,  
  0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,  
  0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,  
  0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,  
  0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,  
  0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,  
  0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,  
  0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,  
  0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,  
  0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,  
  0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,  
  0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,  
  0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,  
  0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,  
  0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,  
  0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,  
  0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,  
  0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,  
  0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,  
  0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,  
  0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,  
  0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,  
  0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,  
  0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,  
  0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,  
  0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,  
  0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,  
  0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,  
  0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,  
  0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,  
  0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,  
  0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,  
  0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,  
  0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,  
  0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,  
  0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,  
  0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,  
  0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,  
  0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,  
  0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,  
  0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,  
  0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351  
}; 

static inline unsigned long CRC8 (unsigned long crc,
                                  unsigned char d)
{
    return ((crc >> 8) ^ crc32c_table[(crc ^ d) & 0xFF]);
}
static inline unsigned long CRC16 (unsigned long crc,
                                   unsigned short d)
{
    crc = CRC8 (crc, d & 0xff);
    d = d >> 8;
    crc = CRC8 (crc, d & 0xff);
    return crc;
}


static unsigned long
crc_eliding_c_comments (const char *buf, unsigned long crc)
{
    const char *p;
    enum { cOTHER,              /*  */
           cSTRING,             /* "...    */
           cSBACKSLASH,         /* "...\   */
           cCHAR,               /* '...    */
           cCBACKSLASH,         /* '...\   */
           cSLASH,              /* /       */
           cSLASH_SLASH,        /* //...   */
           cSLASH_STAR,         /* / *...  */
           cSTAR                /* / *...* */
    } ss = cOTHER;

    for (p = buf; ;) {
        unsigned char c = *p++;

        switch (c) {
        case 0:
            switch (ss) {
            case cOTHER:
                return (crc);
            case cSTRING: case cSBACKSLASH:
            case cCHAR: case cCBACKSLASH:
            case cSLASH: case cSLASH_SLASH: case cSLASH_STAR: case cSTAR:
                fprintf (stderr, "Inopportune EOF: %s\n", buf);
                exit (1);
            }
            break;
        case '\"':
            switch (ss) {
            case cOTHER: ss = cSTRING; break; /* start string */
            case cSTRING: ss = cOTHER; break; /* end string */
            case cSBACKSLASH: ss = cSTRING; break;
            case cCHAR: break;
            case cCBACKSLASH: ss = cCHAR; break;
            case cSLASH: crc = CRC8 (crc, '/'); ss = cOTHER; break;
            case cSLASH_SLASH: continue; /* in comment */
            case cSLASH_STAR: continue; /* in comment */
            case cSTAR: ss = cSLASH_STAR; continue; /* in comment */
            }
            break;
        case '\\':
            switch (ss) {
            case cOTHER: break;
            case cSTRING: ss = cSBACKSLASH; break;
            case cSBACKSLASH: ss = cSTRING; break;
            case cCHAR: ss = cCBACKSLASH; break;
            case cCBACKSLASH: ss = cCHAR; break;
            case cSLASH: crc = CRC8 (crc, '/'); ; ss = cOTHER; break;
            case cSLASH_SLASH: continue; /* in comment */
            case cSLASH_STAR: continue; /* in comment */
            case cSTAR: ss = cSLASH_STAR; continue; /* in comment */
            }
            break;
        case '/':
            switch (ss) {
            case cOTHER: ss = cSLASH; continue; /* potential comment */
            case cSTRING: break;
            case cSBACKSLASH: ss = cSTRING; break;
            case cCHAR: break;
            case cCBACKSLASH: ss = cCHAR; break;
            case cSLASH: ss = cSLASH_SLASH; continue; /* start comment */
            case cSLASH_SLASH: continue; /* in comment */
            case cSLASH_STAR: continue; /* in comment */
            case cSTAR: ss = cOTHER; continue; /* end of comment */
            }
            break;
        case '*':
            switch (ss) {
            case cOTHER: break;
            case cSTRING: break;
            case cSBACKSLASH: ss = cSTRING; break;
            case cCHAR: break;
            case cCBACKSLASH: ss = cCHAR; break;
            case cSLASH: ss = cSLASH_STAR; continue; /* start comment */
            case cSLASH_SLASH: continue; /* in comment */
            case cSLASH_STAR: ss = cSTAR; continue; /* potential end */
            case cSTAR: continue; /* still potential end of comment */
            }
            break;
        case '\n': case '\r': case ' ': case '\t': case '\014':
            switch (ss) {
            case cOTHER: continue; /* ignore all whitespace */
            case cSTRING: break;
            case cSBACKSLASH: ss = cSTRING; break;
            case cCHAR: break;
            case cCBACKSLASH: ss = cCHAR; break;
            case cSLASH: c = '/'; ss = cOTHER; break;
            case cSLASH_SLASH:
                if (c == '\n' || c == '\r') ss = cOTHER; /* end comment */
                continue;
            case cSLASH_STAR: continue; /* in comment */
            case cSTAR: ss = cSLASH_STAR; continue; /* in comment */
            }
        default:
            switch (ss) {
            case cOTHER: break;
            case cSTRING: break;
            case cSBACKSLASH: ss = cSTRING; break;
            case cCHAR: break;
            case cCBACKSLASH: ss = cCHAR; break;
            case cSLASH: crc = CRC8 (crc, '/'); ss = cOTHER; break;
            case cSLASH_SLASH: continue; /* in comment */
            case cSLASH_STAR: continue; /* in comment */
            case cSTAR: ss = cSLASH_STAR; continue; /* in comment */
            }
        }
        crc = CRC8 (crc, c);
    }
}

/*
 * main 
 */
int main (int argc, char **argv)
{
    int curarg = 1;
    char *ofile=0;
    char *pythonfile=0;
    char *jsonfile=0;
    char *show_name=0;

    while (curarg < argc) {
        if (!strncmp (argv [curarg], "--verbose", 3)) {
            fprintf (stderr, "%s version %s\n", argv [0], version);
            curarg++;
            continue;
        }
        
        if (!strncmp (argv [curarg], "--yydebug", 3)) {
            yydebug = 1;
            curarg++;
            continue;
        }
        
        if (!strncmp (argv [curarg], "--dump", 3)) {
            dump_tree = 1;
            curarg++;
            continue;
        }
        
        if (!strncmp (argv[curarg], "--show-name", 3)) {
            curarg++;
            if (curarg < argc) {
                show_name = argv[curarg];
                curarg++;
                continue;
            } else {
                fprintf(stderr, "Missing filename after --show-name \n");
                exit(1);
            }
        }

        if (!strncmp (argv [curarg], "--input", 3)) {
            curarg++;
            if (curarg < argc) {
                input_filename = argv[curarg];
                if (!strcmp (argv [curarg], "-"))
                    ifp = stdin;
                else
                    ifp = fopen (argv [curarg], "r");
                if (ifp == NULL) {
                    fprintf (stderr, "Couldn't open input file %s\n", 
                             argv[curarg]);
                    exit (1);
                }
                curarg++;
            } else {
                fprintf(stderr, "Missing filename after --input\n");
                exit(1);
            }
            continue;
        }
        if (!strncmp (argv [curarg], "--output", 3)) {
            curarg++;
            if (curarg < argc) {
                ofp = fopen (argv[curarg], "w");
                if (ofp == NULL) {
                    fprintf (stderr, "Couldn't open output file %s\n", 
                         argv[curarg]);
                    exit (1);
                }
                ofile = argv[curarg];
                curarg++;
            } else {
                fprintf(stderr, "Missing filename after --output\n");
                exit(1);
            }
            continue;
        }
        if (!strncmp (argv [curarg], "--python", 8)) {
            curarg++;
            if (curarg < argc) {
	        if (!strcmp(argv[curarg], "-")) {
		    pythonfp = stdout;
		} else {
		    pythonfp = fopen(argv[curarg], "w");
		    pythonfile = argv[curarg];
		}
                if (pythonfp == NULL) {
                    fprintf (stderr, "Couldn't open python output file %s\n",
                         argv[curarg]);
                    exit (1);
                }
                curarg++;
            } else {
                fprintf(stderr, "Missing filename after --python\n");
                exit(1);
            }
            continue;
        }
        if (!strncmp (argv [curarg], "--json", 6)) {
            curarg++;
            if (curarg < argc) {
	        if (!strcmp(argv[curarg], "-")) {
		    jsonfp = stdout;
		} else {
		    jsonfp = fopen(argv[curarg], "w");
		    jsonfile = argv[curarg];
		}
                if (jsonfp == NULL) {
                    fprintf (stderr, "Couldn't open JSON output file %s\n",
                         argv[curarg]);
                    exit (1);
                }
                curarg++;
            } else {
                fprintf(stderr, "Missing filename after --json\n");
                exit(1);
            }
            continue;
        }
        if (!strncmp (argv [curarg], "--app", 4)) {
            curarg++;
            if (curarg < argc) {
                vlib_app_name = argv[curarg];
                curarg++;
            } else {
                fprintf(stderr, "Missing app name after --app\n");
                exit(1);
            }
            continue;
        }

        usage(argv[0]);
        exit (1);
    }
    if (ofp == NULL) {
        ofile = 0;
    }
    if (pythonfp == NULL) {
        pythonfile = 0;
    }
    if (jsonfp == NULL) {
        jsonfile = 0;
    }
    if (ifp == NULL) {
        fprintf(stderr, "No input file specified...\n");
        exit(1);
    }
    if (show_name) {
        input_filename = show_name;
    }

    starttime = time (0);

    if (yyparse() == 0) {
        fclose (ifp);
        curarg -= 2;
        if (ofile) {
            printf ("Output written to %s\n", ofile);
            fclose (ofp);
        }
        if (pythonfile) {
            printf ("Python bindings written to %s\n", pythonfile);
            fclose (pythonfp);
        }
        if (jsonfile) {
            printf ("JSON bindings written to %s\n", jsonfile);
            fclose (jsonfp);
        }
    }
    else {
        fclose (ifp);
        if (ofp)
            fclose (ofp);
        if (ofile) {
            printf ("Removing %s\n", ofile);
            unlink (ofile);
        }
        if (pythonfile) {
            printf ("Removing %s\n", pythonfile);
            unlink (pythonfile);
        }
        if (jsonfile) {
            printf ("Removing %s\n", jsonfile);
            unlink (jsonfile);
        }
        exit (1);
    }
    exit (0);
}

/*
 * usage
 */
static void usage (char *progname)
{
    fprintf (stderr, 
             "usage: %s --input <filename> [--output <filename>] "
	     "[--json <filename>] [--python <filename>]\n%s",
             progname,
             "          [--yydebug] [--dump-tree]\n");
    exit (1);
}

/*
 * yyerror 
 */
void yyerror (char *s)
{
    fprintf (stderr, "%s:%d %s\n", current_filename, the_lexer_linenumber, s);
}

static char namebuf [MAXNAME];

static inline char
getc_char (FILE *ifp)
{
    char rv;

    if (have_ungetc_char) {
        have_ungetc_char = 0;
        return saved_ungetc_char;
    }
        
    if (clib_fifo_elts (push_input_fifo)) {
        clib_fifo_sub1(push_input_fifo, rv);
        return (rv & 0x7f);
    }
    return ((char)(getc(ifp) & 0x7f));
}

u32 fe (char *fifo)
{
    return clib_fifo_elts (fifo);
}

static inline void
ungetc_char (char c, FILE *ifp)
{
    saved_ungetc_char = c;
    have_ungetc_char = 1;
}

void autoreply (void *np_arg)
{
    static u8 *s;
    node_t *np = (node_t *)np_arg;
    int i;

    vec_reset_length (s);

    s = format (0, " define %s_reply\n", (char *)(np->data[0]));
    s = format (s, "{\n");
    s = format (s, "    u32 context;\n");
    s = format (s, "    i32 retval;\n");
    s = format (s, "};\n");

    for (i = 0; i < vec_len (s); i++)
        clib_fifo_add1 (push_input_fifo, s[i]);
}

/*
 * yylex (well, yylex_1: The real yylex below does crc-hackery)
 */
static int yylex_1 (void)
{
    int nameidx=0;
    char c;
    enum { LP_INITIAL_WHITESPACE, LP_LINE_NUMBER,
	   LP_PRE_FILENAME_WHITESPACE, LP_FILENAME,
	   LP_POST_FILENAME,
	   LP_OTHER
    } lp_substate = LP_INITIAL_WHITESPACE;

 again:
    switch (the_lexer_state) {
        /*
         * START state -- looking for something interesting 
         */
    case START_STATE:
        c = getc_char (ifp);
        if (feof (ifp))
            return (EOF);

        switch (c) {
        case '\n':
            the_lexer_linenumber++;
            goto again;

        case '#':
            the_lexer_state = LINE_PRAGMA_STATE;
            lp_substate = LP_INITIAL_WHITESPACE;
            goto again;

            /* FALLTHROUGH */
        case '\t':
        case ' ':
            goto again;
            
        case '(':
            return (LPAR);

        case ')':
            return (RPAR);

        case ';':
            return (SEMI);

        case '[':
            return (LBRACK);
            
        case ']':
            return (RBRACK);

        case '{':
            return (LCURLY);
            
        case '}':
            return (RCURLY);

        case ',':
            return (COMMA);

        case '"':
            nameidx = 0;
            the_lexer_state = STRING_STATE;
            goto again;

        case '@':
            nameidx = 0;
            the_lexer_state = HELPER_STATE;
            goto again;

        case '/':
            c = getc_char (ifp);
            if (feof (ifp))
                return (EOF);

            if (c == '/') {
                the_lexer_state = CPP_COMMENT_STATE;
                goto again;
            } else if (c == '*') {
                the_lexer_state = C_COMMENT_STATE;
                goto again;
            } else {
                fprintf (stderr, "unknown token /%c at line %d\n",
                         c, the_lexer_linenumber);
                return (BARF);
            }

        case '\\':
            c = getc_char (ifp);
            if (feof (ifp))
                return (EOF);
            
            /* Note fallthrough... */

        default:
            if (isalpha (c) || c == '_') {
                namebuf [0] = c;
                nameidx = 1;
                the_lexer_state = NAME_STATE;
                goto again;
            } else if (isdigit(c)) {
                namebuf [0] = c;
                nameidx = 1;
                the_lexer_state = NUMBER_STATE;
                goto again;
            }

            fprintf (stderr, "unknown token %c at line %d\n",
                     c, the_lexer_linenumber);
            return (BARF);
        }

        /*
         * NAME state -- eat the rest of a name 
         */
    case NAME_STATE:
        c = getc_char (ifp);
        if (feof (ifp))
            return (EOF);
        
        if (!isalnum (c) && c != '_') {
            ungetc_char (c, ifp);
            namebuf [nameidx] = 0;
            the_lexer_state = START_STATE;
            return (name_check (namebuf, &yylval));
        }                
        if (nameidx >= (MAXNAME-1)) {
            fprintf(stderr, "lex input buffer overflow...\n");
            exit(1);
        }
        namebuf [nameidx++] = c;
        goto again;
        
        /*
         * NUMBER state -- eat the rest of a number
         */
    case NUMBER_STATE:
        c = getc_char (ifp);
        if (feof (ifp))
            return (EOF);
        
        if (!isdigit (c)) {
            ungetc_char (c, ifp);
            namebuf [nameidx] = 0;
            the_lexer_state = START_STATE;
            yylval = (void *) atol(namebuf);
            return (NUMBER);
        }                
        if (nameidx >= (MAXNAME-1)) {
            fprintf(stderr, "lex input buffer overflow...\n");
            exit(1);
        }
        namebuf [nameidx++] = c;
        goto again;

        /*
         * C_COMMENT state -- eat a peach
         */
    case C_COMMENT_STATE:
        c = getc_char (ifp);
        if (feof (ifp))
            return (EOF);
        if (c == '*') {
            c = getc_char (ifp);
            if (feof (ifp))
                return (EOF);
            if (c == '/') {
                the_lexer_state = START_STATE;
                goto again;
            }
        }
        if (c == '\n')
            the_lexer_linenumber++;
        goto again;
            
        /*
         * CPP_COMMENT state -- eat a plum 
         */

    case CPP_COMMENT_STATE:
        c = getc_char (ifp);
        if (feof (ifp))
            return (EOF);
        if (c == '\n') {
            the_lexer_linenumber++;
            the_lexer_state = START_STATE;
            goto again;
        }
        goto again;

    case STRING_STATE:
        c = getc_char (ifp);
        if (feof (ifp))
            return (EOF);
        switch (c) {
        case '\\':
            c = getc_char (ifp);
            if (feof (ifp))
                return (EOF);
            namebuf[nameidx++] = c;
            goto again;

        case '"':
            namebuf[nameidx] = 0;
            yylval = (YYSTYPE) sxerox (namebuf);
            the_lexer_state = START_STATE;
            return (STRING);

        default:
            if (c == '\n')
                the_lexer_linenumber++;

            if (nameidx >= (MAXNAME-1)) {
                fprintf(stderr, "lex input buffer overflow...\n");
                exit(1);
            }
            namebuf[nameidx++] = c;
            goto again;
        }
        break;

    case HELPER_STATE:
        c = getc_char (ifp);
        if (feof (ifp))
            return (EOF);
        switch (c) {
        case '\\':
            c = getc_char (ifp);
            if (feof (ifp))
                return (EOF);
            namebuf[nameidx] = c;
            goto again;

        case '@':
            namebuf[nameidx] = 0;
            yylval = (YYSTYPE) sxerox (namebuf);
            the_lexer_state = START_STATE;
            return (HELPER_STRING);

        default:
            if (c == '\n')
                the_lexer_linenumber++;

            /*
             * CPP makes it approximately impossible to 
             * type "#define FOO 123", so we provide a 
             * lexical trick to achieve that result 
             */

            if (c == '$')
                c = '#';

            if (nameidx >= (MAXNAME-1)) {
                fprintf(stderr, "lex input buffer overflow...\n");
                exit(1);
            }
            namebuf[nameidx++] = c;
            goto again;
        }
        break;

    case LINE_PRAGMA_STATE:
	/* We're only interested in lines of the form # 259 "foo.c" 17 */

        switch (lp_substate) {

        case LP_INITIAL_WHITESPACE: /* no number seen yet */
            c = getc_char(ifp);
            if (feof(ifp))
                return(EOF);
            if (c >= '0' && c <= '9') {
                namebuf[nameidx++] = c;
                lp_substate = LP_LINE_NUMBER;
            } else if (c == '\n') {
		goto lp_end_of_line;
	    } else if (c != ' ' && c != '\t') {
		/* Nothing */
	    } else {
		lp_substate = LP_OTHER;
	    }
	    goto again;

        case LP_LINE_NUMBER:	/* eating linenumber */
            c = getc_char(ifp);
            if (feof(ifp))
                return(EOF);
            if (c >= '0' && c <= '9') {
                namebuf[nameidx++] = c;
	    } else if (c == ' ' || c == '\t') {
                namebuf[nameidx++] = 0;
                the_lexer_linenumber = atol(namebuf);
                lp_substate = LP_PRE_FILENAME_WHITESPACE;
            } else if (c == '\n') {
		goto lp_end_of_line;
            } else {
		lp_substate = LP_OTHER;
	    }
            goto again;

        case LP_PRE_FILENAME_WHITESPACE: /* awaiting filename */
            c = getc_char(ifp);
            if (feof(ifp))
                return(EOF);
            
            if (c == '"') {
                lp_substate = LP_FILENAME;
                nameidx = 0;
            } else if (c == ' ' || c == '\t') {
		/* nothing */
	    } else if (c == '\n') {
		goto lp_end_of_line;
	    } else {
		lp_substate = LP_OTHER;
	    }
            goto again;

        case LP_FILENAME:	/* eating filename */
            c = getc_char(ifp);
            if (feof(ifp))
                return(EOF);

            if (c == '"') {
                lp_substate = LP_POST_FILENAME;
                namebuf[nameidx] = 0;
            } else if (c == '\n') {
		goto lp_end_of_line; /* syntax error... */
	    } else {
                namebuf[nameidx++] = c;
            }
            goto again;

        case LP_POST_FILENAME:	/* ignoring rest of line */
        case LP_OTHER:
            c = getc_char(ifp);
            if (feof(ifp))
                return(EOF);

            if (c == '\n') {
	        if (lp_substate == LP_POST_FILENAME) {
		    if (current_filename_allocated) {
			current_filename_allocated = 0;
			free(current_filename);
		    }

		    if (!strcmp(namebuf, "<stdin>")) {
			current_filename = input_filename;
		    } else {
			current_filename = sxerox(namebuf);
			current_filename_allocated = 1;
		    }
		}
	    lp_end_of_line:
                the_lexer_state = START_STATE;
                nameidx = 0;
            }
            goto again;
        }
        break;
    }
    fprintf (stderr, "LEXER BUG!\n");
    exit (1);
    /* NOTREACHED */
    return (0);
}

/*
 * Parse a token and side-effect input_crc
 * in a whitespace- and comment-insensitive fashion.
 */
int yylex (void)
{
    /*
     * Accumulate a crc32-based signature while processing the
     * input file.  The goal is to come up with a magic number
     * which changes precisely when the original input file changes
     * but which ignores whitespace changes.
     */
    unsigned long crc = input_crc;
    int node_type = yylex_1 ();
    unsigned long crc2 = message_crc;
    int use_helper_string = 0;
    unsigned short code;

    switch (node_type) {
    case PRIMTYPE:
    case NAME:
    case NUMBER:
    case STRING:
    case HELPER_STRING: 
        use_helper_string = 1;
        break;

     /* Other node types have no "substate" */
     /* This code is written in this curious fashion because we
      * want the generated CRC to be independent of the particular
      * values a particular version of lex/bison assigned to various states.
      */

    case RPAR:               code = 258; break;
    case LPAR:               code = 259; break;
    case SEMI:               code = 260; break;
    case LBRACK:             code = 261; break;
    case RBRACK:             code = 262; break;
    case BARF:               code = 265; break;
    case TPACKED:            code = 266; break;
    case DEFINE:             code = 267; break;
    case LCURLY:             code = 268; break;
    case RCURLY:             code = 269; break;
    case UNION:              code = 271; break;
    case COMMA:              code = 273; break;
    case NOVERSION:          code = 274; break;
    case MANUAL_PRINT:       code = 275; break;
    case MANUAL_ENDIAN:      code = 276; break;
    case TYPEONLY:           code = 278; break;
    case DONT_TRACE:         code = 279; break;
    case AUTOREPLY:          code = 280; break;
        
    case EOF: code = ~0; break; /* hysterical compatibility */

    default:
        fprintf(stderr, "yylex: node_type %d missing state CRC cookie\n",
                node_type);
        exit(1);
    }

    if (use_helper_string)
    {
        /* We know these types accumulated token text into namebuf */
        /* HELPER_STRING may still contain C comments.  Argh. */
        crc = crc_eliding_c_comments (namebuf, crc);
        crc2 = crc_eliding_c_comments (namebuf, crc2);
    } else
    {
        crc = CRC16 (crc, code);
        crc2 = CRC16 (crc2, code);
    }

    input_crc = crc;
    message_crc = crc2;
    return (node_type);
}

/*
 * name_check -- see if the name we just ate
 * matches a known keyword.  If so, set yylval
 * to a new instance of <subclass of node>, and return PARSER_MACRO
 *
 * Otherwise, set yylval to sxerox (s) and return NAME
 */

static struct keytab {
    char *name;
    enum node_subclass subclass_id;
} keytab [] = 
/* Keep the table sorted, binary search used below! */
{
    {"autoreply",       NODE_AUTOREPLY},
    {"define",          NODE_DEFINE},  
    {"dont_trace",      NODE_DONT_TRACE},
    {"f64",             NODE_F64},
    {"i16",             NODE_I16},
    {"i32",             NODE_I32},
    {"i64",             NODE_I64},
    {"i8",              NODE_I8},
    {"manual_endian",   NODE_MANUAL_ENDIAN},
    {"manual_print",    NODE_MANUAL_PRINT},
    {"noversion",       NODE_NOVERSION},
    {"packed",          NODE_PACKED},
    {"typeonly",        NODE_TYPEONLY},
    {"u16", 	        NODE_U16},
    {"u32",		NODE_U32},
    {"u64",             NODE_U64},
    {"u8", 		NODE_U8},
    {"union",           NODE_UNION},
    {"uword",           NODE_UWORD},
};
 
static int name_check (const char *s, YYSTYPE *token_value)
{
    enum node_subclass subclass_id;
    int top, bot, mid;
    int result;

    for (top = 0, bot = (sizeof(keytab) / sizeof(struct keytab))-1; 
         bot >= top; ) {
        mid = (top + bot) / 2;
        result = name_compare (s, keytab[mid].name);
        if (result < 0)
            bot = mid - 1;
        else if (result > 0)
            top = mid + 1;
        else {
            subclass_id = keytab[mid].subclass_id;

            switch (subclass_id) {
            case NODE_U8:
            case NODE_U16:
            case NODE_U32:
            case NODE_U64:
            case NODE_I8:
            case NODE_I16:
            case NODE_I32:
            case NODE_I64:
            case NODE_F64:
            case NODE_UWORD:
                *token_value = make_node(subclass_id);
                return (PRIMTYPE);

            case NODE_PACKED:
                *token_value = make_node(subclass_id);
                return (TPACKED);

            case NODE_DEFINE:
                message_crc = 0;
                *token_value = make_node(subclass_id);
                return(DEFINE);

            case NODE_MANUAL_PRINT:
                *token_value = (YYSTYPE) NODE_FLAG_MANUAL_PRINT;
                return (MANUAL_PRINT);

            case NODE_MANUAL_ENDIAN:
                *token_value = (YYSTYPE) NODE_FLAG_MANUAL_ENDIAN;
                return (MANUAL_ENDIAN);

            case NODE_TYPEONLY:
                *token_value = (YYSTYPE) NODE_FLAG_TYPEONLY;
                return(TYPEONLY);

            case NODE_DONT_TRACE:
                *token_value = (YYSTYPE) NODE_FLAG_DONT_TRACE;
                return(DONT_TRACE);

            case NODE_AUTOREPLY:
                *token_value = (YYSTYPE) NODE_FLAG_AUTOREPLY;
                return(AUTOREPLY);

            case NODE_NOVERSION:
                return(NOVERSION);

            case NODE_UNION:
                return(UNION);

            default:
                fprintf (stderr, "fatal: keytab botch!\n");
                exit (1);
            }
        }
    }
    *token_value = (YYSTYPE) sxerox (s);
    return (NAME);
}

/*
 * sxerox
 */

char *sxerox (const char *s)
{
    int len = strlen (s);
    char *rv;

    rv = (char *) malloc (len+1);
    if (rv == 0) {
        fprintf(stderr, "Out of memory...");
        exit (1);
    }
        
    strcpy (rv, s);
    return (rv);
}

/*
 * name_compare
 */

int name_compare (const char *s1, const char *s2)
{
    char c1, c2;

    while (*s1 && *s2) {
        c1 = *s1++;
        c2 = *s2++;

        c1 = tolower (c1);
        c2 = tolower (c2);
        if (c1 < c2)
            return (-1);
        else if (c1 > c2)
            return (1);
    }
    if (*s1 < *s2)
        return (-1);
    else if (*s1 > *s2)
        return (1);
    return (0);
}
