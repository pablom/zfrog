// cf_toml.c

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <setjmp.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <string.h>

#include <sys/stat.h>
#include "zfrog.h"
#include "cf_toml.h"

/***********************************************************
 *  TOML has 3 data structures: value, array, table.
 *  Each of them can have identification key.
 ***********************************************************/
typedef struct toml_keyval_t toml_keyval_t;

struct toml_keyval_t
{
    const char* key;    /* key to this value */
    const char* val;	/* the raw value */
};

enum tokentype_t
{
    INVALID,
    DOT,
    COMMA,
    EQUAL,
    LBRACE,
    RBRACE,
    NEWLINE,
    LBRACKET,
    RBRACKET,
    STRING,
};

typedef enum tokentype_t tokentype_t;

struct toml_table_t
{
    const char* key;	/* key to this table            */
    int implicit;		/* table was created implicitly */

    /* key-values in the table */
    int             nkval;
    toml_keyval_t** kval;

    /* arrays in the table */
    int            narr;
    toml_array_t** arr;

    /* tables in the table */
    int            ntab;
    toml_table_t** tab;
};

typedef struct token_t token_t;

struct token_t
{
    tokentype_t tok;
    int         lineno;
    char*       ptr;
    int         len;
    int         eof;
};

typedef struct context_t context_t;

struct context_t
{
    char* start;
    char* stop;
    jmp_buf jmp;

    token_t tok;
    toml_table_t* root;
    toml_table_t* curtab;

    struct
    {
        int     top;
        char*   key[10];
        token_t tok[10];
    } tpath;

};

struct toml_array_t
{
    const char* key;	/* key to this array */
    int kind;           /* element kind: 'v'alue, 'a'rray, or 't'able */
    int type;           /* for value kind: 'i'nt, 'd'ouble, 'b'ool, 's'tring, 't'ime, 'D'ate, 'T'imestamp */

    int nelem;			/* number of elements */
    union
    {
        char**         val;
        toml_array_t** arr;
        toml_table_t** tab;
    } u;
};

/* Forward static function declaration */
static void e_internal_error(context_t*,const char*);
static void e_syntax_error(context_t*,int,const char*);
static void e_bad_key_error(context_t*,int);
static void e_key_exists_error(context_t*,token_t);

static void parse_keyval(context_t*,toml_table_t*);
static void parse_array( context_t*,toml_array_t*);
static void parse_table( context_t*,toml_table_t*);
static void parse_select(context_t*);
static toml_array_t* create_keyarray_in_table(context_t*,toml_table_t*,token_t,int);
static toml_table_t* create_table_in_array(context_t*,toml_array_t*);
static toml_keyval_t* create_keyval_in_table(context_t*,toml_table_t*,token_t);
static toml_table_t* create_keytable_in_table(context_t*,toml_table_t*,token_t);
static toml_array_t* create_array_in_array(context_t*,toml_array_t*);
static int check_key(toml_table_t*,const char*,toml_keyval_t**,toml_array_t**,toml_table_t**);
static char* kill_line_ending_backslash(char*);
static void fill_tabpath(context_t*);
static void walk_tabpath(context_t*);
static char* normalize_key(context_t*,token_t);
static char* normalize_string(const char*,int,int);
static int valtype(const char*);
static tokentype_t scan_string(context_t*,char*,int,int);
static tokentype_t next_token(context_t*,int);
static tokentype_t ret_token(context_t*,tokentype_t,int,char*,int);
static tokentype_t ret_eof(context_t*,int);


static void toml_free_tab(toml_table_t*);
static void toml_free_kval(toml_keyval_t*);
static void toml_free_arr(toml_array_t*);

#define STRINGIFY(x) #x
#define TOSTRING(x)  STRINGIFY(x)
#define FLINE __FILE__ ":" TOSTRING(__LINE__)

#define SKIP_NEWLINES(ctx)  while (ctx->tok.tok == NEWLINE) next_token(ctx, 0)
#define EAT_TOKEN(ctx, typ) \
    if ((ctx)->tok.tok != typ) e_internal_error(ctx, FLINE); else next_token(ctx, 0)


toml_table_t* cf_toml_open( const char *filename )
{
    toml_table_t* ret = NULL;
    FILE *fp = NULL;
    struct stat stb;

    /* Try to open file */
    if( (fp = fopen(filename, "r")) )
    {
        /* Get file name & check that is not a folder */
        if( !fstat(fileno(fp), &stb) && S_ISREG(stb.st_mode) != 0 )
        {
            ret = cf_toml_parse_file(fp, stb.st_size);
        }

        /* Close file */
        fclose( fp );
    }

    return ret;
}

toml_table_t* cf_toml_parse_file( FILE* fp, size_t f_size )
{
    toml_table_t* ret = NULL;

    /* Allocate temporary buffer */
    char* buf = (char*)mem_malloc(f_size + 1);

     /* Try to read all file data to temporary buffer */
    int n = fread(buf, 1, f_size, fp);

    if( (size_t)n == f_size )
    {
        /* tag on a NUL to cap the string */
        buf[n] = 0;

        /* parse it, cleanup and finish */
        ret = cf_toml_parse(buf);
    }

    /* Delete temporary buffer */
    mem_free( buf );

    return ret;
}

toml_table_t* cf_toml_parse( char* conf )
{
    int i = 0;
    token_t tok;
    context_t ctx;

    /* Init context */
    memset(&ctx, 0, sizeof(ctx));
    ctx.start = conf;
    ctx.stop = ctx.start + strlen(conf);

    /* Start with an artificial newline of length 0 */
    ctx.tok.tok = NEWLINE;
    ctx.tok.lineno = 1;
    ctx.tok.ptr = conf;
    ctx.tok.len = 0;

    /* make a root table */
    ctx.root = mem_calloc(1, sizeof(*ctx.root));

    /* Set root as default table */
    ctx.curtab = ctx.root;

    if( setjmp(ctx.jmp) )
    {
        /* Got here from a long_jmp. Something bad has happened */
        /* Free resources and return error */
        for( i = 0; i < ctx.tpath.top; i++ )
            mem_free( ctx.tpath.key[i] );

        cf_toml_free(ctx.root);
        return NULL;
    }

    /* Scan forward until EOF */
    for( tok = ctx.tok; ! tok.eof ; tok = ctx.tok)
    {
        switch( tok.tok )
        {
            case NEWLINE:
                next_token(&ctx, 1);
                break;

            case STRING:
                parse_keyval(&ctx, ctx.curtab);
                if( ctx.tok.tok != NEWLINE )
                {
                    e_syntax_error(&ctx, ctx.tok.lineno, "extra chars after value");
                    return NULL;         /* not reached */
                }

                EAT_TOKEN(&ctx, NEWLINE);
                break;

            case LBRACKET:  /* [ x.y.z ] or [[ x.y.z ]] */
                parse_select(&ctx);
                break;

            default:
                e_syntax_error(&ctx, tok.lineno, "syntax error");
                break;
        }
    }

    /* success */
    for( i = 0; i < ctx.tpath.top; i++ )
        mem_free( ctx.tpath.key[i] );

    return ctx.root;
}

void cf_toml_free(toml_table_t* tab)
{
    toml_free_tab(tab);
}

const char* cf_toml_key_in(toml_table_t* tab, int keyidx)
{
    if( keyidx < tab->nkval )
        return tab->kval[keyidx]->key;

    keyidx -= tab->nkval;

    if( keyidx < tab->narr )
        return tab->arr[keyidx]->key;

    keyidx -= tab->narr;

    if( keyidx < tab->ntab )
        return tab->tab[keyidx]->key;

    return 0;
}

const char* cf_toml_raw_in( toml_table_t* tab, const char* key )
{
    int i;

    for( i = 0; i < tab->nkval; i++ )
    {
        if( !strcmp(key, tab->kval[i]->key) )
            return tab->kval[i]->val;
    }

    return 0;
}

toml_array_t* cf_toml_array_in( toml_table_t* tab, const char* key )
{
    int i;

    for( i = 0; i < tab->narr; i++ )
    {
        if( !strcmp(key, tab->arr[i]->key) )
            return tab->arr[i];
    }

    return 0;
}

toml_table_t* cf_toml_table_in( toml_table_t* tab, const char* key )
{
    int i;
    for( i = 0; i < tab->ntab; i++ )
    {
        if( !strcmp(key, tab->tab[i]->key) )
            return tab->tab[i];
    }

    return 0;
}

const char* cf_toml_raw_at( toml_array_t* arr, int idx )
{
    if( arr->kind != 'v' )
        return 0;

    if( ! (0 <= idx && idx < arr->nelem) )
        return 0;

    return arr->u.val[idx];
}

char cf_toml_array_kind( toml_array_t* arr )
{
    return arr->kind;
}

int cf_toml_array_nelem( toml_array_t* arr )
{
    return arr->nelem;
}

const char* cf_toml_array_key( toml_array_t* arr )
{
    return arr ? arr->key : (const char*) NULL;
}

int cf_toml_table_nkval( toml_table_t* tab )
{
    return tab->nkval;
}

int cf_toml_table_narr( toml_table_t* tab )
{
    return tab->narr;
}

int cf_toml_table_ntab( toml_table_t* tab )
{
    return tab->ntab;
}

const char* cf_toml_table_key( toml_table_t* tab )
{
    return tab ? tab->key : (const char*) NULL;
}

toml_array_t* cf_toml_array_at( toml_array_t* arr, int idx )
{
    if( arr->kind != 'a' )
        return 0;
    if( !(0 <= idx && idx < arr->nelem) )
        return 0;

    return arr->u.arr[idx];
}

toml_table_t* cf_toml_table_at( toml_array_t* arr, int idx )
{
    if( arr->kind != 't' )
        return 0;

    if( !(0 <= idx && idx < arr->nelem) )
        return 0;

    return arr->u.tab[idx];
}

int cf_toml_rtots( const char* src_, toml_timestamp_t* ret )
{
    int64_t val;
    int i;
    char* z = NULL;
    const char* q = NULL;
    const char* p = src_;

    if( ! src_ )
        return -1;

    q = src_ + strlen(src_);

    memset(ret, 0, sizeof(*ret));

    /* parse date */
    val = 0;

    if( q - p > 4 && p[4] == '-' )
    {
        for( i = 0; i < 10; i++, p++ )
        {
            int xx = *p;
            if( xx == '-' )
            {
                if( i == 4 || i == 7 )
                    continue;
                else
                    return -1;
            }

            if( ! ('0' <= xx && xx <= '9') )
                return -1;

            val = val * 10 + (xx - '0');
        }

        ret->day   = &ret->__buffer.day;
        ret->month = &ret->__buffer.month;
        ret->year  = &ret->__buffer.year;

        *ret->day   = val % 100; val /= 100;
        *ret->month = val % 100; val /= 100;
        *ret->year  = val;

        if( *p )
        {
            if( *p != 'T' )
                return -1;
            p++;
        }
    }

    if( q == p )
        return 0;

    /* parse time */
    val = 0;

    if( q - p < 8 )
        return -1;

    for( i = 0; i < 8; i++, p++ )
    {
        int xx = *p;
        if( xx == ':' )
        {
            if( i == 2 || i == 5 )
                continue;
            else
                return -1;
        }

        if( ! ('0' <= xx && xx <= '9') )
            return -1;

        val = val * 10 + (xx - '0');
    }

    ret->second = &ret->__buffer.second;
    ret->minute = &ret->__buffer.minute;
    ret->hour   = &ret->__buffer.hour;

    *ret->second = val % 100; val /= 100;
    *ret->minute = val % 100; val /= 100;
    *ret->hour   = val;

    /* skip fractional second */
    if( *p == '.' ) for (p++; '0' <= *p && *p <= '9'; p++);
    if( q == p ) return 0;

    /* parse and copy Z */
    ret->z = ret->__buffer.z;
    z = ret->z;

    if( *p == 'Z' )
    {
        *z++ = *p++;
        *z = 0;
        return (p == q) ? 0 : -1;
    }

    if( *p == '+' || *p == '-' )
    {
        *z++ = *p++;

        if( ! (isdigit(p[0]) && isdigit(p[1])) )
            return -1;

        *z++ = *p++;
        *z++ = *p++;

        if( *p == ':' )
        {
            *z++ = *p++;

            if( !(isdigit(p[0]) && isdigit(p[1])) )
                return -1;

            *z++ = *p++;
            *z++ = *p++;
        }

        *z = 0;
    }

    return (p == q) ? 0 : -1;
}

/**********************************************************
 *  We are at '[...]'
**********************************************************/
static void parse_array( context_t* ctx, toml_array_t* arr )
{
    EAT_TOKEN(ctx, LBRACKET);

    for(;;)
    {
        SKIP_NEWLINES(ctx);

        /* until ] */
        if( ctx->tok.tok == RBRACKET )
            break;

        switch( ctx->tok.tok )
        {
        case STRING:
            {
                char** tmp = NULL;
                char* val = ctx->tok.ptr;
                int   vlen = ctx->tok.len;

                /* set array kind if this will be the first entry */
                if( arr->kind == 0 )
                    arr->kind = 'v';

                /* check array kind */
                if( arr->kind != 'v' )
                {
                    e_syntax_error(ctx, ctx->tok.lineno,"a string array can only contain strings");
                    return;     /* not reached */
                }

                /* make a new value in array */
                tmp = (char**) mem_realloc(arr->u.val, (arr->nelem+1) * sizeof(*tmp));

                arr->u.val = tmp;
                val = strndup(val, vlen);

                arr->u.val[arr->nelem++] = val;

                /* set array type if this is the first entry, or check that the types matched. */
                if( arr->nelem == 1 )
                    arr->type = valtype(arr->u.val[0]);
                else if( arr->type != valtype(val) )
                {
                    e_syntax_error(ctx, ctx->tok.lineno, "array type mismatch");
                    return; /* not reached */
                }

                EAT_TOKEN(ctx, STRING);
                break;
            }

        case LBRACKET:
            {   /* [ [array], [array] ... ] */
                /* set the array kind if this will be the first entry */
                if( arr->kind == 0 )
                    arr->kind = 'a';

                /* check array kind */
                if( arr->kind != 'a' )
                {
                    e_syntax_error(ctx, ctx->tok.lineno, "array type mismatch");
                    return;     /* not reached */
                }

                parse_array(ctx, create_array_in_array(ctx, arr));
                break;
            }

        case LBRACE:
            {   /* [ {table}, {table} ... ] */
                /* set the array kind if this will be the first entry */
                if( arr->kind == 0 )
                    arr->kind = 't';
                /* check array kind */
                if( arr->kind != 't' )
                {
                    e_syntax_error(ctx, ctx->tok.lineno, "array type mismatch");
                    return;     /* not reached */
                }

                parse_table(ctx, create_table_in_array(ctx, arr));
                break;
            }

        default:
            e_syntax_error(ctx, ctx->tok.lineno, "syntax error");
            return;  /* not reached */
        }

        SKIP_NEWLINES(ctx);

        /* on comma, continue to scan for next element */
        if( ctx->tok.tok == COMMA )
        {
            EAT_TOKEN(ctx, COMMA);
            continue;
        }

        break;
    }

    if( ctx->tok.tok != RBRACKET )
    {
        e_syntax_error(ctx, ctx->tok.lineno, "syntax error");
        return;  /* not reached */
    }

    EAT_TOKEN(ctx, RBRACKET);
}
/**********************************************************
 * handle lines like these:
 *    key = "value"
 *    key = [ array ]
 *    key = { table }
**********************************************************/
static void parse_keyval(context_t* ctx, toml_table_t* tab)
{
    token_t key;

    if( ctx->tok.tok != STRING )
    {
        e_internal_error(ctx, FLINE);
        return; /* not reached */
    }

    key = ctx->tok;

    EAT_TOKEN(ctx, STRING);

    if( ctx->tok.tok != EQUAL )
    {
        e_syntax_error(ctx, ctx->tok.lineno, "missing =");
        return;  /* not reached */
    }

    EAT_TOKEN(ctx, EQUAL);

    switch( ctx->tok.tok )
    {
        case STRING:
        {   /* key = "value" */
            toml_keyval_t* keyval = create_keyval_in_table(ctx, tab, key);
            token_t val = ctx->tok;
            assert(keyval->val == 0);
            keyval->val = strndup(val.ptr, val.len);
            EAT_TOKEN(ctx, STRING);
            return;
        }

        case LBRACKET:
            {   /* key = [ array ] */
                toml_array_t* arr = create_keyarray_in_table(ctx, tab, key, 0);
                parse_array(ctx, arr);
                return;
            }

        case LBRACE:
            {   /* key = { table } */
                toml_table_t* nxttab = create_keytable_in_table(ctx, tab, key);
                parse_table(ctx, nxttab);
                return;
            }

        default:
            e_syntax_error(ctx, ctx->tok.lineno, "syntax error");
            return; /* not reached */
    }
}
/**********************************************************
 *  We are at '{ ... }'.
 *  Parse the table.
 **********************************************************/
static void parse_table( context_t* ctx, toml_table_t* tab )
{
    EAT_TOKEN(ctx, LBRACE);

    for(;;)
    {
        SKIP_NEWLINES(ctx);

        /* until } */
        if( ctx->tok.tok == RBRACE )
            break;

        if( ctx->tok.tok != STRING )
        {
            e_syntax_error(ctx, ctx->tok.lineno, "syntax error");
            return; /* not reached */
        }

        parse_keyval(ctx, tab);
        SKIP_NEWLINES(ctx);

        /* on comma, continue to scan for next keyval */
        if( ctx->tok.tok == COMMA )
        {
            EAT_TOKEN(ctx, COMMA);
            continue;
        }

        break;
    }

    if( ctx->tok.tok != RBRACE )
    {
        e_syntax_error(ctx, ctx->tok.lineno, "syntax error");
        return;  /* not reached */
    }

    EAT_TOKEN(ctx, RBRACE);
}
/**********************************************************
 *  handle lines like [x.y.z] or [[x.y.z]]
**********************************************************/
static void parse_select( context_t* ctx )
{
    int count_lbracket = 0;

    if( ctx->tok.tok != LBRACKET )
    {
        e_internal_error(ctx, FLINE);
        return;  /* not reached */
    }

    count_lbracket++;
    next_token(ctx, 1 /* DOT IS SPECIAL */);
    if( ctx->tok.tok == LBRACKET )
    {
        count_lbracket++;
        next_token(ctx, 1 /* DOT IS SPECIAL */);
    }

    fill_tabpath(ctx);

    /* For [x.y.z] or [[x.y.z]], remove z from tpath */
    token_t z = ctx->tpath.tok[ctx->tpath.top-1];
    mem_free( ctx->tpath.key[ctx->tpath.top-1] );
    ctx->tpath.top--;

    walk_tabpath(ctx);

    if( count_lbracket == 1 )
    {
        /* [x.y.z] -> create z = {} in x.y */
        ctx->curtab = create_keytable_in_table(ctx, ctx->curtab, z);
    }
    else
    {
        /* [[x.y.z]] -> create z = [] in x.y */
        toml_array_t* arr = create_keyarray_in_table(ctx, ctx->curtab, z, 1 /*skip_if_exist*/);
        if( !arr )
        {
            e_syntax_error(ctx, z.lineno, "key exists");
            return;
        }

        if( arr->kind == 0 )
            arr->kind = 't';

        if( arr->kind != 't' )
        {
            e_syntax_error(ctx, z.lineno, "array mismatch");
            return; /* not reached */
        }

        /* add to z[] */
        toml_table_t* dest;
        {
            int n = arr->nelem;
            toml_table_t** base = realloc(arr->u.tab, (n+1) * sizeof(*base));
            if (0 == base) {
                e_outofmemory(ctx, FLINE);
                return;         /* not reached */
            }
        arr->u.tab = base;

        if (0 == (base[n] = calloc(1, sizeof(*base[n])))) {
        e_outofmemory(ctx, FLINE);
                return;         /* not reached */
            }

            if (0 == (base[n]->key = strdup("__anon__"))) {
        e_outofmemory(ctx, FLINE);
                return;         /* not reached */
            }

        dest = arr->u.tab[arr->nelem++];
        }

        ctx->curtab = dest;
    }

    if( ctx->tok.tok != RBRACKET )
    {
        e_syntax_error(ctx, ctx->tok.lineno, "expects ]");
        return; /* not reached */
    }

    EAT_TOKEN(ctx, RBRACKET);

    if( count_lbracket == 2 )
    {
        if( ctx->tok.tok != RBRACKET )
        {
            e_syntax_error(ctx, ctx->tok.lineno, "expects ]]");
            return; /* not reached */
        }

        EAT_TOKEN(ctx, RBRACKET);
    }

    if( ctx->tok.tok != NEWLINE)
    {
        e_syntax_error(ctx, ctx->tok.lineno, "extra chars after ] or ]]");
        return; /* not reached */
    }
}
/**********************************************************
 *  Create an array in the table
 **********************************************************/
static toml_array_t* create_keyarray_in_table( context_t* ctx,toml_table_t* tab, token_t keytok, int skip_if_exist )
{
    int n = 0;
    toml_array_t** base = NULL;

    /* first, normalize the key to be used for lookup.
     * remember to free it if we error out.
     */
    char* newkey = normalize_key(ctx, keytok);

    /* if key exists: error out */
    toml_array_t* dest = 0;

    if( check_key(tab, newkey, 0, &dest, 0) )
    {
        mem_free(newkey); /* don't need this anymore */

        /* special case skip if exists? */
        if( skip_if_exist )
            return dest;

        e_key_exists_error(ctx, keytok);
        return 0; /* not reached */
    }

    /* make a new array entry */
    n = tab->narr;

    base = (toml_array_t**) mem_realloc(tab->arr, (n+1) * sizeof(*base));
    base[n] = (toml_array_t*) mem_calloc(1, sizeof(*base[n]));
    tab->arr = base;

    dest = tab->arr[tab->narr++];

    /* save the key in the new array struct */
    dest->key = newkey;
    return dest;
}
/******************************************************************
 * Create a table in an array
 ******************************************************************/
static toml_table_t* create_table_in_array( context_t* ctx, toml_array_t* parent )
{
    int n = parent->nelem;
    toml_table_t** base = NULL;

    /* Reallocate memory buffer */
    base = (toml_table_t**)mem_realloc(parent->u.tab, (n+1) * sizeof(*base));

    parent->u.tab = base;
    base[n] = (toml_table_t*) mem_calloc( 1, sizeof(*base[n]) );

    return parent->u.tab[parent->nelem++];
}
/******************************************************************
 *  at [x.y.z] or [[x.y.z]]
 *  Scan forward and fill tabpath until it enters ] or ]]
  * There will be at least one entry on return.
 ******************************************************************/
static void fill_tabpath( context_t* ctx )
{
    int i;
    int lineno = ctx->tok.lineno;

    /* clear tpath */
    for( i = 0; i < ctx->tpath.top; i++ )
    {
        char** p = &ctx->tpath.key[i];
        mem_free(*p);
        *p = 0;
    }

    ctx->tpath.top = 0;

    for(;;)
    {
        if( ctx->tpath.top >= 10 )
        {
            e_syntax_error(ctx, lineno, "table path is too deep; max allowed is 10.");
            return; /* not reached */
        }

        if( ctx->tok.tok != STRING )
        {
            e_syntax_error(ctx, lineno, "invalid or missing key");
            return; /* not reached */
        }

        ctx->tpath.tok[ctx->tpath.top] = ctx->tok;
        ctx->tpath.key[ctx->tpath.top] = normalize_key(ctx, ctx->tok);
        ctx->tpath.top++;

        next_token(ctx, 1);

        if( ctx->tok.tok == RBRACKET )
            break;

        if( ctx->tok.tok != DOT )
        {
            e_syntax_error(ctx, lineno, "invalid key");
            return;             /* not reached */
        }

        next_token(ctx, 1);
    }

    if( ctx->tpath.top <= 0 )
    {
        e_syntax_error(ctx, lineno, "empty table selector");
        return; /* not reached */
    }
}
/******************************************************************
 *  Walk tabpath from the root, and create new tables on the way.
 *  Sets ctx->curtab to the final table.
 ******************************************************************/
static void walk_tabpath( context_t* ctx )
{
    int i = 0;
    /* start from root */
    toml_table_t* curtab = ctx->root;

    for( i = 0; i < ctx->tpath.top; i++ )
    {
        const char* key = ctx->tpath.key[i];

        toml_keyval_t* nextval = 0;
        toml_array_t* nextarr = 0;
        toml_table_t* nexttab = 0;

        switch( check_key(curtab, key, &nextval, &nextarr, &nexttab) )
        {
        case 't':
            /* found a table. nexttab is where we will go next. */
            break;

        case 'a':
            /* found an array. nexttab is the last table in the array. */
            if( nextarr->kind != 't' )
            {
                e_internal_error(ctx, FLINE);
                return;         /* not reached */
            }

            if( nextarr->nelem == 0 )
            {
                e_internal_error(ctx, FLINE);
                return;         /* not reached */
            }

            nexttab = nextarr->u.tab[nextarr->nelem-1];
            break;

        case 'v':
            e_key_exists_error(ctx, ctx->tpath.tok[i]);
            return;  /* not reached */

        default:
            {   /* Not found. Let's create an implicit table */
                int n = curtab->ntab;
                toml_table_t** base = (toml_table_t**) mem_realloc(curtab->tab, (n+1) * sizeof(*base));

                curtab->tab = base;

                base[n] = (toml_table_t*) mem_calloc(1, sizeof(*base[n]));
                base[n]->key = mem_strdup( key );

                nexttab = curtab->tab[curtab->ntab++];

                /* tabs created by walk_tabpath are considered implicit */
                nexttab->implicit = 1;
            }
            break;
        }

        /* switch to next tab */
        curtab = nexttab;
    }

    /* save it */
    ctx->curtab = curtab;
}

static int valtype( const char* val )
{
    toml_timestamp_t ts;

    if( *val == '\'' || *val == '"' ) return 's';
    if( cf_toml_rtob(val, 0) == 0 ) return 'b';
    if( cf_toml_rtoi(val, 0) == 0 ) return 'i';
    if( cf_toml_rtod(val, 0) == 0 ) return 'd';
    if( cf_toml_rtots(val, &ts) == 0 )
    {
        if( ts.year && ts.hour )
            return 'T'; /* timestamp */

        if( ts.year )
            return 'D'; /* date */

        return 't'; /* time */
    }

    return 'u'; /* unknown */
}
/******************************************************************
 * Normalize a key. Convert all special chars to raw
 * unescaped utf-8 chars.
******************************************************************/
static char* normalize_key( context_t* ctx, token_t strtok )
{
    const char* sp = strtok.ptr;
    const char* sq = strtok.ptr + strtok.len;
    int lineno = strtok.lineno;
    char* ret;
    int ch = *sp;
    char ebuf[80];
    const char* xp = NULL;

    /* handle quoted string */
    if( ch == '\'' || ch == '\"' )
    {
        /* if ''' or """, take 3 chars off front and back. Else, take 1 char off. */
        if( sp[1] == ch && sp[2] == ch )
            sp += 3, sq -= 3;
        else
            sp++, sq--;

        if( ch == '\'' )
        {
            /* for single quote, take it verbatim. */
            if( !(ret = strndup(sp, sq - sp))) 
            {
                e_outofmemory(ctx, FLINE);
                return 0;       /* not reached */
            }

        }
        else
        {
            /* for double quote, we need to normalize */
            ret = normalize_string(sp, sq - sp, 0);
            if( !ret )
            {
                snprintf(ctx->errbuf, ctx->errbufsz, "line %d: %s", lineno, ebuf);
                longjmp(ctx->jmp, 1);
            }
        }

        /* newlines are not allowed in keys */
        if( strchr(ret, '\n') )
        {
            free(ret);
            e_bad_key_error(ctx, lineno);
            return 0;           /* not reached */
        }

        return ret;
    }

    /* for bare-key allow only this regex: [A-Za-z0-9_-]+ */    
    for( xp = sp; xp != sq; xp++ )
    {
        int k = *xp;
        if( isalnum(k) )
            continue;

        if( k == '_' || k == '-' )
            continue;

        e_bad_key_error(ctx, lineno);
        return 0; /* not reached */
    }

    /* dup and return it */
    if( !(ret = strndup(sp, sq - sp)) )
    {
        e_outofmemory(ctx, FLINE);
        return 0;               /* not reached */
    }

    return ret;
}



static void toml_free_tab( toml_table_t* p )
{
    int i;

    if( !p )
        return;

    mem_free(p->key);

    for (i = 0; i < p->nkval; i++)
        toml_free_kval(p->kval[i]);
    mem_free( p->kval );

    for (i = 0; i < p->narr; i++)
        toml_free_arr(p->arr[i]);
    mem_free(p->arr);

    for( i = 0; i < p->ntab; i++ )
        toml_free_tab( p->tab[i] );
    mem_free( p->tab );

    mem_free( p );
}

static void toml_free_kval( toml_keyval_t* p )
{
    if( !p ) return;
    mem_free(p->key);
    mem_free(p->val);
    mem_free(p);
}

static void toml_free_arr( toml_array_t* p )
{
    int i = 0;
    if( !p ) return;

    mem_free( p->key );

    switch( p->kind )
    {
        case 'v':
            for( i = 0; i < p->nelem; i++ )
                mem_free(p->u.val[i]);
            mem_free(p->u.val);
            break;

        case 'a':
            for( i = 0; i < p->nelem; i++ )
                toml_free_arr(p->u.arr[i]);
            mem_free(p->u.arr);
            break;

        case 't':
            for( i = 0; i < p->nelem; i++ )
                toml_free_tab(p->u.tab[i]);
            mem_free(p->u.tab);
            break;
    }

    mem_free(p);
}

static tokentype_t next_token( context_t* ctx, int dotisspecial )
{
    int lineno = ctx->tok.lineno;
    char* p = ctx->tok.ptr;
    int i;

    /* eat this tok */
    for( i = 0; i < ctx->tok.len; i++ )
    {
        if( *p++ == '\n' )
            lineno++;
    }

    /* make next tok */
    while( p < ctx->stop )
    {
        /* skip comment. stop just before the \n. */
        if( *p == '#' )
        {
            for (p++; p < ctx->stop && *p != '\n'; p++);
            continue;
        }

        if( dotisspecial && *p == '.' )
            return ret_token(ctx, DOT, lineno, p, 1);

        switch( *p )
        {
            case ',': return ret_token(ctx, COMMA, lineno, p, 1);
            case '=': return ret_token(ctx, EQUAL, lineno, p, 1);
            case '{': return ret_token(ctx, LBRACE, lineno, p, 1);
            case '}': return ret_token(ctx, RBRACE, lineno, p, 1);
            case '[': return ret_token(ctx, LBRACKET, lineno, p, 1);
            case ']': return ret_token(ctx, RBRACKET, lineno, p, 1);
            case '\n': return ret_token(ctx, NEWLINE, lineno, p, 1);
            case '\r':
            case ' ':
            case '\t':
                /* ignore white spaces */
                p++;
                continue;
        }

        return scan_string(ctx, p, lineno, dotisspecial);
    }

    return ret_eof(ctx, lineno);
}

static tokentype_t ret_token(context_t* ctx, tokentype_t tok, int lineno, char* ptr, int len)
{
    token_t t;
    t.tok = tok;
    t.lineno = lineno;
    t.ptr = ptr;
    t.len = len;
    t.eof = 0;
    ctx->tok = t;
    return tok;
}

static tokentype_t ret_eof(context_t* ctx, int lineno)
{
    ret_token(ctx, NEWLINE, lineno, ctx->stop, 0);
    ctx->tok.eof = 1;
    return ctx->tok.tok;
}

static tokentype_t scan_string(context_t* ctx, char* p, int lineno, int dotisspecial)
{
    char* orig = p;

    if( strncmp(p, "'''", 3) == 0 )
    {
        if( (p = strstr(p + 3, "'''")) == 0 )
        {
            e_syntax_error(ctx, lineno, "unterminated triple-s-quote");
            return 0; /* not reached */
        }

        return ret_token(ctx, STRING, lineno, orig, p + 3 - orig);
    }

    if( strncmp(p, "\"\"\"", 3) == 0 )
    {
        int hexreq = 0;		/* #hex required */
        int escape = 0;
        int qcnt = 0;		/* count quote */

        for( p += 3; *p && qcnt < 3; p++ )
        {
            if( escape )
            {
                escape = 0;
                if( strchr("btnfr\"\\", *p) )
                    continue;

                if( *p == 'u' ) { hexreq = 4; continue; }
                if( *p == 'U' ) { hexreq = 8; continue; }

                if( *p == '\n' )
                    continue; /* allow for line ending backslash */

                e_syntax_error(ctx, lineno, "bad escape char");
                return 0; /* not reached */
            }

            if( hexreq )
            {
                hexreq--;
                if( strchr("0123456789ABCDEF", *p) )
                    continue;

                e_syntax_error(ctx, lineno, "expect hex char");
                return 0;       /* not reached */
            }

            if( *p == '\\' )
            {
                escape = 1;
                continue;
            }

            qcnt = (*p == '"') ? qcnt + 1 : 0;
        }

        if( qcnt != 3 )
        {
            e_syntax_error(ctx, lineno, "unterminated triple-quote");
            return 0;  /* not reached */
        }

        return ret_token(ctx, STRING, lineno, orig, p - orig);
    }

    if( '\'' == *p )
    {
        for( p++; *p && *p != '\n' && *p != '\''; p++);

        if( *p != '\'' )
        {
            e_syntax_error(ctx, lineno, "unterminated s-quote");
            return 0; /* not reached */
        }

        return ret_token(ctx, STRING, lineno, orig, p + 1 - orig);
    }

    if( '\"' == *p )
    {
        int hexreq = 0;		/* #hex required */
        int escape = 0;

        for( p++; *p; p++ )
        {
            if( escape )
            {
                escape = 0;

                if( strchr("btnfr\"\\", *p) ) continue;
                if( *p == 'u' ) { hexreq = 4; continue; }
                if( *p == 'U' ) { hexreq = 8; continue; }

                e_syntax_error(ctx, lineno, "bad escape char");
                return 0; /* not reached */
            }

            if( hexreq )
            {
                hexreq--;
                if( strchr("0123456789ABCDEF", *p) )
                    continue;

                e_syntax_error(ctx, lineno, "expect hex char");
                return 0; /* not reached */
            }

            if( *p == '\\' ) { escape = 1; continue; }
            if( *p == '\n' ) break;
            if( *p == '"' ) break;
        }

        if( *p != '"' )
        {
            e_syntax_error(ctx, lineno, "unterminated quote");
            return 0; /* not reached */
        }

        return ret_token(ctx, STRING, lineno, orig, p + 1 - orig);
    }

    for( ; *p && *p != '\n'; p++ )
    {
        int ch = *p;
        if( ch == '.' && dotisspecial ) break;
        if( 'A' <= ch && ch <= 'Z' ) continue;
        if( 'a' <= ch && ch <= 'z' ) continue;
        if( '0' <= ch && ch <= '9' ) continue;
        if( strchr("+-_.:", ch) ) continue;
        break;
    }

    return ret_token(ctx, STRING, lineno, orig, p - orig);
}

static void e_internal_error( context_t* ctx, const char* fline )
{
    cf_log(LOG_ERR, "toml error: internal error (%s)", fline);
    longjmp(ctx->jmp, 1);
}

static void e_syntax_error( context_t* ctx, int lineno, const char* msg )
{
    cf_log(LOG_ERR, "toml error: line %d: %s", lineno, msg);
    longjmp(ctx->jmp, 1);
}

static void e_bad_key_error( context_t* ctx, int lineno )
{
    cf_log(LOG_ERR, "toml error: line %d: bad key", lineno);
    longjmp(ctx->jmp, 1);
}

static void e_key_exists_error( context_t* ctx, token_t keytok )
{
    char buf[100];
    int i;
    for( i = 0; i < keytok.len && i < (int)sizeof(buf) - 1; i++ )
    {
        buf[i] = keytok.ptr[i];
    }

    buf[i] = 0;

    cf_log(LOG_ERR, "toml error: line %d: key %s exists", keytok.lineno, buf);
    longjmp(ctx->jmp, 1);
}
/*******************************************************************
 *  Convert src to raw unescaped utf-8 string.
 *  Returns NULL if error with errmsg in errbuf.
 *******************************************************************/
static char* normalize_string( const char* src, int srclen,int kill_line_ending_backslash )
{
    char* dst = 0;		/* will write to dst[] and return it */
    int   max = 0;		/* max size of dst[] */
    int   off = 0;		/* cur offset in dst[] */
    const char* sp = src;
    const char* sq = src + srclen;
    int ch;

    /* scan forward on src */
    for(;;)
    {
        if( off >=  max - 10 )
            /* have some slack for misc stuff */
            dst = mem_realloc(dst, max += 100);

        /* finished? */
        if( sp >= sq )
            break;

        ch = *sp++;
        if( ch != '\\' )
        {
            // a plain copy suffice
            dst[off++] = ch;
            continue;
        }

        /* ch was backslash. we expect the escape char. */
        if( sp >= sq )
        {
            snprintf(errbuf, errbufsz, "last backslash is invalid");
            mem_free( dst );
            return 0;
        }

        /* if we want to kill line-ending-backslash ... */
        if( kill_line_ending_backslash )
        {
            /* if this is a newline immediately following the backslash ... */
            if( *sp == '\n' || (*sp == '\r' && sp[1] == '\n') )
            {
                /* skip all the following whitespaces */
                sp += strspn(sp, " \t\r\n");
                continue;
            }
        }

        /* get the escaped char */
        ch = *sp++;

        switch( ch )
        {
        case 'u':
        case 'U':
            {
                int i = 0;
                int v = 0;
                int64_t ucs = 0;
                int nhex = (ch == 'u' ? 4 : 8);

                for( i = 0; i < nhex; i++ )
                {
                    if( sp >= sq )
                    {
                        snprintf(errbuf, errbufsz, "\\%c expects %d hex chars", ch, nhex);
                        mem_free(dst);
                        return 0;
                    }

                    ch = *sp++;
                    v = ('0' <= ch && ch <= '9') ? ch - '0': (('A' <= ch && ch <= 'F') ? ch - 'A' + 10 : -1);

                    if( v == -1)
                    {
                        snprintf(errbuf, errbufsz, "invalid hex chars for \\u or \\U");
                        mem_free(dst);
                        return 0;
                    }

                    ucs = ucs * 16 + v;
                }

                int n = toml_ucs_to_utf8(ucs, &dst[off]);

                if( -1 == n)
                {
                    snprintf(errbuf, errbufsz, "illegal ucs code in \\u or \\U");
                    mem_free(dst);
                    return 0;
                }

                off += n;
            }
            continue;

        case 'b': ch = '\b'; break;
        case 't': ch = '\t'; break;
        case 'n': ch = '\n'; break;
        case 'f': ch = '\f'; break;
        case 'r': ch = '\r'; break;
        case '"':  ch = '"'; break;
        case '\\': ch = '\\'; break;
        default:
            snprintf(errbuf, errbufsz, "illegal escape char \\%c", ch);
            mem_free(dst);
            return 0;
        }

        dst[off++] = ch;
    }

    /* Cap with NUL and return it */
    dst[off++] = 0;
    return dst;
}
/*******************************************************************
 * Convert a char in utf8 into UCS, and store it in *ret.
 * Return #bytes consumed or -1 on failure.
 *******************************************************************/
int toml_utf8_to_ucs(const char* orig, int len, int64_t* ret)
{
    const unsigned char* buf = (const unsigned char*) orig;
    unsigned i = *buf++;
    int64_t v;
    
    /* 0x00000000 - 0x0000007F:
       0xxxxxxx
    */
    if( (i >> 7) == 0 )
    {
        if( len < 1 )
            return -1;

        v = i;
        return *ret = v, 1;
    }

    /* 0x00000080 - 0x000007FF:
       110xxxxx 10xxxxxx
    */
    if( (i >> 5) == 0x6 )
    {
        if( len < 2 )
            return -1;

        v = i & 0x1f;
        for( int j = 0; j < 1; j++ )
        {
            i = *buf++;
            if( 0x2 != (i >> 6) )
                return -1;
            v = (v << 6) | (i & 0x3f);
        }

        return *ret = v, (const char*) buf - orig;
    }

    /* 0x00000800 - 0x0000FFFF:
       1110xxxx 10xxxxxx 10xxxxxx
    */
    if( (i >> 4) == 0xE )
    {
        if( len < 3 )
            return -1;

        v = i & 0x0F;
        for (int j = 0; j < 2; j++) {
	    i = *buf++;
	    if (0x2 != (i >> 6)) return -1;
	    v = (v << 6) | (i & 0x3f);
	}
        return *ret = v, (const char*) buf - orig;
    }

    /* 0x00010000 - 0x001FFFFF:
       11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
    */
    if( (i >> 3) == 0x1E )
    {
        if( len < 4 )
            return -1;
        v = i & 0x07;
        for (int j = 0; j < 3; j++) {
	    i = *buf++;
	    if (0x2 != (i >> 6)) return -1;
	    v = (v << 6) | (i & 0x3f);
	}
        return *ret = v, (const char*) buf - orig;
    }
    
    /* 0x00200000 - 0x03FFFFFF:
       111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
    */
    if (0x3E == (i >> 2)) {
	if (len < 5) return -1;
	v = i & 0x03;
	for (int j = 0; j < 4; j++) {
	    i = *buf++;
	    if (0x2 != (i >> 6)) return -1;
	    v = (v << 6) | (i & 0x3f);
	}
	return *ret = v, (const char*) buf - orig;
    }

    /* 0x04000000 - 0x7FFFFFFF:
       1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
    */
    if (0x7e == (i >> 1)) {
	if (len < 6) return -1;
	v = i & 0x01;
	for (int j = 0; j < 5; j++) {
	    i = *buf++;
	    if (0x2 != (i >> 6)) return -1;
	    v = (v << 6) | (i & 0x3f);
	}
	return *ret = v, (const char*) buf - orig;
    }
    return -1;
}
/*******************************************************************
 *  Convert a UCS char to utf8 code, and return it in buf.
 *  Return #bytes used in buf to encode the char, or 
 *  -1 on error.
 *******************************************************************/
int toml_ucs_to_utf8(int64_t code, char buf[6])
{
    /* http://stackoverflow.com/questions/6240055/manually-converting-unicode-codepoints-into-utf-8-and-utf-16 */
    /* The UCS code values 0xd800–0xdfff (UTF-16 surrogates) as well
     * as 0xfffe and 0xffff (UCS noncharacters) should not appear in
     * conforming UTF-8 streams.
     */
    if( 0xd800 <= code && code <= 0xdfff ) return -1;
    if( 0xfffe <= code && code <= 0xffff ) return -1;

    /* 0x00000000 - 0x0000007F:
       0xxxxxxx
    */
    if( code < 0 )
        return -1;

    if( code <= 0x7F )
    {
        buf[0] = (unsigned char) code;
        return 1;
    }

    /* 0x00000080 - 0x000007FF:
       110xxxxx 10xxxxxx
    */
    if( code <= 0x000007FF )
    {
        buf[0] = 0xc0 | (code >> 6);
        buf[1] = 0x80 | (code & 0x3f);
        return 2;
    }

    /* 0x00000800 - 0x0000FFFF:
       1110xxxx 10xxxxxx 10xxxxxx
    */
    if( code <= 0x0000FFFF )
    {
        buf[0] = 0xe0 | (code >> 12);
        buf[1] = 0x80 | ((code >> 6) & 0x3f);
        buf[2] = 0x80 | (code & 0x3f);
        return 3;
    }

    /* 0x00010000 - 0x001FFFFF:
       11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
    */
    if( code <= 0x001FFFFF )
    {
        buf[0] = 0xf0 | (code >> 18);
        buf[1] = 0x80 | ((code >> 12) & 0x3f);
        buf[2] = 0x80 | ((code >> 6) & 0x3f);
        buf[3] = 0x80 | (code & 0x3f);
        return 4;
    }

    /* 0x00200000 - 0x03FFFFFF:
       111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
    */
    if( code <= 0x03FFFFFF )
    {
        buf[0] = 0xf8 | (code >> 24);
        buf[1] = 0x80 | ((code >> 18) & 0x3f);
        buf[2] = 0x80 | ((code >> 12) & 0x3f);
        buf[3] = 0x80 | ((code >> 6) & 0x3f);
        buf[4] = 0x80 | (code & 0x3f);
        return 5;
    }
    
    /* 0x04000000 - 0x7FFFFFFF:
       1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx
    */
    if( code <= 0x7FFFFFFF )
    {
        buf[0] = 0xfc | (code >> 30);
        buf[1] = 0x80 | ((code >> 24) & 0x3f);
        buf[2] = 0x80 | ((code >> 18) & 0x3f);
        buf[3] = 0x80 | ((code >> 12) & 0x3f);
        buf[4] = 0x80 | ((code >> 6) & 0x3f);
        buf[5] = 0x80 | (code & 0x3f);
        return 6;
    }

    return -1;
}
/*******************************************************************
 *  Look up key in tab. Return 0 if not found, or
 *  'v'alue, 'a'rray or 't'able depending on the element
 *******************************************************************/
static int check_key(toml_table_t* tab, const char* key,toml_keyval_t** ret_val, toml_array_t** ret_arr, toml_table_t** ret_tab)
{
    int i;
    void* dummy;

    if( !ret_tab ) ret_tab = (toml_table_t**) &dummy;
    if( !ret_arr ) ret_arr = (toml_array_t**) &dummy;
    if( !ret_val ) ret_val = (toml_keyval_t**) &dummy;

    *ret_tab = 0; *ret_arr = 0; *ret_val = 0;
    
    for( i = 0; i < tab->nkval; i++)
    {
        if (0 == strcmp(key, tab->kval[i]->key))
        {
            *ret_val = tab->kval[i];
            return 'v';
        }
    }

    for( i = 0; i < tab->narr; i++ )
    {
        if( strcmp(key, tab->arr[i]->key) == 0 )
        {
            *ret_arr = tab->arr[i];
            return 'a';
        }
    }

    for( i = 0; i < tab->ntab; i++ )
    {
        if( strcmp(key, tab->tab[i]->key) == 0 )
        {
            *ret_tab = tab->tab[i];
            return 't';
        }
    }

    return 0;
}
/*******************************************************************
 * Create a keyval in the table
 *******************************************************************/
static toml_keyval_t* create_keyval_in_table(context_t* ctx, toml_table_t* tab, token_t keytok)
{
    int n;
    toml_keyval_t** base = NULL;
    /* first, normalize the key to be used for lookup. 
     * remember to free it if we error out. 
     */
    char* newkey = normalize_key(ctx, keytok);

    /* if key exists: error out */
    toml_keyval_t* dest = NULL;

    if( check_key(tab, newkey, 0, 0, 0) )
    {
        mem_free(newkey);
        e_key_exists_error(ctx, keytok);
        return 0; /* not reached */
    }

    /* make a new entry */
    n = tab->nkval;

    base = (toml_keyval_t**) mem_realloc(tab->kval, (n+1) * sizeof(*base));
    base[n] = (toml_keyval_t*) mem_calloc(1, sizeof(*base[n]));
    tab->kval = base;
    dest = tab->kval[tab->nkval++];
    /* save the key in the new value struct */
    dest->key = newkey;
    return dest;
}
/*******************************************************************
 *  Create a table in the table
 *******************************************************************/
static toml_table_t* create_keytable_in_table(context_t* ctx, toml_table_t* tab, token_t keytok)
{
    int n = 0;
    toml_table_t** base = NULL;

    /* first, normalize the key to be used for lookup. 
     * remember to free it if we error out. 
     */
    char* newkey = normalize_key(ctx, keytok);

    /* if key exists: error out */
    toml_table_t* dest = NULL;

    if( check_key(tab, newkey, 0, 0, &dest) )
    {
        mem_free(newkey); /* don't need this anymore */
	
        /* special case: if table exists, but was created implicitly ... */
        if( dest && dest->implicit )
        {
            /* we make it explicit now, and simply return it. */
            dest->implicit = 0;
            return dest;
        }

        e_key_exists_error(ctx, keytok);
        return 0; /* not reached */
    }

    /* create a new table entry */
    n = tab->ntab;
    base = (toml_table_t**) mem_realloc(tab->tab, (n+1) * sizeof(*base));
    base[n] = (toml_table_t*) mem_calloc(1, sizeof(*base[n]));
    tab->tab = base;	            
    dest = tab->tab[tab->ntab++];    
    /* save the key in the new table struct */
    dest->key = newkey;
    return dest;
}
/*******************************************************************
 * Create an array in an array
 *******************************************************************/
static toml_array_t* create_array_in_array( context_t* ctx, toml_array_t* parent )
{
    int n = parent->nelem;
    toml_array_t** base = NULL;

    base = (toml_array_t**) mem_realloc(parent->u.arr, (n+1) * sizeof(*base));
    base[n] = (toml_array_t*) mem_calloc(1, sizeof(*base[n]));
    parent->u.arr = base;

    return parent->u.arr[parent->nelem++];
}

static char* kill_line_ending_backslash(char* str)
{
    /* first round: find (backslash, \n) */
    char* p = str;

    if( !str )
        return 0;

    while( (p = strstr(p, "\\\n")) != NULL )
    {
        char* q = (p + 1);
        q += strspn(q, " \t\r\n");
        memmove(p, q, strlen(q) + 1);
    }

    /* second round: find (backslash, \r, \n) */
    p = str;

    while( (p = strstr(p, "\\\r\n")) != NULL )
    {
        char* q = (p + 1);
        q += strspn(q, " \t\r\n");
        memmove(p, q, strlen(q) + 1);
    }

    return str;
}


typedef struct tabpath_t tabpath_t;
struct tabpath_t {
    int     cnt;
    token_t key[10];
};






/* Raw to boolean */
int cf_toml_rtob(const char* src, int* ret_)
{
    if (!src) return -1;
    int dummy;
    int* ret = ret_ ? ret_ : &dummy;
    
    if (0 == strcmp(src, "true")) {
	*ret = 1;
	return 0;
    }
    if (0 == strcmp(src, "false")) {
	*ret = 0;
	return 0;
    }
    return -1;
}


/* Raw to integer */
int cf_toml_rtoi(const char* src, int64_t* ret_)
{
    if (!src) return -1;
    
    char buf[100];
    char* p = buf;
    char* q = p + sizeof(buf);
    const char* s = src;
    int64_t dummy;
    int64_t* ret = ret_ ? ret_ : &dummy;
    
    if (*s == '+')
	*p++ = *s++;
    else if (*s == '-')
	*p++ = *s++;

    /* if 0 ... */
    if ('0' == s[0]) {
	/* ensure no other digits after it */
	if (s[1]) return -1;
	return *ret = 0, 0;
    }

    /* just strip underscores and pass to strtoll */
    while (*s && p < q) {
	int ch = *s++;
	if (ch == '_') ; else *p++ = ch;
    }
    if (*s || p == q) return -1;
    
    /* cap with NUL */
    *p = 0;

    /* Run strtoll on buf to get the integer */
    char* endp;
    errno = 0;
    *ret = strtoll(buf, &endp, 0);
    return (errno || *endp) ? -1 : 0;
}


int cf_toml_rtod( const char* src, double* ret_ )
{
    char* endp = NULL;
    char buf[100];
    char* p = buf;
    char* q = p + sizeof(buf);
    const char* s = src;
    double dummy;
    double* ret = ret_ ? ret_ : &dummy;

    if( !src )
        return -1;
    
    /* check for special cases */
    if( s[0] == '+' || s[0] == '-' ) *p++ = *s++;
    if( s[0] == '.' ) return -1;	/* no leading zero */
    if( s[0] == '0')
    {
        /* zero must be followed by . or NUL */
        if( s[1] && s[1] != '.' )
            return -1;
    }

    /* just strip underscores and pass to strtod */
    while( *s && p < q )
    {
        int ch = *s++;
        if( ch == '_' ) ; else *p++ = ch;
    }

    if( *s || p == q )
        return -1;

    if( p != buf && p[-1] == '.' )
        return -1; /* no trailing zero */

    /* cap with NUL */
    *p = 0;

    /* Run strtod on buf to get the value */    
    errno = 0;
    *ret = strtod(buf, &endp);
    return (errno || *endp) ? -1 : 0;
}

int cf_toml_rtos( const char* src, char** ret )
{
    int srclen = 0;

    if( !src )
        return -1;

    if( *src != '\'' && *src != '"' )
        return -1;

    *ret = 0;
    srclen = strlen(src);

    if( *src == '\'' )
    {
        if( !strncmp(src, "'''", 3) )
        {
            const char* sp = src + 3;
            const char* sq = src + srclen - 3;
            /* last 3 chars in src must be ''' */
            if( ! (sp <= sq && 0 == strcmp(sq, "'''")) )
                return -1;
	    
            /* skip first new line right after ''' */
            if( *sp == '\n' )
                sp++;
            else if( sp[0] == '\r' && sp[1] == '\n' )
                sp += 2;

            *ret = kill_line_ending_backslash(strndup(sp, sq - sp));
        }
        else
        {
            const char* sp = src + 1;
            const char* sq = src + srclen - 1;
            /* last char in src must be ' */
            if( ! (sp <= sq && *sq == '\'') )
                return -1;
            /* copy from sp to p */
            *ret = strndup(sp, sq - sp);
        }

        return *ret ? 0 : -1;
    }

    const char* sp;
    const char* sq;

    if( !strncmp(src, "\"\"\"", 3) )
    {
        sp = src + 3;
        sq = src + srclen - 3;

        if( ! (sp <= sq && 0 == strcmp(sq, "\"\"\"")) )
            return -1;
	
        /* skip first new line right after """ */
        if( *sp == '\n' )
            sp++;
        else if( sp[0] == '\r' && sp[1] == '\n' )
            sp += 2;
    }
    else
    {
        sp = src + 1;
        sq = src + srclen - 1;
        if( ! (sp <= sq && *sq == '"') )
            return -1;
    }

    char dummy_errbuf[1];
    *ret = normalize_string(sp, sq - sp, 1, // flag kill_line_ending_backslash
                            dummy_errbuf, sizeof(dummy_errbuf));
    return *ret ? 0 : -1;
}

