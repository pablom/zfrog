// cf_redis_cmd.c

#include <ctype.h>
#include "zfrog.h"
#include "cf_redis.h"

/* Forward function declaration */
static uint32_t countDigits(uint64_t);
static size_t bulklen(size_t);
static int redis_vformat_command( char**, const char*, va_list);

/****************************************************************************
 *  Return the number of digits of 'v' when converted to string in radix 10
 ***************************************************************************/
static uint32_t countDigits( uint64_t v )
{
    uint32_t result = 1;

    for(;;)
    {
        if( v < 10 ) return result;
        if( v < 100 ) return result + 1;
        if( v < 1000 ) return result + 2;
        if( v < 10000 ) return result + 3;
        v /= 10000U;
        result += 4;
    }
}
/*************************************************************************
*  Helper that calculates the bulk length given a certain string length
*************************************************************************/
static size_t bulklen( size_t len )
{
    return 1 + countDigits(len) + 2 + len + 2;
}
/************************************************************************
*  Helper function create Redis format command
************************************************************************/
static int redis_vformat_command( char **target, const char *format, va_list ap )
{
    int error_type = 0; /* 0 = no error; -1 = memory error; -2 = format error */
    int touched = 0;    /* was the current argument touched? */
    int argc = 0;       /* Total number of arguments */

    const char *c = format;

    struct cf_buf curarg; /* Temporary buffer for current argument */
    struct cf_buf args;   /* Temporary buffer for all arguments in final commands */

    /* Init buffer for current argument */
    cf_buf_init( &curarg, 256);
    /* Init buffer for all incoming arguments */
    cf_buf_init( &args, 256);

    /* Init response cmd */
    *target = NULL;

    while( *c != '\0' && error_type == 0 )
    {
        if( *c != '%' || c[1] == '\0' )
        {
            if( *c == ' ' )
            {
                if( touched )
                {
                    argc++; /* Increment total number of arguments */
                    /* Add current argument to args buffer */
                    cf_buf_appendf( &args, "$%zu\r\n", curarg.offset );
                    cf_buf_append( &args, curarg.data, curarg.offset );
                    cf_buf_append( &args, "\r\n", 2 );
                    /* Reset current argument buffer */
                    cf_buf_reset( &curarg );
                }
            }
            else
            {
                cf_buf_append( &curarg, c, 1);
                touched = 1;
            }
        }
        else
        {
            char *arg = NULL;
            size_t size = 0;

            switch( c[1] )
            {
            case 's':
                arg = va_arg(ap,char*);
                size = strlen(arg);
                if( size > 0 )
                    cf_buf_append( &curarg, arg, size );
                break;
            case 'b':
                arg = va_arg(ap,char*);
                size = va_arg(ap,size_t);
                if( size > 0 )
                    cf_buf_append( &curarg, arg, size );
                break;
            case '%':
                cf_buf_append( &curarg, "%", 1 );
                break;
            default:
                /* Try to detect printf format */
                {
                    static const char intfmts[] = "diouxX";
                    static const char flags[] = "#0-+ ";
                    char _format[16];
                    const char *_p = c+1;
                    size_t _l = 0;
                    va_list _cpy;

                    /* Flags */
                    while( *_p != '\0' && strchr(flags,*_p) != NULL ) _p++;

                    /* Field width */
                    while( *_p != '\0' && isdigit(*_p) ) _p++;

                    /* Precision */
                    if( *_p == '.' )
                    {
                        _p++;
                        while (*_p != '\0' && isdigit(*_p)) _p++;
                    }

                    /* Copy va_list before consuming with va_arg */
                    va_copy(_cpy,ap);

                    /* Integer conversion (without modifiers) */
                    if( strchr(intfmts,*_p) != NULL )
                        va_arg(ap,int);
                    /* Double conversion (without modifiers) */
                    else if( strchr("eEfFgGaA",*_p) != NULL )
                        va_arg(ap,double);
                    else if( _p[0] == 'h' && _p[1] == 'h' ) /* Size: char */
                    {
                        _p += 2;

                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                            va_arg(ap,int); /* char gets promoted to int */
                        else
                            error_type = -2;
                    }
                    else if( _p[0] == 'h' ) /* Size: short */
                    {
                        _p += 1;
                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                            va_arg(ap,int); /* short gets promoted to int */
                        else
                            error_type = -2;
                    }
                    else if( _p[0] == 'l' && _p[1] == 'l' ) /* Size: long long */
                    {
                        _p += 2;
                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                            va_arg(ap,long long);
                        else
                            error_type = -2;
                    }
                    else if( _p[0] == 'l' ) /* Size: long */
                    {
                        _p += 1;
                        if( *_p != '\0' && strchr(intfmts,*_p) != NULL )
                            va_arg(ap,long);
                        else
                            error_type = -2;
                    }

                    if( error_type == 0 )
                    {
                        _l = (_p + 1)-c;
                        if( _l < sizeof(_format) - 2 )
                        {
                            memcpy(_format,c,_l);
                            _format[_l] = '\0';
                            cf_buf_appendv( &curarg,_format,_cpy );
                            /* Update current position (note: outer blocks
                             * increment c twice so compensate here) */
                            c = _p - 1;
                        }
                    }

                    va_end(_cpy);
                    break;
                }
            }

            touched = 1;
            c++;
        }

        c++;
    }

    if( error_type == 0 && ( argc > 0 || touched ) )
    {
        int pos = 0;
        char *cmd = NULL;   /* final command */
        int totlen = args.offset; /* Set current data length */

        /* Add the last argument if needed */
        if( touched )
        {
            /* Increment total length */
            totlen += bulklen( curarg.offset );
            argc++; /* Increment total number of arguments */

            /* Add current argument to args buffer */
            cf_buf_appendf( &args, "$%zu\r\n", curarg.offset );
            cf_buf_append( &args, curarg.data, curarg.offset );
            cf_buf_append( &args, "\r\n", 2 );
        }

        /* Add bytes needed to hold multi bulk count */
        totlen += 1 + countDigits(argc) + 2;
        /* Build the command at protocol level */
        cmd = mem_malloc( totlen + 1 );
        pos = sprintf(cmd,"*%d\r\n",argc);
        /* Set data to final command */
        memcpy( cmd + pos, args.data, args.offset );
        cmd[totlen] = '\0'; /* Set end of string */

        /* Set final command */
        *target = cmd;

        /* Set return code as total cmd length */
        error_type = totlen;
    }

    /* Clean up temporary buffers */
    cf_buf_cleanup( &curarg );
    cf_buf_cleanup( &args );

    return error_type;
}
/************************************************************************
 *  Helper function to create Redis command
 ************************************************************************/
int cf_redis_format_command( char **target, const char *format, ... )
{
    va_list ap;
    int len = -1;
    va_start(ap,format);
    len = redis_vformat_command(target, format, ap);
    va_end(ap);

    /* The API says "-1" means bad result, but we now also return "-2" in some
     * cases.  Force the return value to always be -1. */
    if( len < 0 )
        len = -1;

    return len;
}



