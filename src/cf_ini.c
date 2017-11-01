// cf_ini.c

#include "zfrog.h"
#include "cf_ini.h"
#include <ctype.h>


#define INI_MAX_LINE    200
#define MAX_SECTION     50
#define MAX_NAME        50

#define HANDLER(u, s, n, v) handler(u, s, n, v, lineno)

/************************************************************************
* Return pointer to first char (of chars) or inline comment in given
* string, or pointer to null at end of string if neither found.
* Inline comment must
************************************************************************/
static char* find_chars_or_comment( char *s, const char *chars )
{
    int was_space = 0;
    while( *s && (!chars || !strchr(chars, *s)) && !(was_space && strchr(";", *s)) )
    {
        was_space = isspace((unsigned char)(*s));
        s++;
    }

    return (char *)s;
}
/************************************************************************
 *  Parse stream as input .ini configuration data
 ************************************************************************/
int cf_ini_parse_stream( ini_reader reader, void *stream, ini_handler handler, void *user )
{
    char *line = NULL;
    char section[MAX_SECTION] = "";
    char prev_name[MAX_NAME] = "";

    char *start = NULL;
    char *end = NULL;
    char *name = NULL;
    char *value = NULL;
    int lineno = 0;
    int error = 0;

    if( !(line = (char *)mem_malloc(INI_MAX_LINE)) ) {
        return -2;
    }

    /* Scan through stream line by line */
    while( reader(line, INI_MAX_LINE, stream) != NULL )
    {
        lineno++;

        start = line;

        if (lineno == 1 && (unsigned char)start[0] == 0xEF &&
                           (unsigned char)start[1] == 0xBB &&
                           (unsigned char)start[2] == 0xBF) {
            start += 3;
        }

        start = lskip(rstrip(start));

        if( *start == ';' || *start == '#' )
        {
            /* Per Python configparser, allow both ; and # comments at the
               start of a line */
        }
        else if( *prev_name && *start && start > line )
        {
            /* Non-blank line with leading whitespace, treat as continuation
               of previous name's value (as per Python configparser). */
            if( !HANDLER(user, section, prev_name, start) && !error )
                error = lineno;
        }
        else if( *start == '[' )
        {
            /* A "[section]" line */
            end = find_chars_or_comment(start + 1, "]");
            if( *end == ']' )
            {
                *end = '\0';
                cf_strncpy0(section, start + 1, sizeof(section));
                *prev_name = '\0';
            }
            else if( !error )
            {
                /* No ']' found on section line */
                error = lineno;
            }
        }
        else if( *start )
        {
            /* Not a comment, must be a name[=:]value pair */
            end = find_chars_or_comment(start, "=:");
            if( *end == '=' || *end == ':' )
            {
                *end = '\0';
                name = rstrip(start);
                value = end + 1;
                end = find_chars_or_comment(value, NULL);
                if( *end )
                    *end = '\0';
                value = lskip(value);
                rstrip(value);

                /* Valid name[=:]value pair found, call handler */
                cf_strncpy0(prev_name, name, sizeof(prev_name));
                if( !HANDLER(user, section, name, value) && !error )
                    error = lineno;
            }
            else if( !error )
            {
                /* No '=' or ':' found on name[=:]value line */
                error = lineno;
            }
        }

        /* Stop parsing on first error */
        if( error )
            break;
    }

    mem_free(line);

    return error;
}
/************************************************************************
 *  Parse input .ini configuration file
 ************************************************************************/
int cf_ini_parse_file( FILE *file, ini_handler handler, void *user)
{
    return cf_ini_parse_stream((ini_reader)fgets, file, handler, user);
}
/************************************************************************
 *  Parse input .ini configuration file
 ************************************************************************/
int cf_ini_parse( const char *filename, ini_handler handler, void *user )
{
    FILE *file = NULL;
    int error;

    if( !(file = fopen(filename, "r")) )
        return -1;

    error = ini_parse_file(file, handler, user);
    /* Close file */
    fclose( file );

    return error;
}
