// cf_ini.h

#ifndef __CF_INI_H_
#define __CF_INI_H_

#if defined(__cplusplus)
extern "C" {
#endif


/************************************************************************
 *  Typedef for prototype of handler function
 ************************************************************************/
typedef int (*ini_handler)(void* user, const char* section, const char* name, const char* value,int lineno);

/***********************************************************************
 *  Typedef for prototype of fgets-style reader function
************************************************************************/
typedef char* (*ini_reader)(char* str, int num, void* stream);

/*********************************************************************************
 *  Parse given INI-style file. May have [section]s, name=value pairs
 *  (whitespace stripped), and comments starting with ';' (semicolon). Section
 *  is "" if name=value pair parsed before any section heading. name:value
 *  pairs are also supported as a concession to Python's configparser.
 *
 *  For each name=value pair parsed, call handler function with given user
 *  pointer as well as section, name, and value (data only valid for duration
 *  of handler call). Handler should return nonzero on success, zero on error.
 *
 *  Returns 0 on success, line number of first error on parse error (doesn't
 *  stop on first error), -1 on file open error, or -2 on memory allocation
 *  error (only when INI_USE_STACK is zero)
 **********************************************************************************/
int cf_ini_parse(const char* filename, ini_handler handler, void* user);

/********************************************************************************
 *  Same as ini_parse(), but takes a FILE* instead of filename. This doesn't
 *  close the file when it's finished -- the caller must do that
*********************************************************************************/
int cf_ini_parse_file(FILE* file, ini_handler handler, void* user);

/*********************************************************************************
 *  Same as ini_parse(), but takes an ini_reader function pointer instead of
 *  filename. Used for implementing custom or string-based I/O
 *********************************************************************************/
int cf_ini_parse_stream(ini_reader reader, void* stream, ini_handler handler,void* user);

#if defined(__cplusplus)
}
#endif

#endif /* __CF_INI_H_ */
