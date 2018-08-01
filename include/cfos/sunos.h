// sunos.h

#ifndef __SUNOS__H_
#define __SUNOS__H_

#include <inttypes.h>
#include <sys/port.h>
#include <port.h>
#include <atomic.h>
#include <strings.h>


#define __sync_bool_compare_and_swap(p, o, n) atomic_cas_uint((volatile uint_t *)p, o, n)

/* Macros for min/max  */
#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))


#ifndef INET_ADDRSTRLEN
    #define INET_ADDRSTRLEN    16
#endif

#ifndef INET6_ADDRSTRLEN
    #define INET6_ADDRSTRLEN   46
#endif


char* strsep(char** stringp, const char* delim);
int vasprintf(char **ptr, const char *format, va_list ap);

#endif /* __SUNOS__H_ */
