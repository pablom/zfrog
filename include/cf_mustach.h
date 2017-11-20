// cf_mustach.h

/* Mustache template parser */

#ifndef __CF_MUSTACH_H_
#define __CF_MUSTACH_H_


#define CF_MUSTACH_OK                       0
#define CF_MUSTACH_ERROR_SYSTEM            -1
#define CF_MUSTACH_ERROR_UNEXPECTED_END    -2
#define CF_MUSTACH_ERROR_EMPTY_TAG         -3
#define CF_MUSTACH_ERROR_TAG_TOO_LONG      -4
#define CF_MUSTACH_ERROR_BAD_SEPARATORS    -5
#define CF_MUSTACH_ERROR_TOO_DEPTH         -6
#define CF_MUSTACH_ERROR_CLOSING           -7
#define CF_MUSTACH_ERROR_BAD_UNESCAPE_TAG  -8

#if defined(__cplusplus)
extern "C" {
#endif

struct cf_mustach_itf
{
    int (*start)(void *closure);
    int (*put)(void *closure, const char *name, int escape, FILE *file);
    int (*enter)(void *closure, const char *name);
    int (*next)(void *closure);
    int (*leave)(void *closure);
};

int cf_fmustach(const char *template, struct cf_mustach_itf *itf, void *closure, FILE *file);
int cf_fdmustach(const char *template, struct cf_mustach_itf *itf, void *closure, int fd);
int cf_mustach(const char *template, struct cf_mustach_itf *itf, void *closure, char **result, size_t *size);


#if defined(__cplusplus)
}
#endif


#endif /* __CF_MUSTACH_H_ */
