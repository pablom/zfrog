// cf_file.h

#ifndef __CF_FILE_H_
#define __CF_FILE_H_

#include <string.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct
{
    FILE *fp;
    const unsigned char *key;
    unsigned char *iv;
    int keysz;
    int has_header;
} CF_FILE;

CF_FILE *cf_fopen(const char *path, const char *mode);
void cf_fkey(unsigned char key[], CF_FILE *fp);
size_t cf_fread(void *ptr, size_t size, size_t nmemb, CF_FILE *fp);
size_t cf_fwrite(const void *ptr, size_t size, size_t nmemb, CF_FILE *fp);
size_t cf_fsize(CF_FILE *fp);
int cf_fclose(CF_FILE *fp);

#define afseek(f,o,w) \
    fseek(f->fp, o, w)

#define aftell(f) \
    ftell(f->fp)

#define arewind(f) \
    rewind(f->fp)

#if defined(__cplusplus)
}
#endif

#endif /* __CF_FILE_H_ */
