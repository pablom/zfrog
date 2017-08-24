// cf_file.c

#include "zfrog.h"
#include "cf_file.h"

#include <openssl/evp.h>
#include <openssl/aes.h>

#define FILE_MAGIC 0xfe8a

struct cryptfile
{
    uint16_t    magic;
    uint16_t    keysz;
    uint8_t     iv[32];
};

static void file_crypt(int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec);


static int read_header(CF_FILE *file)
{
    static struct cryptfile hdr;

    /* Set pointer to offset 0 */
    rewind(file->fp);

    memset(&hdr, '\0', sizeof(struct cryptfile));
    fread(&hdr, sizeof(struct cryptfile), 1, file->fp);

    if( hdr.magic != FILE_MAGIC )
        return -1;

    file->iv = hdr.iv;
    file->keysz = hdr.keysz;
    file->has_header = 1;

    return 0;
}

static void write_header(CF_FILE *file)
{
    static struct cryptfile hdr;

    memset(&hdr, '\0', sizeof(struct cryptfile));
    random_string(hdr.iv, 16, 1);

    hdr.magic = FILE_MAGIC;
    hdr.keysz = 128;

    /* Set pointer to offset 0 */
    rewind(file->fp);

    fwrite(&hdr, sizeof(struct cryptfile), 1, file->fp);

    file->iv = hdr.iv;
    file->keysz = hdr.keysz;
    file->has_header = 1;
}

CF_FILE* cf_fopen( const char *path, const char *mode )
{
    CF_FILE *file = mem_malloc(sizeof(CF_FILE));
    file->key = NULL;
    file->iv = NULL;
    file->has_header = 0;

    if( !(file->fp = fopen(path, mode)) )
    {
        mem_free(file);
        return NULL;
    }

    return file;
}

void cf_fkey( unsigned char key[], CF_FILE *file )
{
    file->key = key;
}

size_t cf_fread(void *ptr, size_t size, size_t nmemb, CF_FILE* file)
{
    if( !file->has_header )
    {
        if( read_header(file) < 0 )
            return 0;
    }

    return fread(ptr, size, nmemb, file->fp);
}

size_t cf_fwrite( const void *ptr, size_t size, size_t nmemb, CF_FILE *file )
{
    if( !file->has_header )
        write_header( file );

    return fwrite(ptr, size * nmemb, nmemb, file->fp);
}

size_t cf_fsize( CF_FILE *file )
{
    size_t filesz;
    fseek(file->fp, 0, SEEK_END);
    filesz = ftell(file->fp);
    fseek(file->fp, 0, SEEK_SET);

    if( filesz < 1 )
        return 0;

    return filesz - sizeof(struct cryptfile);
}

int cf_fclose( CF_FILE *file )
{
    int ret = fclose(file->fp);
    mem_free(file);
    return ret;
}

static void file_crypt(int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec)
{
    const unsigned int bufsize = 4096;
    unsigned char *read_buf = malloc(bufsize);

    int out_len;
    EVP_CIPHER_CTX ctx;

    EVP_CipherInit(&ctx, EVP_aes_256_cbc(), ckey, ivec, should_encrypt);
    unsigned int blocksize = EVP_CIPHER_CTX_block_size(&ctx);
    unsigned char *cipher_buf = malloc(bufsize + blocksize);

    while( 1 )
    {
        unsigned int numRead = fread(read_buf, sizeof(unsigned char), bufsize, ifp);
        EVP_CipherUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead);
        fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
        if( numRead < bufsize )
            break;
    }

    /* Now cipher the final block and write it out */
    EVP_CipherFinal(&ctx, cipher_buf, &out_len);
    fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

    /* Free memory */
    free( cipher_buf );
    free(read_buf);
}
