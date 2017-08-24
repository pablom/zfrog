#include <sys/types.h>
#include <linux/types.h>
#include <zlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>

extern int compress2gzip(uint8_t *dest, unsigned long *destLen,
                        const uint8_t *source, unsigned long sourceLen, int level)
{
        z_stream stream;
        int err;

        stream.next_in = (Bytef*)source;
        stream.avail_in = (uInt)sourceLen;

        stream.next_out = dest;
        stream.avail_out = (uInt)*destLen;
        if ((uLong)stream.avail_out != *destLen) return Z_BUF_ERROR;

        stream.zalloc = (alloc_func)0;
        stream.zfree = (free_func)0;
        stream.opaque = (voidpf)0;

        err = deflateInit2(&stream,
                           level, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        if (err != Z_OK) return err;

        err = deflate(&stream, Z_FINISH);
        if (err != Z_STREAM_END) {
                deflateEnd(&stream);
                return err == Z_OK ? Z_BUF_ERROR : err;
        }
        *destLen = stream.total_out;

        err = deflateEnd(&stream);
        return err;
}

