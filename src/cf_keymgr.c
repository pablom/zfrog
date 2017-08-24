// cf_keymgr.c

#include <sys/param.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "cf_pkcs11.h"
#include "zfrog.h"

#define RAND_TMP_FILE		"rnd.tmp"
#define RAND_POLL_INTERVAL	(1800 * 1000)
#define RAND_FILE_SIZE		1024

struct key
{
    EVP_PKEY *pkey;
    struct cf_domain *dom;
    void* p11_key;
    TAILQ_ENTRY(key) list;
};

char *rand_file = NULL;
static TAILQ_HEAD(, key)	keys;
extern volatile sig_atomic_t sig_recv;
static int initialized = 0;

static void	keymgr_load_randfile(void);
static void	keymgr_save_randfile(void);
static void	keymgr_entropy_request(struct cf_msg *, const void *);

static void	keymgr_load_privatekey(struct cf_domain *);
static void	keymgr_msg_recv(struct cf_msg *, const void *);
static void	keymgr_rsa_encrypt(struct cf_msg *, const void *, struct key *);
static void	keymgr_ecdsa_sign(struct cf_msg *, const void *, struct key *);
static void keymgr_pkcs11_rsa_encrypt(struct cf_msg *, const void *, struct key *);



void cf_keymgr_run( void )
{
    int quit = 0;  
    uint64_t now, last_seed = 0;

    if( rand_file != NULL )
    {
        keymgr_load_randfile();
        keymgr_save_randfile();
    }
    else {
        cf_log(LOG_WARNING, "no rand_file location specified");
    }

	initialized = 1;
    /* Init key's list */
    TAILQ_INIT( &keys );

    /* Delete all listener objects */
    cf_listener_cleanup();
    /* Unload all shared libraries */
    cf_module_cleanup();

    /* Try to load PKCS11 module */
    cf_init_pkcs11_module();

    cf_domain_callback( keymgr_load_privatekey );
    cf_worker_privdrop();

	net_init();
    connection_init();
    cf_platform_event_init();

    cf_msg_worker_init();
    cf_msg_register(CF_MSG_KEYMGR_REQ, keymgr_msg_recv);
    cf_msg_register(CF_MSG_ENTROPY_REQ, keymgr_entropy_request);

    cf_log(LOG_NOTICE, "key manager (%d) started", getpid());

    while( quit != 1 )
    {
        now = cf_time_ms();

        if( (now - last_seed) > RAND_POLL_INTERVAL )
        {
            RAND_poll();
            last_seed = now;
        }

        if( sig_recv != 0 )
        {
            switch( sig_recv )
            {
			case SIGQUIT:
			case SIGINT:
			case SIGTERM:				
                quit = 1;
				break;
			default:
				break;
			}
			sig_recv = 0;
		}

        cf_platform_event_wait(1000);
        cf_connection_prune( CF_CONNECTION_PRUNE_DISCONNECT );
	}

    cf_keymgr_cleanup();
    cf_platform_event_cleanup();
    connection_cleanup();
	net_cleanup();
}

void cf_keymgr_cleanup(void)
{
    struct key	*key, *next;

    cf_log(LOG_NOTICE, "cleaning up keys");

    if( initialized == 0 )
		return;

    for( key = TAILQ_FIRST(&keys); key != NULL; key = next )
    {
		next = TAILQ_NEXT(key, list);
		TAILQ_REMOVE(&keys, key, list);

        /* Delete private key structure */
        if( key->pkey )
            EVP_PKEY_free( key->pkey );

		mem_free(key);
	}
}

static void keymgr_load_privatekey( struct cf_domain *dom )
{
    FILE *fp = NULL;
    struct key *key = NULL;
    void* p11_key = NULL;

    if( dom->certkey == NULL )
        return;

    if( (fp = fopen(dom->certkey, "r")) == NULL )
    {
        if( (p11_key = cf_pkcs11_load_privatekey(dom->certkey)) == NULL )
            cf_fatal("failed to open private key: %s", dom->certkey);
    }

    key = mem_malloc( sizeof(*key) );
    key->dom = dom;
    key->p11_key = NULL;

    if( p11_key == NULL )
    {
        if( (key->pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL )
            cf_fatal("PEM_read_PrivateKey: %s", ssl_errno_s);

        fclose( fp );
    }
    else
        key->p11_key = p11_key; /* set PKCS11 private key */

    mem_free( dom->certkey );
    dom->certkey = NULL;

	TAILQ_INSERT_TAIL(&keys, key, list);
}

static void keymgr_msg_recv( struct cf_msg *msg, const void *data )
{
    const struct cf_keyreq *req = NULL;
    struct key *key = NULL;

    if( msg->length < sizeof(*req) )
		return;

    req = (const struct cf_keyreq *)data;
    if( msg->length != (sizeof(*req) + req->data_len) )
		return;

	key = NULL;
    TAILQ_FOREACH(key, &keys, list)
    {
        if( !strncmp(key->dom->domain, req->domain, req->domain_len) )
			break;
	}

    if( key == NULL )
		return;


    if( key->p11_key )
        keymgr_pkcs11_rsa_encrypt(msg, data, key);
    else
    {
        switch( EVP_PKEY_id(key->pkey) )
        {
        case EVP_PKEY_RSA:
            keymgr_rsa_encrypt(msg, data, key);
            break;
        case EVP_PKEY_EC:
            keymgr_ecdsa_sign(msg, data, key);
            break;
        default:
            break;
        }
    }
}

static void keymgr_pkcs11_rsa_encrypt( struct cf_msg *msg, const void *data, struct key *key )
{
    int ret;
    const struct cf_keyreq *req = NULL;
    size_t	keylen;
    uint8_t buf[1024];

    req = (const struct cf_keyreq *)data;

    keylen = 256;

    if( req->data_len > keylen || keylen > sizeof(buf) )
        return;

    ret = cf_pkcs11_private_encrypt( key->p11_key, req->data, req->data_len, buf );

    cf_msg_send(msg->src, CF_MSG_KEYMGR_RESP, buf, ret);
}

static void keymgr_rsa_encrypt(struct cf_msg *msg, const void *data, struct key *key)
{
    int	ret;
    RSA	*rsa = NULL;
    size_t keylen = 0;
    uint8_t	buf[1024];

    const struct cf_keyreq *req = (const struct cf_keyreq *)data;

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    rsa = EVP_PKEY_get0_RSA(key->pkey);
#else
    rsa = key->pkey->pkey.rsa;
#endif

    keylen = RSA_size(rsa);

    if( req->data_len > keylen || keylen > sizeof(buf) )
        return;

    ret = RSA_private_encrypt(req->data_len, req->data, buf, rsa, req->padding );
    if( ret != RSA_size(rsa) )
        return;

    cf_msg_send(msg->src, CF_MSG_KEYMGR_RESP, buf, ret);
}

static void keymgr_ecdsa_sign(struct cf_msg *msg, const void *data, struct key *key)
{
    size_t len;
    EC_KEY *ec = NULL;
    unsigned int siglen;
    uint8_t sig[1024];

    const struct cf_keyreq *req = (const struct cf_keyreq *)data;

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    ec = EVP_PKEY_get0_EC_KEY(key->pkey);
#else
    ec = key->pkey->pkey.ec;
#endif

    len = ECDSA_size(ec);

    if( req->data_len > len || len > sizeof(sig) )
        return;

    if( ECDSA_sign(EVP_PKEY_NONE, req->data, req->data_len, sig, &siglen, ec) == 0 )
        return;

    if( siglen > sizeof(sig) )
		return;

    cf_msg_send(msg->src, CF_MSG_KEYMGR_RESP, sig, siglen);
}

static void keymgr_entropy_request( struct cf_msg *msg, const void *data )
{
    uint8_t	buf[RAND_FILE_SIZE];

    if( RAND_bytes(buf, sizeof(buf)) != 1 )
    {
        cf_log(LOG_WARNING, "failed to generate entropy for worker %u: %s", msg->src, ssl_errno_s);
        return;
    }

    /* No cleanse, this stuff is leaked in the kernel path anyway */
    cf_msg_send(msg->src, CF_MSG_ENTROPY_RESP, buf, sizeof(buf));
}

static void keymgr_load_randfile(void)
{
    int	fd;
    struct stat	st;
    ssize_t ret;
    size_t total;
    uint8_t	buf[RAND_FILE_SIZE];

    if( rand_file == NULL )
        return;

    if ((fd = open(rand_file, O_RDONLY)) == -1)
        cf_fatal("open(%s): %s", rand_file, errno_s);

    if (fstat(fd, &st) == -1)
        cf_fatal("stat(%s): %s", rand_file, errno_s);
    if (!S_ISREG(st.st_mode))
        cf_fatal("%s is not a file", rand_file);
    if (st.st_size != RAND_FILE_SIZE)
        cf_fatal("%s has an invalid size", rand_file);

    total = 0;

    while( total != RAND_FILE_SIZE )
    {
        ret = read(fd, buf, sizeof(buf));
        if (ret == 0)
            cf_fatal("EOF on %s", rand_file);

        if( ret == -1 )
        {
            if( errno == EINTR )
                continue;
            cf_fatal("read(%s): %s", rand_file, errno_s);
        }

        total += (size_t)ret;
        RAND_seed(buf, (int)ret);
        OPENSSL_cleanse(buf, sizeof(buf));
    }

    close( fd );

    if( unlink(rand_file) == -1 )
        cf_log(LOG_WARNING, "failed to unlink %s: %s", rand_file, errno_s);
}

static void keymgr_save_randfile(void)
{
    int	fd;
    struct stat	st;
    ssize_t ret;
    uint8_t	buf[RAND_FILE_SIZE];

    if( rand_file == NULL )
        return;

    if( stat(RAND_TMP_FILE, &st) != -1 )
    {
        cf_log(LOG_WARNING, "removing stale %s file", RAND_TMP_FILE);
        unlink(RAND_TMP_FILE);
    }

    if( RAND_bytes(buf, sizeof(buf)) != 1 )
    {
        cf_log(LOG_WARNING, "RAND_bytes: %s", ssl_errno_s);
        goto cleanup;
    }

    if( (fd = open(RAND_TMP_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0400)) == -1 )
    {
        cf_log(LOG_WARNING, "failed to open %s: %s - random data not written", RAND_TMP_FILE, errno_s);
        goto cleanup;
    }

    ret = write(fd, buf, sizeof(buf));
    if( ret == -1 || (size_t)ret != sizeof(buf) )
    {
        cf_log(LOG_WARNING, "failed to write random data");
        close(fd);
        unlink(RAND_TMP_FILE);
        goto cleanup;
    }

    if( close(fd) == -1 )
        cf_log(LOG_WARNING, "close(%s): %s", RAND_TMP_FILE, errno_s);

    if( rename(RAND_TMP_FILE, rand_file) == -1 )
    {
        cf_log(LOG_WARNING, "rename(%s, %s): %s", RAND_TMP_FILE, rand_file, errno_s);
        unlink(rand_file);
        unlink(RAND_TMP_FILE);
    }

cleanup:
    OPENSSL_cleanse(buf, sizeof(buf));
}

