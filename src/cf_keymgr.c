// cf_keymgr.c

/*********************************************************************************
 *  The zFrog keymgr process is responsible for managing certificates and their
 *  matching private keys.
 *
 *  It is the only process in zFrog that holds the private keys (the workers
 *  do not have a copy of them in memory).
 *
 *  When a worker requires the private key for signing it will send a message
 *  to the keymgr with the to-be-signed data (CF_MSG_KEYMGR_REQ). The keymgr
 *  will perform the signing and respond with a CF_MSG_KEYMGR_RESP message.
 *
 *  The keymgr can transparently reload the private keys and certificates
 *  for a configured domain when it receives a SIGUSR1. It it reloads them
 *  it will send the newly loaded certificate chains to the worker processes
 *  which will update their TLS contexts accordingly.
*********************************************************************************/


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
    EVP_PKEY          *pkey;
    struct cf_domain  *dom;
    void              *p11_key;
    TAILQ_ENTRY(key)  list;
};

char* rand_file = NULL;
static TAILQ_HEAD(, key)	keys;
extern volatile sig_atomic_t sig_recv;

/* Forward function declarations */
static void keymgr_reload(void);
static void	keymgr_load_randfile(void);
static void	keymgr_save_randfile(void);
static void	keymgr_load_privatekey(struct cf_domain*);
static void	keymgr_msg_recv(struct cf_msg*, const void*);
static void	keymgr_entropy_request(struct cf_msg*, const void*);
static void	keymgr_certificate_request(struct cf_msg*, const void*);
static void	keymgr_submit_certificates(struct cf_domain*, uint16_t);
static void	keymgr_submit_file(uint8_t, struct cf_domain*, const char*, uint16_t, int);
static void	keymgr_rsa_encrypt(struct cf_msg*, const void*, struct key*);
static void	keymgr_ecdsa_sign(struct cf_msg*, const void*, struct key*);
static void keymgr_pkcs11_rsa_encrypt(struct cf_msg*, const void*, struct key*);

/****************************************************************
 *  Key manager worker main entry function
 ****************************************************************/
void cf_keymgr_run( void )
{
    int quit = 0;  
    uint64_t now, last_seed = 0;

    /* Init key's list */
    TAILQ_INIT(&keys);

    /* Delete all listener objects */
    cf_listener_cleanup();
    /* Unload all shared libraries */
    cf_module_cleanup();

    /* Network init */
    net_init();
    cf_connection_init();
    cf_platform_event_init();
    cf_msg_worker_init();
    cf_msg_register(CF_MSG_KEYMGR_REQ, keymgr_msg_recv);
    cf_msg_register(CF_MSG_ENTROPY_REQ, keymgr_entropy_request);
    cf_msg_register(CF_MSG_CERTIFICATE_REQ, keymgr_certificate_request);

    /* Drop current user */
    cf_worker_privdrop( server.keymgr_runas_user, server.keymgr_root_path );

    /* Try to load PKCS11 module */
    cf_init_pkcs11_module();

    if( rand_file != NULL )
    {
        keymgr_load_randfile();
        keymgr_save_randfile();
    }
    else {
        cf_log(LOG_WARNING, "no rand_file location specified");
    }

    /* Reload (init) private keys */
    keymgr_reload();

    /* Initialize random pool */
    RAND_poll();

#if defined(__OpenBSD__)
    if( pledge("stdio rpath", NULL) == -1 )
        cf_fatal("failed to pledge keymgr process");
#endif

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
            case SIGUSR1:
                keymgr_reload();
                break;
			default:
				break;
			}
			sig_recv = 0;
		}

        cf_platform_event_wait(1000);
        cf_connection_prune( CF_CONNECTION_PRUNE_DISCONNECT );
	}

    cf_keymgr_cleanup(1);
    cf_platform_event_cleanup();
    cf_connection_cleanup();
	net_cleanup();
}
/****************************************************************
 *  Key manager cleanup function
 ****************************************************************/
void cf_keymgr_cleanup( int final )
{
    struct key	*key, *next;

    if( final )
        cf_log(LOG_NOTICE, "cleaning up keys");

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
/****************************************************************
 *  Key manager reload cartificates and keys function
 ****************************************************************/
static void keymgr_reload(void)
{
    struct cf_domain* dom = NULL;

    cf_log(LOG_INFO, "(re)loading certificates and keys");

    /* Cleanup current loaded keys */
    cf_keymgr_cleanup(0);
    /* Reinit key's list */
    TAILQ_INIT( &keys );

    cf_domain_callback(keymgr_load_privatekey);

    /* can't use cf_domain_callback() due to dst parameter */
    TAILQ_FOREACH(dom, &server.domains, list)
        keymgr_submit_certificates(dom, CF_MSG_WORKER_ALL);
}
/****************************************************************
 *  Helper function to load private key for domain
 ****************************************************************/
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

    //mem_free( dom->certkey );
    //dom->certkey = NULL;

	TAILQ_INSERT_TAIL(&keys, key, list);
}

static void keymgr_msg_recv( struct cf_msg* msg, const void* data )
{
    const struct cf_keyreq* req = NULL;
    struct key* key = NULL;

    if( msg->length < sizeof(*req) )
		return;

    req = (const struct cf_keyreq*)data;

    if( msg->length != (sizeof(*req) + req->data_len) )
		return;

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

static void keymgr_pkcs11_rsa_encrypt( struct cf_msg* msg, const void* data, struct key* key )
{
    int ret;
    const struct cf_keyreq *req = NULL;
    size_t	keylen;
    uint8_t buf[1024];

    req = (const struct cf_keyreq *)data;

    keylen = 256;

    if( req->data_len > keylen || keylen > sizeof(buf) )
        return;

    cf_log(LOG_NOTICE,"PKCS11 RSA data len = %d, keylen = %lu, padding = %d", req->data_len, keylen, req->padding);

    ret = cf_pkcs11_private_encrypt( key->p11_key, req->data, req->data_len, buf );

    cf_msg_send(msg->src, CF_MSG_KEYMGR_RESP, buf, ret);
}

static void keymgr_rsa_encrypt( struct cf_msg* msg, const void* data, struct key* key )
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

    cf_log(LOG_NOTICE,"RSA data len = %d, keylen = %lu, padding = %d", req->data_len, keylen, req->padding);

    if( req->data_len > keylen || keylen > sizeof(buf) )
        return;

    ret = RSA_private_encrypt(req->data_len, req->data, buf, rsa, req->padding );
    if( ret != RSA_size(rsa) )
        return;

    cf_msg_send(msg->src, CF_MSG_KEYMGR_RESP, buf, ret);
}

static void keymgr_ecdsa_sign( struct cf_msg* msg, const void* data, struct key* key )
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

static void keymgr_entropy_request( struct cf_msg* msg, const void* data )
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
/****************************************************************
 *  Helper function to load random file
 ****************************************************************/
static void keymgr_load_randfile(void)
{
    int	fd;
    struct stat	st;
    ssize_t ret;
    size_t total = 0;
    uint8_t	buf[RAND_FILE_SIZE];

    if( rand_file == NULL )
        return;

    if( (fd = open(rand_file, O_RDONLY)) == -1 )
        cf_fatal("open(%s): %s", rand_file, errno_s);

    if( fstat(fd, &st) == -1 )
        cf_fatal("stat(%s): %s", rand_file, errno_s);
    if( !S_ISREG(st.st_mode) )
        cf_fatal("%s is not a file", rand_file);
    if( st.st_size != RAND_FILE_SIZE )
        cf_fatal("%s has an invalid size", rand_file);

    while( total != RAND_FILE_SIZE )
    {
        if( (ret = read(fd, buf, sizeof(buf))) == 0 )
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
/****************************************************************
 *  Helper function to save random file
 ****************************************************************/
static void keymgr_save_randfile( void )
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

    if( RAND_bytes(buf, sizeof(buf)) == 1 )
    {
        if( (fd = open(RAND_TMP_FILE, O_CREAT | O_TRUNC | O_WRONLY, 0400)) != -1 )
        {
            /* Try to write random data to file */
            ret = write(fd, buf, sizeof(buf));

            if( close(fd) == -1 )
                cf_log(LOG_WARNING, "close(%s): %s", RAND_TMP_FILE, errno_s);

            if( ret != -1 && (size_t)ret == sizeof(buf) )
            {
                if( rename(RAND_TMP_FILE, rand_file) == -1 )
                {
                    cf_log(LOG_WARNING, "rename(%s, %s): %s", RAND_TMP_FILE, rand_file, errno_s);
                    unlink(rand_file);
                    unlink( RAND_TMP_FILE );
                }
            }
            else
            {
                cf_log(LOG_WARNING, "failed to write random data");
                unlink( RAND_TMP_FILE );
            }
        }
        else
            cf_log(LOG_WARNING, "failed to open %s: %s - random data not written", RAND_TMP_FILE, errno_s);
    }
    else
        cf_log(LOG_WARNING, "RAND_bytes: %s", ssl_errno_s);

    OPENSSL_cleanse(buf, sizeof(buf));
}

static void keymgr_certificate_request( struct cf_msg* msg, const void* data )
{
    struct cf_domain* dom = NULL;

    TAILQ_FOREACH(dom, &server.domains, list)
        keymgr_submit_certificates(dom, msg->src);
}

static void keymgr_submit_certificates( struct cf_domain* dom, uint16_t dst)
{
    keymgr_submit_file(CF_MSG_CERTIFICATE, dom, dom->certfile, dst, 0);

    if (dom->crlfile != NULL)
        keymgr_submit_file(CF_MSG_CRL, dom, dom->crlfile, dst, 1);
}

static void keymgr_submit_file( u_int8_t id, struct cf_domain* dom, const char *file, uint16_t dst, int can_fail )
{
    int				fd;
    struct stat			st;
    ssize_t				ret;
    size_t				len;
    struct cf_x509_msg	*msg = NULL;
    uint8_t			    *payload = NULL;

    if( (fd = open(file, O_RDONLY)) == -1 )
    {
        if( errno == ENOENT && can_fail )
            return;
        cf_fatal("open(%s): %s", file, errno_s);
    }

    if( fstat(fd, &st) == -1 )
        cf_fatal("stat(%s): %s", file, errno_s);

    if( !S_ISREG(st.st_mode) )
        cf_fatal("%s is not a file", file);

    if( st.st_size <= 0 || st.st_size > (1024 * 1024 * 5) )
    {
        cf_fatal("%s length is not valid (%jd)", file, (intmax_t)st.st_size);
    }

    len = sizeof(*msg) + st.st_size;
    payload = mem_calloc(1, len);

    msg = (struct cf_x509_msg *)payload;
    msg->domain_len = strlen(dom->domain);
    if( msg->domain_len > sizeof(msg->domain) )
        cf_fatal("domain name '%s' too long", dom->domain);
    memcpy(msg->domain, dom->domain, msg->domain_len);

    msg->data_len = st.st_size;
    ret = read(fd, &msg->data[0], msg->data_len);

    if( ret == -1 )
        cf_fatal("failed to read from %s: %s", file, errno_s);

    if( ret == 0 )
        cf_fatal("eof while reading %s", file);

    if( (size_t)ret != msg->data_len )
    {
        cf_fatal("bad read on %s: expected %zu, got %zd", file, msg->data_len, ret);
    }

    cf_msg_send(dst, id, payload, len);
    mem_free(payload);
    close(fd);
}
