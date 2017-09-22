// cf_domain.c

#include <sys/param.h>

#ifndef CF_NO_TLS
    #include <openssl/x509.h>
    #include <openssl/bio.h>
    #include <openssl/evp.h>
    #include <openssl/ec.h>
    #include <openssl/ecdsa.h>
    #include <poll.h>
#endif

#include <fnmatch.h>

#include "zfrog.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif


#define SSL_SESSION_ID	"cf_ssl_sessionid"

struct cf_domain_h domains;
struct cf_domain  *primary_dom = NULL;

#ifndef CF_NO_TLS
    static uint8_t	keymgr_buf[2048];
    static size_t keymgr_buflen = 0;
    static int keymgr_response = 0;
    DH	*tls_dhparam = NULL;
    int	tls_version = CF_TLS_VERSION_1_2;
#endif

static void	domain_load_crl(struct cf_domain *);

#ifndef CF_NO_TLS
    /* Forward function declaration */
    static int domain_x509_verify(int, X509_STORE_CTX *);
    static void	keymgr_init(void);
    static void	keymgr_await_data(void);
    static void	keymgr_msg_response(struct cf_msg *, const void *);
    static int keymgr_rsa_init( RSA *);
    static int keymgr_rsa_finish( RSA *);
    static int keymgr_rsa_privenc(int, const unsigned char *, unsigned char *, RSA *, int);
    static ECDSA_SIG *keymgr_ecdsa_sign(const unsigned char *, int, const BIGNUM *, const BIGNUM *, EC_KEY *);

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    static RSA_METHOD	*keymgr_rsa_meth = NULL;
    static EC_KEY_METHOD	*keymgr_ec_meth = NULL;
#else

#if !defined(LIBRESSL_VERSION_TEXT)
/*
 * Run own ecdsa_method data structure as OpenSSL has this in ecs_locl.h
 * and does not export this on systems.
 *
 * XXX - OpenSSL is merging ECDSA functionality into EC in 1.1.0.
 */
struct ecdsa_method
{
	const char	*name;
    ECDSA_SIG	*(*ecdsa_do_sign)(const unsigned char *, int, const BIGNUM *, const BIGNUM *, EC_KEY *);
    int		(*ecdsa_sign_setup)(EC_KEY *, BN_CTX *, BIGNUM **, BIGNUM **);
    int		(*ecdsa_do_verify)(const unsigned char *, int, const ECDSA_SIG *, EC_KEY *);
	int		flags;
    char	*app_data;
};
#endif

static ECDSA_METHOD	keymgr_ecdsa =
{
    "zfrog ECDSA keymgr method",
	keymgr_ecdsa_sign,
	NULL,
	NULL,
	0,
	NULL
};

static RSA_METHOD keymgr_rsa =
{
    "zfrog RSA keymgr method",
	NULL,
	NULL,
	keymgr_rsa_privenc,
	NULL,
	NULL,
	NULL,
	keymgr_rsa_init,
	keymgr_rsa_finish,
	RSA_METHOD_FLAG_NO_CHECK,
	NULL,
	NULL,
	NULL,
	NULL
};
#endif /* OPENSSL_VERSION_NUMBER */
#endif /* CF_NO_TLS */

void cf_domain_init(void)
{
	TAILQ_INIT(&domains);

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    if( keymgr_rsa_meth == NULL )
    {
        if( (keymgr_rsa_meth = RSA_meth_new("zfrog RSA keymgr method", RSA_METHOD_FLAG_NO_CHECK)) == NULL )
            cf_fatal("failed to allocate RSA method");
    }

    RSA_meth_set_init(keymgr_rsa_meth, keymgr_rsa_init);
    RSA_meth_set_finish(keymgr_rsa_meth, keymgr_rsa_finish);
    RSA_meth_set_priv_enc(keymgr_rsa_meth, keymgr_rsa_privenc);

    if( keymgr_ec_meth == NULL )
    {
        if( (keymgr_ec_meth = EC_KEY_METHOD_new(NULL)) == NULL )
            cf_fatal("failed to allocate EC KEY method");
    }

    EC_KEY_METHOD_set_sign(keymgr_ec_meth, NULL, NULL, keymgr_ecdsa_sign);
#endif
}

void cf_domain_cleanup(void)
{
    struct cf_domain *dom = NULL;

    while( (dom = TAILQ_FIRST(&domains)) != NULL )
    {
		TAILQ_REMOVE(&domains, dom, list);
        cf_domain_free(dom);
	}

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    if( keymgr_rsa_meth != NULL )
    {
        RSA_meth_free(keymgr_rsa_meth);
        keymgr_rsa_meth = NULL;
    }

    if( keymgr_ec_meth != NULL )
    {
        EC_KEY_METHOD_free(keymgr_ec_meth);
        keymgr_ec_meth = NULL;
    }
#endif
}

int domain_new( char *domain )
{
    struct cf_domain *dom = NULL;

    if( cf_domain_lookup(domain) != NULL )
        return CF_RESULT_ERROR;

    log_debug("domain_new(%s)", domain);

    dom = mem_malloc(sizeof(*dom));
	dom->accesslog = -1;
#ifndef CF_NO_TLS
	dom->cafile = NULL;
	dom->certkey = NULL;
	dom->ssl_ctx = NULL;
	dom->certfile = NULL;
	dom->crlfile = NULL;
#endif
    dom->domain = mem_strdup(domain);
	TAILQ_INIT(&(dom->handlers));
	TAILQ_INSERT_TAIL(&domains, dom, list);

    if( primary_dom == NULL )
		primary_dom = dom;

    return CF_RESULT_OK;
}

void cf_domain_free( struct cf_domain *dom )
{
#ifndef CF_NO_HTTP
    struct cf_module_handle *hdlr;
#endif
    if( dom == NULL )
		return;

    if( primary_dom == dom )
		primary_dom = NULL;

	TAILQ_REMOVE(&domains, dom, list);

    if( dom->domain != NULL )
        mem_free(dom->domain);

#ifndef CF_NO_TLS
    if( dom->ssl_ctx != NULL )
		SSL_CTX_free(dom->ssl_ctx);
    if( dom->cafile != NULL )
        mem_free(dom->cafile);
    if( dom->certkey != NULL )
        mem_free(dom->certkey);
    if( dom->certfile != NULL )
        mem_free(dom->certfile);
    if( dom->crlfile != NULL )
        mem_free(dom->crlfile);
#endif

#ifndef CF_NO_HTTP
	/* Drop all handlers associated with this domain */
    while( (hdlr = TAILQ_FIRST(&(dom->handlers))) != NULL )
    {
		TAILQ_REMOVE(&(dom->handlers), hdlr, list);
        cf_module_handler_free( hdlr );
	}
#endif
    mem_free(dom);
}

void cf_domain_tls_init( struct cf_domain *dom )
{
#ifndef CF_NO_TLS
    BIO	*in = NULL;
    RSA	*rsa = NULL;
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
	STACK_OF(X509_NAME)	*certs;
    EC_KEY *eckey = NULL;
    X509_STORE *store = NULL;
    const SSL_METHOD *method = NULL;

#if !defined(OPENSSL_NO_EC)
    EC_KEY *ecdh = NULL;
#endif

    log_debug("cf_domain_tls_init(%s)", dom->domain);

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    if( (method = TLS_method()) == NULL )
        cf_fatal("TLS_method(): %s", ssl_errno_s);
#else
    switch( tls_version )
    {
    case CF_TLS_VERSION_1_2:
		method = TLSv1_2_server_method();
		break;
    case CF_TLS_VERSION_1_1:
        method = TLSv1_1_server_method();
        break;
    case CF_TLS_VERSION_1_0:
		method = TLSv1_server_method();
		break;
    case CF_TLS_VERSION_BOTH:
		method = SSLv23_server_method();
		break;
	default:
        cf_fatal("unknown tls_version: %d", tls_version);
		return;
	}
#endif

    /* Create SSL context */
    if( (dom->ssl_ctx = SSL_CTX_new( method )) == NULL )
        cf_fatal("cf_domain_tls_init(): SSL_ctx_new(): %s", ssl_errno_s);

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    if( !SSL_CTX_set_min_proto_version(dom->ssl_ctx, TLS1_VERSION) )
        cf_fatal("SSL_CTX_set_min_proto_version: %s", ssl_errno_s);

    if( !SSL_CTX_set_max_proto_version(dom->ssl_ctx, TLS1_2_VERSION) )
        cf_fatal("SSL_CTX_set_max_proto_version: %s", ssl_errno_s);

    switch( tls_version )
    {
    case CF_TLS_VERSION_1_2:
        if( !SSL_CTX_set_min_proto_version(dom->ssl_ctx, TLS1_2_VERSION))
            cf_fatal("SSL_CTX_set_min_proto_version: %s", ssl_errno_s);
        break;
    case CF_TLS_VERSION_1_0:
        if( !SSL_CTX_set_max_proto_version(dom->ssl_ctx, TLS1_VERSION) )
            cf_fatal("SSL_CTX_set_min_proto_version: %s", ssl_errno_s);
        break;
    case CF_TLS_VERSION_BOTH:
        break;
    default:
        cf_fatal("unknown tls_version: %d", tls_version);
        return;
    }
#endif

    if( !SSL_CTX_use_certificate_chain_file(dom->ssl_ctx, dom->certfile) )
    {
        cf_fatal("SSL_CTX_use_certificate_chain_file(%s): %s", dom->certfile, ssl_errno_s);
	}

    if( (in = BIO_new(BIO_s_file_internal())) == NULL )
        cf_fatal("BIO_new: %s", ssl_errno_s);

    if( BIO_read_filename(in, dom->certfile) <= 0 )
        cf_fatal("BIO_read_filename: %s", ssl_errno_s);

    if( (x509 = PEM_read_bio_X509(in, NULL, NULL, NULL)) == NULL ) {
        cf_fatal("PEM_read_bio_X509: %s", ssl_errno_s);
    }

	BIO_free(in);

    if( (pkey = X509_get_pubkey(x509)) == NULL )
        cf_fatal("certificate has no public key");

    switch( EVP_PKEY_id(pkey) )
    {
	case EVP_PKEY_RSA:
        if( (rsa = EVP_PKEY_get1_RSA(pkey)) == NULL )
            cf_fatal("no RSA public key present");
		RSA_set_app_data(rsa, dom);
#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
        RSA_set_method(rsa, keymgr_rsa_meth);
#else
		RSA_set_method(rsa, &keymgr_rsa);
#endif
		break;
	case EVP_PKEY_EC:
        if( (eckey = EVP_PKEY_get1_EC_KEY(pkey)) == NULL )
            cf_fatal("no EC public key present");
#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
        EC_KEY_set_ex_data(eckey, 0, dom);
        EC_KEY_set_method(eckey, keymgr_ec_meth);
#else
		ECDSA_set_ex_data(eckey, 0, dom);
		ECDSA_set_method(eckey, &keymgr_ecdsa);
#endif
		break;
	default:
        cf_fatal("unknown public key in certificate");
	}

    if( !SSL_CTX_use_PrivateKey(dom->ssl_ctx, pkey) )
        cf_fatal("SSL_CTX_use_PrivateKey(): %s", ssl_errno_s);

    if( !SSL_CTX_check_private_key(dom->ssl_ctx) )
        cf_fatal("Public/Private key for %s do not match", dom->domain);

    if( tls_dhparam == NULL )
        cf_fatal("No DH parameters given");

	SSL_CTX_set_tmp_dh(dom->ssl_ctx, tls_dhparam);
    SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_SINGLE_DH_USE);

    if( (ecdh = EC_KEY_new_by_curve_name(NID_secp384r1)) == NULL )
        cf_fatal("EC_KEY_new_by_curve_name: %s", ssl_errno_s);

	SSL_CTX_set_tmp_ecdh(dom->ssl_ctx, ecdh);
	EC_KEY_free(ecdh);

    SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_SINGLE_ECDH_USE);
	SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_COMPRESSION);

    if( dom->cafile != NULL )
    {
        if( (certs = SSL_load_client_CA_file(dom->cafile)) == NULL )
        {
            cf_fatal("SSL_load_client_CA_file(%s): %s", dom->cafile, ssl_errno_s);
		}

		SSL_CTX_load_verify_locations(dom->ssl_ctx, dom->cafile, NULL);
		SSL_CTX_set_verify_depth(dom->ssl_ctx, 1);
		SSL_CTX_set_client_CA_list(dom->ssl_ctx, certs);
        SSL_CTX_set_verify(dom->ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        if( (store = SSL_CTX_get_cert_store(dom->ssl_ctx)) == NULL )
            cf_fatal("SSL_CTX_get_cert_store(): %s", ssl_errno_s);

		X509_STORE_set_verify_cb(store, domain_x509_verify);
	}

	SSL_CTX_set_session_id_context(dom->ssl_ctx,(unsigned char *)SSL_SESSION_ID, strlen(SSL_SESSION_ID));

	/*
	 * Force OpenSSL to not use its freelists. Even without using
	 * SSL_MODE_RELEASE_BUFFERS there are times it will use the
	 * freelists. So forcefully putting its max length to 0 is the
	 * only we choice we seem to have.
	 *
	 * Note that OpenBSD has since heartbleed removed freelists
	 * from its OpenSSL in base so we don't need to care about it.
	 */
#if !defined(LIBRESSL_VERSION_TEXT)
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    dom->ssl_ctx->freelist_max_len = 0;
#endif
#endif
	SSL_CTX_set_mode(dom->ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);

    if( tls_version == CF_TLS_VERSION_BOTH )
    {
		SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_SSLv2);
		SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_SSLv3);
		SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_NO_TLSv1_1);
	}

	SSL_CTX_set_options(dom->ssl_ctx, SSL_OP_CIPHER_SERVER_PREFERENCE);
    SSL_CTX_set_cipher_list(dom->ssl_ctx, cf_tls_cipher_list);

    SSL_CTX_set_info_callback(dom->ssl_ctx, cf_tls_info_callback);
    SSL_CTX_set_tlsext_servername_callback(dom->ssl_ctx, cf_tls_sni_cb);

    mem_free(dom->certfile);
	dom->certfile = NULL;
#endif
}

void cf_domain_callback( void (*cb)(struct cf_domain *) )
{
    struct cf_domain *dom = NULL;

    TAILQ_FOREACH(dom, &domains, list)
		cb(dom);
}

struct cf_domain* cf_domain_lookup( const char *domain )
{
    struct cf_domain *dom = NULL;

    TAILQ_FOREACH(dom, &domains, list)
    {
        if( !strcmp(dom->domain, domain) )
            return dom;

#if (__sun && __SVR4)
        if( !fnmatch(dom->domain, domain, 0) )
#else
        if( !fnmatch(dom->domain, domain, FNM_CASEFOLD) )
#endif
            return dom;
	}

    return NULL;
}

void cf_domain_closelogs( void )
{
    struct cf_domain *dom = NULL;

    TAILQ_FOREACH(dom, &domains, list)
    {
        if( dom->accesslog != -1 )
            close( dom->accesslog );
	}
}

void cf_domain_load_crl( void )
{
    struct cf_domain *dom = NULL;

	TAILQ_FOREACH(dom, &domains, list)
		domain_load_crl(dom);
}

void cf_domain_keymgr_init( void )
{
#ifndef CF_NO_TLS
	keymgr_init();
    cf_msg_register(CF_MSG_KEYMGR_RESP, keymgr_msg_response);
#endif
}

static void domain_load_crl( struct cf_domain *dom )
{
#ifndef CF_NO_TLS
    X509_STORE *store = NULL;

	ERR_clear_error();

    if( dom->cafile == NULL )
		return;

    if( dom->crlfile == NULL )
    {
        cf_log(LOG_WARNING, "WARNING: Running without CRL");
		return;
	}

    if( (store = SSL_CTX_get_cert_store(dom->ssl_ctx)) == NULL )
    {
        cf_log(LOG_ERR, "SSL_CTX_get_cert_store(): %s", ssl_errno_s);
		return;
	}

    if( !X509_STORE_load_locations(store, dom->crlfile, NULL) )
    {
        cf_log(LOG_ERR, "X509_STORE_load_locations(): %s", ssl_errno_s);
		return;
	}

    X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
#endif
}

#ifndef CF_NO_TLS
static void keymgr_init(void)
{
    const RSA_METHOD *meth = NULL;

    if( (meth = RSA_get_default_method()) == NULL ) {
        cf_fatal("failed to obtain RSA method");
    }
#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    RSA_meth_set_pub_enc(keymgr_rsa_meth, RSA_meth_get_pub_enc(meth));
    RSA_meth_set_pub_dec(keymgr_rsa_meth, RSA_meth_get_pub_dec(meth));
    RSA_meth_set_bn_mod_exp(keymgr_rsa_meth, RSA_meth_get_bn_mod_exp(meth));
#else
	keymgr_rsa.rsa_pub_enc = meth->rsa_pub_enc;
	keymgr_rsa.rsa_pub_dec = meth->rsa_pub_dec;
	keymgr_rsa.bn_mod_exp = meth->bn_mod_exp;
#endif
}

static int keymgr_rsa_init( RSA *rsa )
{
    if( rsa != NULL )
    {
#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
        RSA_set_flags( rsa, RSA_flags(rsa) | RSA_FLAG_EXT_PKEY | RSA_METHOD_FLAG_NO_CHECK );
#else
		rsa->flags |= RSA_FLAG_EXT_PKEY | RSA_METHOD_FLAG_NO_CHECK;
#endif
        return 1;
	}

    return 0;
}

static int keymgr_rsa_privenc(int flen, const unsigned char *from, unsigned char *to, RSA *rsa, int padding)
{
    int	ret;
    size_t len;
    struct cf_keyreq *req = NULL;
    struct cf_domain *dom = NULL;

	len = sizeof(*req) + flen;

    if( len > sizeof(keymgr_buf) )
        cf_fatal("keymgr_buf too small");

    if( (dom = RSA_get_app_data(rsa)) == NULL )
        cf_fatal("RSA key has no domain attached");

    if( strlen(dom->domain) >= CF_DOMAINNAME_LEN - 1 ) {
        cf_fatal("domain name too long");
    }

	memset(keymgr_buf, 0, sizeof(keymgr_buf));

    req = (struct cf_keyreq *)keymgr_buf;
	req->data_len = flen;
	req->padding = padding;
	req->domain_len = strlen(dom->domain);

	memcpy(&req->data[0], from, req->data_len);
	memcpy(req->domain, dom->domain, req->domain_len);

    cf_msg_send(CF_WORKER_KEYMGR, CF_MSG_KEYMGR_REQ, keymgr_buf, len);
	keymgr_await_data();

	ret = -1;

    if( keymgr_response )
    {
        if( keymgr_buflen < INT_MAX && (int)keymgr_buflen == RSA_size(rsa) )
        {
			ret = RSA_size(rsa);
			memcpy(to, keymgr_buf, RSA_size(rsa));
		}
	}

	keymgr_buflen = 0;
	keymgr_response = 0;

    cf_platform_event_all(worker->msg[1]->fd, worker->msg[1]);

    return ret;
}

static int keymgr_rsa_finish( RSA *rsa )
{
    return 1;
}

static ECDSA_SIG * keymgr_ecdsa_sign(const unsigned char *dgst, int dgst_len, const BIGNUM *in_kinv, const BIGNUM *in_r, EC_KEY *eckey)
{
    size_t len;
    ECDSA_SIG *sig;
    const uint8_t *ptr = NULL;
    struct cf_domain *dom = NULL;
    struct cf_keyreq *req = NULL;

	if (in_kinv != NULL || in_r != NULL)
		return (NULL);

	len = sizeof(*req) + dgst_len;
    if( len > sizeof(keymgr_buf) )
        cf_fatal("keymgr_buf too small");

#if !defined(LIBRESSL_VERSION_TEXT) && OPENSSL_VERSION_NUMBER >= 0x10100000L
    if( (dom = EC_KEY_get_ex_data(eckey, 0)) == NULL ) {
#else
    if( (dom = ECDSA_get_ex_data(eckey, 0)) == NULL ) {
#endif
        cf_fatal("EC_KEY has no domain");
    }

	memset(keymgr_buf, 0, sizeof(keymgr_buf));

    req = (struct cf_keyreq *)keymgr_buf;
	req->data_len = dgst_len;
	req->domain_len = strlen(dom->domain);

	memcpy(&req->data[0], dgst, req->data_len);
	memcpy(req->domain, dom->domain, req->domain_len);

    cf_msg_send(CF_WORKER_KEYMGR, CF_MSG_KEYMGR_REQ, keymgr_buf, len);
	keymgr_await_data();

    if( keymgr_response )
    {
		ptr = keymgr_buf;
		sig = d2i_ECDSA_SIG(NULL, &ptr, keymgr_buflen);
    }
    else
		sig = NULL;

	keymgr_buflen = 0;
	keymgr_response = 0;
    cf_platform_event_all( worker->msg[1]->fd, worker->msg[1] );

    return sig;
}

static void keymgr_await_data(void)
{
    int	ret;
    struct pollfd pfd[1];
    uint64_t start, cur;
#ifndef CF_NO_HTTP
    int process_requests = 0;
#endif

	/*
	 * We need to wait until the keymgr responds to us, so keep doing
     * net_recv_flush() until our callback for CF_MSG_KEYMGR_RESP
	 * tells us that we have obtained the response.
	 *
	 * This means other internal messages can still be delivered by
	 * this worker process to the appropriate callbacks but we do not
	 * drop out until we've either received an answer from the keymgr
	 * or until the timeout has been reached.
	 *
	 * It will however block any other I/O and request handling on
	 * this worker until either of the above criteria is met.
	 */
    start = cf_time_ms();
    cf_platform_disable_read( worker->msg[1]->fd );

	keymgr_response = 0;
	memset(keymgr_buf, 0, sizeof(keymgr_buf));

    for(;;)
    {

#ifndef CF_NO_HTTP
        if( process_requests )
        {
            http_process();
            process_requests = 0;
        }
#endif

		pfd[0].fd = worker->msg[1]->fd;
		pfd[0].events = POLLIN;
		pfd[0].revents = 0;

		ret = poll(pfd, 1, 100);

        if( ret == -1 )
        {
            if( errno == EINTR )
				continue;

            cf_fatal("poll: %s", errno_s);
		}

        cur = cf_time_ms();
        if( (cur - start) > 1000 )
			break;

        if( ret == 0 ) {
#ifndef CF_NO_HTTP
            /* No activity on channel, process HTTP requests */
            process_requests = 1;
#endif
			continue;
        }

        if( pfd[0].revents & (POLLERR | POLLHUP) )
			break;

        if( !(pfd[0].revents & POLLIN) )
			break;

		worker->msg[1]->flags |= CONN_READ_POSSIBLE;

        if( !net_recv_flush(worker->msg[1]) )
			break;

        if( keymgr_response )
			break;

#ifndef CF_NO_HTTP
        /* If we've spent 10 ms already, process HTTP requests */
        if( (cur - start) > 100 )
            process_requests = 1;
#endif
	}
}

static void keymgr_msg_response( struct cf_msg *msg, const void *data )
{
	keymgr_response = 1;
	keymgr_buflen = msg->length;

    if( keymgr_buflen > sizeof(keymgr_buf) )
		return;

	memcpy(keymgr_buf, data, keymgr_buflen);
}

static int domain_x509_verify(int ok, X509_STORE_CTX *ctx)
{
    X509 *cert = NULL;
    const char	*text = NULL;
    int	error, depth;

	error = X509_STORE_CTX_get_error(ctx);
	cert = X509_STORE_CTX_get_current_cert(ctx);

    if( ok == 0 && cert != NULL )
    {
		text = X509_verify_cert_error_string(error);
		depth = X509_STORE_CTX_get_error_depth(ctx);

        cf_log(LOG_WARNING, "X509 verification error depth:%d - %s", depth, text);

        /* Continue on CRL validity errors */
        switch (error)
        {
		case X509_V_ERR_CRL_HAS_EXPIRED:
		case X509_V_ERR_CRL_NOT_YET_VALID:
		case X509_V_ERR_UNABLE_TO_GET_CRL:
			ok = 1;
			break;
		}
	}

    return ok;
}
#endif /* CF_NO_TLS */
