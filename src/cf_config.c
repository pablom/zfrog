// cf_config.c

#include <sys/param.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <fcntl.h>
#include <pwd.h>

#include "zfrog.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

#ifndef CF_NO_TLS
    #include "cf_pkcs11.h"
#endif

#ifdef CF_PGSQL
    #include "cf_pgsql.h"
#endif

#ifdef CF_TASKS
    #include "cf_tasks.h"
#endif

#ifdef CF_PYTHON
    #include "cf_python.h"
#endif


#ifndef CF_SINGLE_BINARY
    static int configure_load(char*);
#else
    static FILE* config_file_write( void );
    extern uint8_t	asset_builtin_core_conf[];
    extern uint32_t asset_len_builtin_core_conf;
#endif

static void	parse_config_file(FILE*);
static void	domain_tls_init(void);
static int configure_include(char*);
static int configure_bind(char*);
static int configure_domain(char*);
static int configure_root(char*);
static int configure_runas(char*);
static int configure_workers(char*);
static int configure_pidfile(char*);
static int configure_rlimit_nofiles(char*);
static int configure_max_connections(char*);
static int configure_accept_threshold(char*);
static int configure_set_affinity(char*);
static int configure_socket_backlog(char*);

#ifndef CF_NO_TLS
    static int configure_certfile(char*);
    static int configure_certkey(char*);
    static int configure_tls_version(char*);
    static int configure_tls_cipher(char*);
    static int configure_tls_dhparam(char*);
    static int configure_client_verify(char*);
    static int configure_client_verify_depth(char*);
    static int configure_keymgr_root(char*);
    static int configure_keymgr_runas(char*);
    static int configure_pkcs11_module(char*);
#endif

#ifndef CF_NO_HTTP
    static int configure_handler(int, char*);
    static int configure_static_handler(char*);
    static int configure_dynamic_handler(char*);
    static int configure_accesslog(char*);
    static int configure_restrict(char*);
    static int configure_http_header_max(char*);
    static int configure_http_body_max(char*);
    static int configure_filemap(char*);
    static int configure_filemap_index(char*);
    static int configure_filemap_ext(char*);
    static int configure_http_media_type(char*);
    static int configure_http_hsts_enable(char*);
    static int configure_http_keepalive_time(char*);
    static int configure_http_request_ms(char*);
    static int configure_http_request_limit(char*);
    static int configure_http_body_disk_offload(char*);
    static int configure_http_body_disk_path(char*);
    static int configure_validator(char*);
    static int configure_params(char*);
    static int configure_validate(char*);
    static int configure_authentication(char*);
    static int configure_authentication_uri(char*);
    static int configure_authentication_type(char*);
    static int configure_authentication_value(char*);
    static int configure_authentication_validator(char*);
    static int configure_websocket_maxframe(char*);
    static int configure_websocket_timeout(char*);
#endif

#ifdef CF_PGSQL
    static int configure_pgsql_conn_max(char*);
    static int configure_pgsql_queue_limit(char*);
#endif

#ifdef CF_TASKS
    static int configure_task_threads(char*);
#endif

#ifdef CF_PYTHON
    static int configure_python_path(char*);
    static int configure_python_import(char*);
#endif
#ifdef CF_LUA
    static int configure_lua_import(char*);
#endif

static struct {
    const char	*name;
	int			(*configure)(char *);
} config_names[] = {
    { "include",                    configure_include },
    { "bind",                       configure_bind },
#if !defined(CF_SINGLE_BINARY)
    { "load",                       configure_load },
#endif
#ifdef CF_PYTHON
    { "python_path",		        configure_python_path },
    { "python_import",              configure_python_import },
#endif
#ifdef CF_LUA
    { "lua_import",                 configure_lua_import },
#endif
    { "domain",                     configure_domain },
    { "chroot",                     configure_root },
    { "runas",                      configure_runas },
    { "workers",                    configure_workers },
    { "worker_max_connections",     configure_max_connections },
    { "worker_rlimit_nofiles",      configure_rlimit_nofiles },
    { "worker_accept_threshold",    configure_accept_threshold },
    { "worker_set_affinity",        configure_set_affinity },
    { "pidfile",                    configure_pidfile },
    { "socket_backlog",             configure_socket_backlog },
#ifndef CF_NO_TLS
    { "tls_version",                configure_tls_version },
    { "tls_cipher",                 configure_tls_cipher },
    { "tls_dhparam",                configure_tls_dhparam },
    { "certfile",                   configure_certfile },
    { "certkey",                    configure_certkey },
    { "client_verify",              configure_client_verify },
    { "client_verify_depth",	    configure_client_verify_depth },
    { "keymgr_runas",               configure_keymgr_runas },
    { "keymgr_root",                configure_keymgr_root },
    { "pkcs11_module",              configure_pkcs11_module },
#endif
#ifndef CF_NO_HTTP
    { "filemap",			        configure_filemap },
    { "filemap_index",		        configure_filemap_index },
    { "filemap_ext",		        configure_filemap_ext },
    { "static",                     configure_static_handler },
    { "dynamic",                    configure_dynamic_handler },
    { "accesslog",                  configure_accesslog },
    { "restrict",			        configure_restrict },
    { "http_header_max",            configure_http_header_max },
    { "http_body_max",              configure_http_body_max },
    { "http_hsts_enable",           configure_http_hsts_enable },
    { "http_keepalive_time",        configure_http_keepalive_time },
    { "http_request_ms",		    configure_http_request_ms },
    { "http_request_limit",         configure_http_request_limit },
    { "http_body_disk_offload",     configure_http_body_disk_offload },
    { "http_body_disk_path",        configure_http_body_disk_path },
    { "http_media_type",		    configure_http_media_type },
    { "validator",                  configure_validator },
    { "params",                     configure_params },
    { "validate",                   configure_validate },
    { "authentication",             configure_authentication },
    { "authentication_uri",         configure_authentication_uri },
    { "authentication_type",        configure_authentication_type },
    { "authentication_value",       configure_authentication_value },
	{ "authentication_validator",	configure_authentication_validator },
    { "websocket_maxframe",         configure_websocket_maxframe },
    { "websocket_timeout",          configure_websocket_timeout },
#endif

#ifdef CF_PGSQL
    { "pgsql_conn_max",             configure_pgsql_conn_max },
    { "pgsql_queue_limit",		    configure_pgsql_queue_limit },
#endif

#ifdef CF_TASKS
    { "task_threads",               configure_task_threads },
#endif
	{ NULL,				NULL },
};

#ifndef CF_NO_HTTP
    static uint8_t current_method = 0;
    static int current_flags = 0;
    static struct cf_auth *current_auth = NULL;
    static struct cf_module_handle *current_handler = NULL;
#endif

extern const char *__progname;
static struct cf_domain	*current_domain = NULL;

/************************************************************************
 *  Parse configuration file
 ************************************************************************/
void cf_parse_config(void)
{
    FILE* fp = NULL;
    char path[PATH_MAX];

#ifndef CF_SINGLE_BINARY        
    log_debug("parsing configuration file '%s'", server.config_file);

    if( (fp = fopen(server.config_file, "r")) == NULL )
        cf_fatal("configuration given cannot be opened: %s", server.config_file);
#else
    fp = config_file_write();
#endif

    /* Try to parse configuration file */
    parse_config_file( fp );
    /* Close configuration file */
    fclose( fp );

    if( !cf_module_loaded() )
        cf_fatal("no application module was loaded");

    if( server.skip_chroot != 1 && server.root_path == NULL )
    {
        if( getcwd(path, sizeof(path)) == NULL )
            cf_fatal("getcwd: %s", errno_s);

        server.root_path = mem_strdup( path );
        cf_log(LOG_NOTICE, "privsep: no root path set, using working directory");
	}

    if( getuid() != 0 && server.skip_chroot == 0 ) {
        cf_fatal("cannot chroot, use -n to skip it");
	}

    if( server.skip_runas != 1 && server.runas_user == NULL ) {
        cf_fatal("missing runas user, use -r to skip it");
	}

    if( getuid() != 0 && server.skip_runas == 0 ) {
        cf_fatal("cannot drop privileges, use -r to skip it");
	}
}
/************************************************************************
 *  Helper function to parse configuration file
 ************************************************************************/
static void parse_config_file( FILE *fp )
{
    int	i, lineno;
    char buf[BUFSIZ], *p, *t;

	lineno = 1;
    while( (p = cf_fread_line(fp, buf, sizeof(buf))) != NULL )
    {
        if( strlen(p) == 0 )
        {
			lineno++;
			continue;
		}

#ifndef CF_NO_HTTP
        if( !strcmp(p, "}") && current_handler != NULL )
        {
			lineno++;
            current_flags = 0;
            current_method = 0;
			current_handler = NULL;
			continue;
		}

        if( !strcmp(p, "}") && current_auth != NULL )
        {
            if( current_auth->validator == NULL )
            {
                domain_tls_init();
                cf_fatal("no authentication validator for %s", current_auth->name);
			}

			lineno++;
			current_auth = NULL;
			continue;
		}
#endif

        if( !strcmp(p, "}") && current_domain != NULL )
            //domain_tls_init();
            current_domain = NULL;

        if( !strcmp(p, "}") )
        {
			lineno++;
			continue;
		}

        if( (t = strchr(p, ' ')) == NULL )
        {
			printf("ignoring \"%s\" on line %d\n", p, lineno++);
			continue;
		}

		*(t)++ = '\0';

        p = cf_text_trim(p, strlen(p));
        t = cf_text_trim(t, strlen(t));

        if( strlen(p) == 0 || strlen(t) == 0 )
        {
			printf("ignoring \"%s\" on line %d\n", p, lineno++);
			continue;
		}

        for(i = 0; config_names[i].name != NULL; i++)
        {
            if( !strcmp(config_names[i].name, p) )
            {
                if( config_names[i].configure(t) )
					break;
                cf_fatal("configuration error on line %d", lineno);
				/* NOTREACHED */
			}
		}

        if( config_names[i].name == NULL )
			printf("ignoring \"%s\" on line %d\n", p, lineno);
		lineno++;
	}
}
/************************************************************************
 *  Helper function to parse configuration file from include directive
 ************************************************************************/
static int configure_include( char *path )
{
    FILE* fp = NULL;

    if( (fp = fopen(path, "r")) == NULL )
        cf_fatal("failed to open include '%s'", path);

    parse_config_file(fp);
    /* Close open file */
    fclose( fp );
    return CF_RESULT_OK;
}
/************************************************************************
 *  Helper function to parse bind server parameters
 ************************************************************************/
static int configure_bind( char *options )
{
    char *argv[4];

    cf_split_string(options, " ", argv, 4);
    if( argv[0] == NULL || argv[1] == NULL )
        return CF_RESULT_ERROR;

    return cf_server_bind(argv[0], argv[1], argv[2]);
}

#ifndef CF_SINGLE_BINARY
static int configure_load( char *options )
{
    char *argv[3];

    cf_split_string(options, " ", argv, 3);
    if( argv[0] == NULL )
        return CF_RESULT_ERROR;

    cf_module_load( argv[0], argv[1], CF_MODULE_NATIVE );
    return CF_RESULT_OK;
}
#else
static FILE* config_file_write( void )
{
    FILE *fp = NULL;
    ssize_t	ret = 0;
    int	fd, len;
    char fpath[MAXPATHLEN];

	len = snprintf(fpath, sizeof(fpath), "/tmp/%s.XXXXXX", __progname);

    if( len == -1 || (size_t)len >= sizeof(fpath) )
        cf_fatal("failed to create temporary path");

    if( (fd = mkstemp(fpath)) == -1 )
        cf_fatal("mkstemp(%s): %s", fpath, errno_s);

    unlink(fpath);

    for(;;)
    {
        ret = write(fd, asset_builtin_core_conf, asset_len_builtin_core_conf);

        if( ret == -1 )
        {
            if( errno == EINTR )
				continue;
            cf_fatal("failed to write temporary config: %s", errno_s);
		}

        if( (size_t)ret != asset_len_builtin_core_conf ) {
            cf_fatal("failed to write temporary config");
        }

		break;
	}

    if( (fp = fdopen(fd, "w+")) == NULL ) {
        cf_fatal("fdopen(): %s", errno_s);
    }

	rewind(fp);

    return fp;
}
#endif

#ifndef CF_NO_TLS
/************************************************************************
 *  Configure domain TLS version
 ************************************************************************/
static int configure_tls_version( char *version )
{                    
    if( !strcmp(version, "1.3") ) {
#if OPENSSL_VERSION_NUMBER >= 0x10101004L
        server.tls_version = CF_TLS_VERSION_1_3;
#else
        server.tls_version = CF_TLS_VERSION_1_2;
#endif
    } else if( !strcmp(version, "1.2") ) {
        server.tls_version = CF_TLS_VERSION_1_2;
    } else if( !strcmp(version, "1.1") ) {
        server.tls_version = CF_TLS_VERSION_1_1;
    } else if( !strcmp(version, "1.0") ) {
        server.tls_version = CF_TLS_VERSION_1_0;
    } else if( !strcmp(version, "both") ) {
        server.tls_version = CF_TLS_VERSION_BOTH;
    }
    else
    {
		printf("unknown value for tls_version: %s\n", version);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure domain TLS cipher list
 ************************************************************************/
static int configure_tls_cipher(char *cipherlist)
{
    if( strcmp(server.tls_cipher_list, CF_DEFAULT_CIPHER_LIST) )
    {
		printf("tls_cipher specified twice\n");
        return CF_RESULT_ERROR;
	}

    server.tls_cipher_list = mem_strdup(cipherlist);
    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure domain TLS DH parameters
 ************************************************************************/
static int configure_tls_dhparam( char *path )
{
    BIO	*bio = NULL;

    if( server.tls_dhparam != NULL )
    {
		printf("tls_dhparam specified twice\n");
        return CF_RESULT_ERROR;
	}

    if( (bio = BIO_new_file(path, "r")) == NULL )
    {
		printf("%s did not exist\n", path);
        return CF_RESULT_ERROR;
	}

    server.tls_dhparam = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
	BIO_free(bio);

    if( server.tls_dhparam == NULL )
    {
		printf("PEM_read_bio_DHparams(): %s\n", ssl_errno_s);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure domain client certificate's verify depth
 ************************************************************************/
static int configure_client_verify_depth( char* value )
{
    int	err, depth;

    if( current_domain == NULL )
    {
        printf("client_verify_depth not specified in domain context\n");
        return CF_RESULT_ERROR;
    }

    depth = cf_strtonum(value, 10, 0, INT_MAX, &err);
    if( err != CF_RESULT_OK )
    {
        printf("bad client_verify_depth value: %s\n", value);
        return CF_RESULT_ERROR;
    }

    current_domain->x509_verify_depth = depth;

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure domain client certificate's file
 ************************************************************************/
static int configure_client_verify( char* options )
{
    char *argv[3];

    if( current_domain == NULL )
    {
		printf("client_certificates not specified in domain context\n");
        return CF_RESULT_ERROR;
	}

    cf_split_string(options, " ", argv, 3);

    if( argv[0] == NULL )
    {
		printf("client_certificate is missing a parameter\n");
        return CF_RESULT_ERROR;
	}

    if( current_domain->cafile != NULL )
    {
        printf("client_certificate already set for %s\n", current_domain->domain);
        return CF_RESULT_ERROR;
	}

    current_domain->cafile = mem_strdup(argv[0]);

    if( argv[1] != NULL )
        current_domain->crlfile = mem_strdup(argv[1]);

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure domain certificate file
 ************************************************************************/
static int configure_certfile( char *path )
{
    if( current_domain == NULL )
    {
		printf("certfile not specified in domain context\n");
        return CF_RESULT_ERROR;
	}

    if( current_domain->certfile != NULL )
    {
        printf("certfile specified twice for %s\n", current_domain->domain);
        return CF_RESULT_ERROR;
	}

    current_domain->certfile = mem_strdup(path);
    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure domain private key file
 ************************************************************************/
static int configure_certkey( char *path )
{
    if( current_domain == NULL )
    {
		printf("certkey not specified in domain text\n");
        return CF_RESULT_ERROR;
	}

    if( current_domain->certkey != NULL )
    {
        printf("certkey specified twice for %s\n", current_domain->domain);
        return CF_RESULT_ERROR;
	}

    current_domain->certkey = mem_strdup(path);
    return CF_RESULT_OK;
}

static int configure_keymgr_runas( char* user )
{
    if( server.keymgr_runas_user != NULL )
        mem_free(server.keymgr_runas_user);

    server.keymgr_runas_user = mem_strdup(user);

    return CF_RESULT_OK;
}

static int configure_keymgr_root( char* root )
{
    if( server.keymgr_root_path != NULL )
        mem_free(server.keymgr_root_path);

    server.keymgr_root_path = mem_strdup(root);

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure PKCS11 module
 ************************************************************************/
static int configure_pkcs11_module( char *path )
{
    char *argv[3];

    cf_split_string(path, " ", argv, 3);
    if( argv[0] == NULL )
        return CF_RESULT_ERROR;

    cf_pkcs11_cfg.module_path =  mem_strdup(path);
    return CF_RESULT_OK;
}
#endif /* CF_NO_TLS */
/************************************************************************
 *  Configure domain
 ************************************************************************/
static int configure_domain( char *options )
{
    char *argv[3];

    if( current_domain != NULL )
    {
		printf("nested domain contexts are not allowed\n");
        return CF_RESULT_ERROR;
	}

    cf_split_string(options, " ", argv, 3);

    if( strcmp(argv[1], "{") )
    {
		printf("domain context not opened correctly\n");
        return CF_RESULT_ERROR;
	}

    if( strlen(argv[0]) >= CF_DOMAINNAME_LEN - 1 )
    {
		printf("domain name '%s' too long\n", argv[0]);
        return CF_RESULT_ERROR;
	}

    if( !cf_domain_new(argv[0]) )
    {
		printf("could not create new domain %s\n", argv[0]);
        return CF_RESULT_ERROR;
	}

    current_domain = cf_domain_lookup(argv[0]);
    return CF_RESULT_OK;
}

#ifndef CF_NO_HTTP
static int configure_static_handler( char *options )
{
    return configure_handler(HANDLER_TYPE_STATIC, options);
}

static int configure_dynamic_handler( char *options )
{
    return configure_handler(HANDLER_TYPE_DYNAMIC, options);
}

static int configure_handler(int type, char *options)
{
    char *argv[4];

    if( current_domain == NULL )
    {
		printf("page handler not specified in domain context\n");
        return CF_RESULT_ERROR;
	}

    cf_split_string(options, " ", argv, 4);

    if( argv[0] == NULL || argv[1] == NULL )
    {
		printf("missing parameters for page handler\n");
        return CF_RESULT_ERROR;
	}

    if( !cf_module_handler_new(argv[0], current_domain->domain, argv[1], argv[2], type) )
    {
		printf("cannot create handler for %s\n", argv[0]);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure access log file
 ************************************************************************/
static int configure_accesslog( char *path )
{
    if( current_domain == NULL )
    {
        log_debug("accesslog not specified in domain context\n");
        return (CF_RESULT_ERROR);
	}

    if( current_domain->accesslog != -1 )
    {
        printf("domain %s already has an open accesslog\n", current_domain->domain);
        return CF_RESULT_ERROR;
	}

    current_domain->accesslog = open(path, O_CREAT | O_APPEND | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    if( current_domain->accesslog == -1 )
    {
		printf("accesslog open(%s): %s\n", path, errno_s);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}

static int configure_restrict( char* options )
{
    struct cf_module_handle	*hdlr = NULL;
    int i, cnt;
    char* argv[10];

    if( current_domain == NULL )
    {
        printf("restrict not used in domain context\n");
        return CF_RESULT_ERROR;
    }

    if( (cnt = cf_split_string(options, " ", argv, 10)) < 2 )
    {
        printf("bad restrict option '%s', missing methods\n", options);
        return CF_RESULT_ERROR;
    }

    TAILQ_FOREACH(hdlr, &(current_domain->handlers), list)
    {
        if (!strcmp(hdlr->path, argv[0]))
            break;
    }

    if( hdlr == NULL )
    {
        printf("bad restrict option handler '%s' not found\n", argv[0]);
        return CF_RESULT_ERROR;
    }

    hdlr->methods = 0;

    for( i = 1; i < cnt; i++ )
    {
        if( !strcasecmp(argv[i], "post") ) {
            hdlr->methods |= HTTP_METHOD_POST;
        } else if( !strcasecmp(argv[i], "get") ) {
            hdlr->methods |= HTTP_METHOD_GET;
        } else if( !strcasecmp(argv[i], "put") ) {
            hdlr->methods |= HTTP_METHOD_PUT;
        } else if( !strcasecmp(argv[i], "delete") ) {
            hdlr->methods |= HTTP_METHOD_DELETE;
        } else if( !strcasecmp(argv[i], "head") ) {
            hdlr->methods |= HTTP_METHOD_HEAD;
        } else if( !strcasecmp(argv[i], "patch") ) {
            hdlr->methods |= HTTP_METHOD_PATCH;
        }
        else
        {
            printf("unknown method: %s in restrict for %s\n", argv[i], argv[0]);
            return CF_RESULT_ERROR;
        }
    }

    return CF_RESULT_OK;
}

static int configure_filemap( char *options )
{
    char *argv[3];

    if( current_domain == NULL )
    {
        printf("filemap outside of domain context\n");
        return CF_RESULT_ERROR;
    }

    cf_split_string(options, " ", argv, 3);

    if( argv[0] == NULL || argv[1] == NULL )
    {
        printf("missing parameters for filemap\n");
        return CF_RESULT_ERROR;
    }

    if( !cf_filemap_create(current_domain, argv[1], argv[0]) )
    {
        printf("cannot create filemap for %s\n", argv[1]);
        return CF_RESULT_ERROR;
    }

    return CF_RESULT_OK;
}

static int configure_filemap_index( char* fmap_index )
{
    mem_free( server.filemap_index );
    server.filemap_index = mem_strdup(fmap_index);
    return CF_RESULT_OK;
}

static int configure_filemap_ext( char *ext )
{
    mem_free(server.filemap_ext);
    server.filemap_ext = mem_strdup(ext);

    return CF_RESULT_OK;
}

static int configure_http_media_type( char *type )
{
    int	i;
    char *extensions, *ext[10];

    extensions = strchr(type, ' ');

    if( extensions == NULL )
    {
        printf("bad http_media_type value: %s\n", type);
        return CF_RESULT_ERROR;
    }

    *(extensions)++ = '\0';

    cf_split_string(extensions, " \t", ext, 10);
    for( i = 0; ext[i] != NULL; i++ )
    {
        if( !http_media_register(ext[i], type) )
        {
            printf("duplicate extension found: %s\n", ext[i]);
            return CF_RESULT_ERROR;
        }
    }

    if( i == 0 )
    {
        printf("missing extensions in: %s\n", type);
        return CF_RESULT_ERROR;
    }

    return CF_RESULT_OK;
}
/************************************************************************
 *  Read HTTP max header from configuration file
 ************************************************************************/
static int configure_http_header_max( char* option )
{
    int	err;

    server.http_header_max = cf_strtonum(option, 10, 1, 65535, &err);

    if( err != CF_RESULT_OK )
    {
		printf("bad http_header_max value: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Read HTTP body max limit bytes size from configuration file
 ************************************************************************/
static int configure_http_body_max( char *option )
{
    int	err;

    server.http_body_max = cf_strtonum(option, 10, 0, LONG_MAX, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad http_body_max value: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}

static int configure_http_body_disk_offload( char *option )
{
    int	err;

    server.http_body_disk_offload = cf_strtonum(option, 10, 0, LONG_MAX, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad http_body_disk_offload value: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}

static int configure_http_body_disk_path( char *path )
{
    if( strcmp(server.http_body_disk_path, HTTP_BODY_DISK_PATH) )
        mem_free(server.http_body_disk_path);

    server.http_body_disk_path = mem_strdup(path);
    return CF_RESULT_OK;
}

static int configure_http_hsts_enable( char *option )
{
    int	err;

    server.http_hsts_enable = cf_strtonum(option, 10, 0, LONG_MAX, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad http_hsts_enable value: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Read HTTP keep alive time from configuration file
 ************************************************************************/
static int configure_http_keepalive_time( char *option )
{
    int	err;

    server.http_keepalive_time = cf_strtonum(option, 10, 0, USHRT_MAX, &err);
    if(err != CF_RESULT_OK)
    {
		printf("bad http_keepalive_time value: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure HTTP timeout request in ms
 ************************************************************************/
static int configure_http_request_ms( char *option )
{
    int	err;

    server.http_request_ms = cf_strtonum(option, 10, 0, UINT_MAX, &err);
    if( err != CF_RESULT_OK )
    {
        printf("bad http_request_ms value: %s\n", option);
        return CF_RESULT_ERROR;
    }

    return CF_RESULT_OK;
}
/************************************************************************
 *  Read HTTP request limit from configuration file
 ************************************************************************/
static int configure_http_request_limit( char *option )
{
    int	err;

    server.http_request_limit = cf_strtonum(option, 10, 0, UINT_MAX, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad http_request_limit value: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure validator
 ************************************************************************/
static int configure_validator( char *name )
{
    uint8_t type;
    char *tname, *value;

    if( (tname = strchr(name, ' ')) == NULL )
    {
		printf("missing validator name\n");
        return CF_RESULT_ERROR;
	}

	*(tname)++ = '\0';
    tname = cf_text_trim(tname, strlen(tname));

    if( (value = strchr(tname, ' ')) == NULL )
    {
		printf("missing validator value\n");
        return CF_RESULT_ERROR;
	}

	*(value)++ = '\0';
    value = cf_text_trim(value, strlen(value));

    if( !strcmp(tname, "regex") )
    {
        type = CF_VALIDATOR_TYPE_REGEX;
    }
    else if (!strcmp(tname, "function"))
    {
        type = CF_VALIDATOR_TYPE_FUNCTION;
    }
    else
    {
		printf("bad type for validator %s\n", tname);
        return CF_RESULT_ERROR;
	}

    if( !cf_validator_add(name, type, value) )
    {
		printf("bad validator specified: %s\n", tname);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}

static int configure_params( char *options )
{
    struct cf_module_handle	*hdlr = NULL;
    char *argv[3];
    char* method = NULL;

    if( current_domain == NULL )
    {
		printf("params not used in domain context\n");
        return CF_RESULT_ERROR;
	}

    if( current_handler != NULL )
    {
		printf("previous params block not closed\n");
        return CF_RESULT_ERROR;
	}

    cf_split_string(options, " ", argv, 3);
    if( argv[1] == NULL )
        return CF_RESULT_ERROR;

    if( (method = strchr(argv[0], ':')) != NULL )
    {
        *(method)++ = '\0';
        if( !strcasecmp(argv[0], "qs") )
            current_flags = CF_PARAMS_QUERY_STRING;
        else
        {
            printf("unknown prefix '%s' for '%s'\n", argv[0], argv[1]);
            return CF_RESULT_ERROR;
        }
    }
    else
        method = argv[0];

    if( !strcasecmp(method, "post") ) {
		current_method = HTTP_METHOD_POST;
    } else if( !strcasecmp(method, "get") ) {
		current_method = HTTP_METHOD_GET;
    } else if( !strcasecmp(method, "put") ) {
		current_method = HTTP_METHOD_PUT;
    } else if( !strcasecmp(method, "delete") ) {
		current_method = HTTP_METHOD_DELETE;
    } else if( !strcasecmp(method, "head") ) {
		current_method = HTTP_METHOD_HEAD;
    } else if( !strcasecmp(method, "patch") ) {
        current_method = HTTP_METHOD_PATCH;
	} else {
        printf("unknown method: %s in params block for %s\n", method, argv[1]);
        return CF_RESULT_ERROR;
	}

	/*
	 * Find the handler ourselves, otherwise the regex is applied
     * in case of a dynamic page
	 */
    TAILQ_FOREACH(hdlr, &(current_domain->handlers), list)
    {
        if( !strcmp(hdlr->path, argv[1]) )
        {
			current_handler = hdlr;
            return CF_RESULT_OK;
		}
	}

	printf("params for unknown page handler: %s\n", argv[1]);
    return CF_RESULT_ERROR;
}

static int configure_validate( char *options )
{
    struct cf_handler_params *p = NULL;
    struct cf_validator	*val = NULL;
    char *argv[3];

    if( current_handler == NULL )
    {
		printf("validate not used in domain context\n");
        return CF_RESULT_ERROR;
	}

    cf_split_string(options, " ", argv, 3);
    if( argv[1] == NULL )
        return CF_RESULT_ERROR;

    if( (val = cf_validator_lookup(argv[1])) == NULL )
    {
		printf("unknown validator %s for %s\n", argv[1], argv[0]);
        return CF_RESULT_ERROR;
	}

    p = mem_malloc(sizeof(*p));
	p->validator = val;
    p->flags = current_flags;
	p->method = current_method;
    p->name = mem_strdup(argv[0]);

	TAILQ_INSERT_TAIL(&(current_handler->params), p, list);
    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure authentication
 ************************************************************************/
static int configure_authentication( char *options )
{
    char *argv[3];

    if( current_auth != NULL )
    {
		printf("previous authentication block not closed\n");
        return CF_RESULT_ERROR;
	}

    cf_split_string(options, " ", argv, 3);
    if( argv[1] == NULL )
    {
		printf("missing name for authentication block\n");
        return CF_RESULT_ERROR;
	}

    if( strcmp(argv[1], "{") )
    {
		printf("missing { for authentication block\n");
        return CF_RESULT_ERROR;
	}

    if( !cf_auth_new(argv[0]) )
        return CF_RESULT_ERROR;

    current_auth = cf_auth_lookup(argv[0]);

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure authentication type
 ************************************************************************/
static int configure_authentication_type( char *option )
{
    if( current_auth == NULL )
    {
		printf("authentication_type outside authentication context\n");
        return CF_RESULT_ERROR;
	}

	if (!strcmp(option, "cookie")) {
        current_auth->type = CF_AUTH_TYPE_COOKIE;
	} else if (!strcmp(option, "header")) {
        current_auth->type = CF_AUTH_TYPE_HEADER;
	} else if (!strcmp(option, "request")) {
        current_auth->type = CF_AUTH_TYPE_REQUEST;
    }
    else
    {
		printf("unknown authentication type '%s'\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}

static int configure_authentication_value( char *option )
{
    if( current_auth == NULL )
    {
		printf("authentication_value outside authentication context\n");
        return CF_RESULT_ERROR;
	}

    if( current_auth->value != NULL )
        mem_free(current_auth->value);

    current_auth->value = mem_strdup(option);

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure authentication validator
 ************************************************************************/
static int configure_authentication_validator( char *validator )
{
    struct cf_validator *val = NULL;

    if( current_auth == NULL )
    {
		printf("authentication_validator outside authentication\n");
        return CF_RESULT_ERROR;
	}

    if( (val = cf_validator_lookup(validator)) == NULL )
    {
		printf("authentication validator '%s' not found\n", validator);
        return CF_RESULT_ERROR;
	}

	current_auth->validator = val;

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure authentication uri
 ************************************************************************/
static int configure_authentication_uri( char *uri )
{
    if( current_auth == NULL )
    {
		printf("authentication_uri outside authentication context\n");
        return CF_RESULT_ERROR;
	}

    if( current_auth->redirect != NULL )
        mem_free(current_auth->redirect);

    current_auth->redirect = mem_strdup(uri);

    return CF_RESULT_OK;
}
/************************************************************************
 *  Read HTTP websocket max frame from configuration file
 ************************************************************************/
static int configure_websocket_maxframe( char *option )
{
	int	err;

    server.websocket_maxframe = cf_strtonum64(option, 1, &err);
    if( err != CF_RESULT_OK )
    {
        printf("bad cf_websocket_maxframe value: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Read HTTP websocket timeout from configuration file
 ************************************************************************/
static int configure_websocket_timeout( char *option )
{
	int	err;

    server.websocket_timeout = cf_strtonum64(option, 1, &err);

    if( err != CF_RESULT_OK )
    {
        printf("bad cf_websocket_timeout value: %s\n", option);
        return CF_RESULT_ERROR;
	}

    server.websocket_timeout = server.websocket_timeout * 1000;

    return CF_RESULT_OK;
}
#endif /* CF_NO_HTTP */
/************************************************************************
 *  Configure chroot application
 ************************************************************************/
static int configure_root( char *path )
{
    if( server.root_path != NULL )
        mem_free(server.root_path);

    server.root_path = mem_strdup(path);
    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure runas application
 ************************************************************************/
static int configure_runas( char *user )
{
    if( server.runas_user != NULL )
        mem_free(server.runas_user);

    server.runas_user = mem_strdup(user);

    return CF_RESULT_OK;
}
/****************************************************************
 *  Read worker count configuration option
 ****************************************************************/
static int configure_workers( char *option )
{
    int err;

    server.worker_count = cf_strtonum(option, 10, 1, 255, &err);
    if( err != CF_RESULT_OK )
    {
		printf("%s is not a valid worker number\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Read PID file path from configuration file
 ************************************************************************/
static int configure_pidfile( char *path )
{
    if( strcmp(server.pidfile, CF_PIDFILE_DEFAULT) )
        mem_free(server.pidfile);

    server.pidfile = mem_strdup(path);
    return CF_RESULT_OK;
}
/************************************************************************
 *  Read max connection limit per worker from configuration file
 ************************************************************************/
static int configure_max_connections( char *option )
{
    int err;

    server.worker_max_connections = cf_strtonum(option, 10, 1, UINT_MAX, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad value for worker_max_connections: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/************************************************************************
 *  Configure rlimit nfiles for application
 ************************************************************************/
static int configure_rlimit_nofiles( char *option )
{
    int err;

    server.worker_rlimit_nofiles = cf_strtonum(option, 10, 1, UINT_MAX, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad value for worker_rlimit_nofiles: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}

static int configure_accept_threshold( char *option )
{
    int err;

    server.worker_accept_threshold = cf_strtonum(option, 0, 1, UINT_MAX, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad value for worker_accept_threshold: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/****************************************************************
 *  Read worker affinity configuration option
 ****************************************************************/
static int configure_set_affinity( char *option )
{
    int err;

    server.worker_set_affinity = cf_strtonum(option, 10, 0, 1, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad value for worker_set_affinity: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/****************************************************************
 *  Read socket backlog configuration option
 ****************************************************************/
static int configure_socket_backlog( char *option )
{
    int	err;

    server.socket_backlog = cf_strtonum(option, 10, 0, UINT_MAX, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad socket_backlog value: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}

static void domain_tls_init( void )
{
    cf_domain_tls_init( current_domain, NULL, 0 );
	current_domain = NULL;
}

#ifdef CF_PGSQL
static int configure_pgsql_conn_max(char *option)
{
    int err;

    server.pgsql_conn_max = cf_strtonum(option, 10, 0, USHRT_MAX, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad value for pgsql_conn_max: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
/****************************************************************
 *  Read PGSQL queue limit configuration
 ****************************************************************/
static int configure_pgsql_queue_limit(char *option)
{
    int err;

    server.pgsql_queue_limit = cf_strtonum(option, 10, 0, UINT_MAX, &err);
    if( err != CF_RESULT_OK )
    {
        printf("bad value for pgsql_queue_limit: %s\n", option);
        return CF_RESULT_ERROR;
    }

    return CF_RESULT_OK;
}
#endif

#ifdef CF_TASKS
static int configure_task_threads( char *option )
{
    int	err;

    server.task_threads = cf_strtonum(option, 10, 0, UCHAR_MAX, &err);
    if( err != CF_RESULT_OK )
    {
		printf("bad value for task_threads: %s\n", option);
        return CF_RESULT_ERROR;
	}

    return CF_RESULT_OK;
}
#endif

#ifdef CF_PYTHON
static int configure_python_path( char *path )
{
    cf_python_path(path);
    return CF_RESULT_OK;
}
static int configure_python_import( char *module  )
{
    char *argv[3];

    cf_split_string(module, " ", argv, 3);
    if( argv[0] == NULL )
        return CF_RESULT_ERROR;

    cf_module_load(argv[0], argv[1], CF_MODULE_PYTHON);
    return CF_RESULT_OK;
 }
 #endif

#ifdef CF_LUA
static int configure_lua_import( char *module  )
{
    char *argv[3];

    cf_split_string(module, " ", argv, 3);
    if( argv[0] == NULL )
        return CF_RESULT_ERROR;

    cf_module_load(argv[0], argv[1], CF_MODULE_LUA);
    return CF_RESULT_OK;
 }
 #endif
