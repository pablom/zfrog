// cf_cli.c

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/queue.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/time.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>
#include <inttypes.h>
#include <fcntl.h>
#include <time.h>
#include <stdarg.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <utime.h>

#define errno_s			strerror(errno)
#define ssl_errno_s		ERR_error_string(ERR_get_error(), NULL)

#if defined(OpenBSD) || defined(__FreeBSD_version) || \
    defined(NetBSD) || defined(__DragonFly_version)
#define PRI_TIME_T		"d"
#endif

#if defined(__linux__)
#if defined(__x86_64__)
#define PRI_TIME_T		PRIu64
#else
#define PRI_TIME_T		"ld"
#endif
#endif

#if defined(__MACH__)
#define PRI_TIME_T		"ld"
#endif

#define LD_FLAGS_MAX	30
#define CFLAGS_MAX		30
#define CXXFLAGS_MAX	CFLAGS_MAX

#define BUILD_NOBUILD	0
#define BUILD_C			1
#define BUILD_CXX		2

struct cli_buf
{
    uint8_t *data;
    size_t	length;
    size_t	offset;
};

struct mime_type
{
    char *ext;
    char *type;
	TAILQ_ENTRY(mime_type)	list;
};

TAILQ_HEAD(mime_list, mime_type);

struct buildopt
{
    char *name;
    char *cf_source;
    char *cf_flavor;
    int	 flavor_nohttp;
    int	 single_binary;

    struct cli_buf *cflags;
    struct cli_buf *cxxflags;
    struct cli_buf *ldflags;
	TAILQ_ENTRY(buildopt)	list;
};

TAILQ_HEAD(buildopt_list, buildopt);

struct cmd
{
    const char *name;
    const char *descr;
    void (*cb)(int, char **);
};

struct filegen
{
    void (*cb)(void);
};

struct cfile
{
    struct stat st;
    int	build;
    char *name;
    char *fpath;
    char *opath;

	TAILQ_ENTRY(cfile)	list;
};

TAILQ_HEAD(cfile_list, cfile);

static struct cli_buf *cli_buf_alloc(size_t);
static void	cli_buf_free(struct cli_buf*);
static char	*cli_buf_stringify(struct cli_buf*, size_t*);
static void	cli_buf_append(struct cli_buf*, const void*, size_t);
static void	cli_buf_appendf(struct cli_buf*, const char*, ...);
static void	cli_buf_appendv(struct cli_buf*, const char*, va_list);
static int cli_proc_path(void*, size_t);

static void *cli_malloc(size_t);
static char	*cli_strdup(const char*);
static void	*cli_realloc(void*, size_t);

static char	*cli_text_trim(char*, size_t);
static char	*cli_read_line(FILE*, char*, size_t);
static long long cli_strtonum(const char*, long long, long long);
static int cli_split_string(char*, const char*, char**, size_t);

static void	cli_usage(void) __attribute__((noreturn));
static void	cli_fatal(const char *, ...) __attribute__((noreturn));

static void	cli_file_close(int);
static void	cli_run_zfrog(void);
static void	cli_generate_certs(void);
static void	cli_compile_zfrog(void*);
static void	cli_link_application(void*);
static void	cli_compile_source_file(void*);
static void	cli_mkdir(const char*, int);
static int	cli_dir_exists(const char*);
static int	cli_file_exists(const char*);
static void	cli_cleanup_files(const char*);
static void	cli_build_cflags(struct buildopt*);
static void	cli_build_cxxflags(struct buildopt*);
static void	cli_build_ldflags(struct buildopt*);
static void	cli_file_read(int, char**, size_t*);
static void	cli_file_writef(int, const char*, ...);
static void	cli_file_open(const char*, int, int*);
static void	cli_file_remove(char*, struct dirent*);
static void	cli_build_asset(char*, struct dirent*);
static void	cli_file_write(int, const void*, size_t);
static int	cli_vasprintf(char**, const char*, ...);
static void	cli_spawn_proc(void (*cb)(void *), void*);
static void	cli_write_asset(const char*, const char*,struct buildopt*);
static void	cli_register_file(char*, struct dirent*);
static void	cli_register_source_file(char*, struct dirent*);
static void	cli_file_create(const char*, const char*, size_t);
static int	cli_file_requires_build(struct stat *, const char*);
static void	cli_find_files(const char*, void (*cb)(char *, struct dirent*));
static void	cli_add_source_file(char*, char*, char*, struct stat*, int);

static struct buildopt* cli_buildopt_default(void);
static struct buildopt* cli_buildopt_new(const char*);
static struct buildopt* cli_buildopt_find(const char*);
static void	cli_buildopt_cleanup(void);
static void	cli_buildopt_parse(const char*);
static void	cli_buildopt_cflags(struct buildopt*, const char*);
static void	cli_buildopt_cxxflags(struct buildopt*, const char*);
static void	cli_buildopt_ldflags(struct buildopt *, const char*);
static void	cli_buildopt_single_binary(struct buildopt*, const char*);
static void	cli_buildopt_source(struct buildopt*, const char*);
static void	cli_buildopt_flavor(struct buildopt*, const char*);
static void	cli_buildopt_mime(struct buildopt*, const char*);

static void	cli_flavor_load(void);
static void	cli_flavor_change(const char*);
static void	cli_features(struct buildopt*, char**, size_t*);

static void	cli_run(int, char**);
static void	cli_help(int, char**);
static void	cli_info(int, char**);
static void	cli_build(int, char**);
static void	cli_clean(int, char**);
static void cli_distclean(int, char**);
static void	cli_create(int, char**);
static void	cli_reload(int, char**);
static void	cli_flavor(int, char**);

static void	file_create_src(void);
static void	file_create_config(void);

static struct cmd cmds[] = {
    { "help",	"this help text",                       cli_help },
	{ "run",	"run an application (-fnr implied)",	cli_run },
    { "reload",	"reload the application (SIGHUP)",      cli_reload },
    { "info",	"show info on zfrog on this system",	cli_info },
    { "build",	"build an application",                 cli_build },
    { "clean",	"cleanup the objects files",            cli_clean },
    { "distclean",	"cleanup the build files",          cli_distclean },
	{ "create",	"create a new application skeleton",	cli_create },
    { "flavor",	"switch between build flavors",         cli_flavor },
	{ NULL,		NULL,					NULL }
};

static struct filegen gen_files[] =
{
	{ file_create_src },
	{ file_create_config },
	{ NULL }
};

static const char *gen_dirs[] = {
	"src",
	"cert",
	"conf",
	"assets",
	NULL
};

static const char *http_serveable_function =
	"int\n"
	"asset_serve_%s_%s(struct http_request *req)\n"
	"{\n"
	"	http_serveable(req, asset_%s_%s, asset_len_%s_%s,\n"
	"	    asset_sha256_%s_%s, \"%s\");\n"
    "	return CF_RESULT_OK;\n"
	"}\n";

static const char *src_data =
    "#include <zfrog.h>\n"
    "#include <cf_http.h>\n"
	"\n"
	"int\t\tpage(struct http_request *);\n"
	"\n"
    "int page(struct http_request *req)\n"
	"{\n"
	"\thttp_response(req, 200, NULL, 0);\n"
    "\treturn CF_RESULT_OK;\n"
	"}\n";

static const char *config_data =
	"# %s configuration\n"
	"\n"
	"bind\t\t127.0.0.1 8888\n"
	"load\t\t./%s.so\n"
	"\n"
	"tls_dhparam\tdh2048.pem\n"
	"\n"
	"domain * {\n"
	"\tcertfile\tcert/server.pem\n"
	"\tcertkey\t\tcert/key.pem\n"
	"\n"
	"\tstatic\t/\tpage\n"
	"}\n";

static const char *build_data =
	"# %s build config\n"
    "# You can switch flavors using: zfrog_cli flavor [newflavor]\n"
	"\n"
	"# Set to yes if you wish to produce a single binary instead\n"
	"# of a dynamic library. If you set this to yes you must also\n"
    "# set cf_source together with cf_flavor.\n"
	"#single_binary=no\n"
    "#cf_source=\n"
    "#cf_flavor=\n"
	"\n"
	"# The flags below are shared between flavors\n"
	"cflags=-Wall -Wmissing-declarations -Wshadow\n"
	"cflags=-Wstrict-prototypes -Wmissing-prototypes\n"
	"cflags=-Wpointer-arith -Wcast-qual -Wsign-compare\n"
	"\n"
	"cxxflags=-Wall -Wmissing-declarations -Wshadow\n"
	"cxxflags=-Wpointer-arith -Wcast-qual -Wsign-compare\n"
	"\n"
	"# Mime types for assets served via the builtin asset_serve_*\n"
	"#mime_add=txt:text/plain; charset=utf-8\n"
	"#mime_add=png:image/png\n"
	"#mime_add=html:text/html; charset=utf-8\n"
	"\n"
	"dev {\n"
	"	# These flags are added to the shared ones when\n"
	"	# you build the \"dev\" flavor.\n"
	"	cflags=-g\n"
	"	cxxflags=-g\n"
	"}\n"
	"\n"
	"#prod {\n"
	"#	You can specify additional flags here which are only\n"
	"#	included if you build with the \"prod\" flavor.\n"
	"#}\n";

static const char *dh2048_data =
	"-----BEGIN DH PARAMETERS-----\n"
	"MIIBCAKCAQEAn4f4Qn5SudFjEYPWTbUaOTLUH85YWmmPFW1+b5bRa9ygr+1wfamv\n"
	"VKVT7jO8c4msSNikUf6eEfoH0H4VTCaj+Habwu+Sj+I416r3mliMD4SjNsUJrBrY\n"
	"Y0QV3ZUgZz4A8ARk/WwQcRl8+ZXJz34IaLwAcpyNhoV46iHVxW0ty8ND0U4DIku/\n"
	"PNayKimu4BXWXk4RfwNVP59t8DQKqjshZ4fDnbotskmSZ+e+FHrd+Kvrq/WButvV\n"
	"Bzy9fYgnUlJ82g/bziCI83R2xAdtH014fR63MpElkqdNeChb94pPbEdFlNUvYIBN\n"
	"xx2vTUQMqRbB4UdG2zuzzr5j98HDdblQ+wIBAg==\n"
	"-----END DH PARAMETERS-----";


static int			s_fd = -1;
static char			*appl = NULL;
static int			run_after = 0;
static char			*compiler_c = "gcc";
static char			*compiler_cpp = "g++";
static char			*compiler_ld = "gcc";
static struct mime_list	mime_types;
static struct cfile_list source_files;
static struct buildopt_list	build_options;
static int			source_files_count;
static int			cxx_files_count;
static struct cmd *command = NULL;
static int			cflags_count = 0;
static int			cxxflags_count = 0;
static int			ldflags_count = 0;
static char			*flavor = NULL;
static char			*cflags[CFLAGS_MAX];
static char			*cxxflags[CXXFLAGS_MAX];
static char			*ldflags[LD_FLAGS_MAX];

/****************************************************************
 *  Helper function to print out usage options
 ****************************************************************/
static void cli_usage(void)
{
    int	i;

    fprintf(stderr, "Usage: zfrog_cli [command]\n");
	fprintf(stderr, "\nAvailable commands:\n");

    for( i = 0; cmds[i].name != NULL; i++ )
		printf("\t%s\t%s\n", cmds[i].name, cmds[i].descr);

	exit(1);
}
/****************************************************************
 *  Main entry function pointer
 ****************************************************************/
int main(int argc, char **argv)
{
    int i;

    if( argc < 2 ) {
        cli_usage();
    }

	argc--;
	argv++;

    umask(S_IWGRP | S_IWOTH);

    for( i = 0; cmds[i].name != NULL; i++ )
    {
        if( !strcmp(argv[0], cmds[i].name) )
        {
			argc--;
			argv++;
			command = &cmds[i];
			cmds[i].cb(argc, argv);
			break;
		}
	}

    if( cmds[i].name == NULL )
    {
        fprintf(stderr, "Unknown command: %s\n", argv[0]);
        cli_usage();
	}

    return 0;
}
/*----------------------------------------------------------------------------*/
static void cli_help(int argc, char **argv)
{
    cli_usage();
}
/*----------------------------------------------------------------------------*/
static void cli_create(int argc, char **argv)
{
    int	i;
    char *fpath;

    if( argc != 1 ) {
        cli_fatal("missing application name");
    }

	appl = argv[0];
	cli_mkdir(appl, 0755);

    for( i = 0; gen_dirs[i] != NULL; i++ )
    {
        cli_vasprintf(&fpath, "%s/%s", appl, gen_dirs[i]);
		cli_mkdir(fpath, 0755);
		free(fpath);
	}

    for( i = 0; gen_files[i].cb != NULL; i++ )
		gen_files[i].cb();

    if( chdir(appl) == -1 ) {
        cli_fatal("chdir(%s): %s", appl, errno_s);
    }

	cli_generate_certs();

	printf("%s created successfully!\n", appl);
	printf("WARNING: DO NOT USE THE GENERATED DH PARAMETERS "
	    "AND CERTIFICATES IN PRODUCTION\n");
}

static void cli_flavor(int argc, char **argv)
{
    struct buildopt *bopt = NULL;
    char pwd[MAXPATHLEN], *conf;

    if( getcwd(pwd, sizeof(pwd)) == NULL ) {
        cli_fatal("could not get cwd: %s", errno_s);
    }

	appl = basename(pwd);
    cli_vasprintf(&conf, "conf/%s.conf", appl);

    if( !cli_dir_exists("conf") || !cli_file_exists(conf) )
        cli_fatal("%s doesn't appear to be a zfrog app", appl);

    free(conf);

	TAILQ_INIT(&build_options);
	TAILQ_INIT(&mime_types);
    cli_buildopt_new("_default");
	cli_buildopt_parse("conf/build.conf");

    if( argc == 0 )
    {
		cli_flavor_load();

        TAILQ_FOREACH(bopt, &build_options, list)
        {
            if( !strcmp(bopt->name, "_default") )
				continue;
            if( !strcmp(bopt->name, flavor) ) {
				printf("* %s\n", bopt->name);
            }
            else {
				printf("  %s\n", bopt->name);
			}
		}
    }
    else
    {
		cli_flavor_change(argv[0]);
		printf("changed build flavor to: %s\n", argv[0]);
	}

	cli_buildopt_cleanup();
}
/*----------------------------------------------------------------------------*/
static void cli_build( int argc, char **argv )
{
    struct dirent dp;
    struct cfile *cf = NULL;
    struct buildopt	*bopt = NULL;
    struct timeval times[2];
    char *build_path = NULL;
    int	requires_relink, l;
    char *sofile, *config, *data;
    char *assets_path, *p, *obj_path;
    char pwd[PATH_MAX], *src_path, *assets_header;
    char* build_appl_path = NULL;

    /* Get current working folder */
    if( getcwd(pwd, sizeof(pwd)) == NULL ) {
        cli_fatal("could not get cwd: %s", errno_s);
    }

    /* Try to use two incoming arguments: first working folder, second application name */
    if( argc > 1 )
    {
        if( !cli_dir_exists( argv[0] ) )
            cli_fatal("missing application folder");

        /* Change working dir */
        if( chdir(argv[0]) == -1 )
            cli_fatal("couldn't change directory to %s", argv[0]);

        build_appl_path = cli_strdup( argv[0] );

        /* Get application name */
        appl = argv[1];
    }
    else if( argc > 0 ) /* Try to use application name */
    {
        /* Get application name */
        appl = argv[0];

        cli_vasprintf( &build_appl_path, "%s/%s", pwd, appl );

        if( !cli_dir_exists(build_appl_path) )
            cli_fatal("missing application folder");

        /* Change working dir */
        if( chdir(build_appl_path) == -1 )
            cli_fatal("couldn't change directory to %s", build_appl_path);
    }
    else
    {
        appl = basename(pwd);
        build_appl_path = cli_strdup(".");
    }

    if( (p = getenv("CC")) != NULL )
    {
		compiler_c = p;
		compiler_ld = p;
	}

    if( (p = getenv("CXX")) != NULL )
    {
		compiler_cpp = p;
		compiler_ld = p;
	}

	source_files_count = 0;
	cxx_files_count = 0;
	TAILQ_INIT(&source_files);
	TAILQ_INIT(&build_options);
	TAILQ_INIT(&mime_types);

    cli_vasprintf(&src_path, "%s/src", build_appl_path);
    cli_vasprintf(&assets_path, "%s/assets", build_appl_path);
    cli_vasprintf(&config, "%s/conf/%s.conf", build_appl_path, appl);
    cli_vasprintf(&assets_header, "%s/src/assets.h", build_appl_path);
    cli_vasprintf(&build_path, "%s/conf/build.conf", build_appl_path);

    free( build_appl_path );

    if( !cli_dir_exists(src_path) || !cli_file_exists(config) ) {
        cli_fatal("%s doesn't appear to be a zfrog app", appl);
    }

	cli_flavor_load();
	bopt = cli_buildopt_new("_default");

    if( !cli_file_exists(build_path) )
    {
		l = cli_vasprintf(&data, build_data, appl);
		cli_file_create("conf/build.conf", data, l);
		free(data);
	}

	cli_find_files(src_path, cli_register_source_file);
	free(src_path);

	cli_buildopt_parse(build_path);
	free(build_path);

    cli_vasprintf(&obj_path, ".objs");
    if( !cli_dir_exists(obj_path) )
		cli_mkdir(obj_path, 0755);
	free(obj_path);

    if( bopt->single_binary )
    {
        if( bopt->cf_source == NULL )
            cli_fatal("single_binary set but not cf_source");

        printf("building zfrog (%s)\n", bopt->cf_source);
        cli_spawn_proc( cli_compile_zfrog, bopt );

        cli_vasprintf(&src_path, "%s/src", bopt->cf_source);
        cli_find_files(src_path, cli_register_file);
		free(src_path);
	}

	printf("building %s (%s)\n", appl, flavor);

	cli_build_cflags(bopt);
	cli_build_cxxflags(bopt);
	cli_build_ldflags(bopt);

    unlink( assets_header );

    /* Generate the assets */
	cli_file_open(assets_header, O_CREAT | O_TRUNC | O_WRONLY, &s_fd);
    cli_file_writef(s_fd, "#ifndef __H_CF_ASSETS_H\n");
    cli_file_writef(s_fd, "#define __H_CF_ASSETS_H\n");

    if( cli_dir_exists(assets_path) )
		cli_find_files(assets_path, cli_build_asset);

    if( bopt->single_binary )
    {
		memset(&dp, 0, sizeof(dp));
#ifndef __sun
        dp.d_type = DT_REG;
#endif
		printf("adding config %s\n", config);
        snprintf(dp.d_name, sizeof(dp.d_name), "builtin_zfrog.conf");
		cli_build_asset(config, &dp);
	}

	cli_file_writef(s_fd, "\n#endif\n");
	cli_file_close(s_fd);

    free( assets_path );
    free( config );

    if( cxx_files_count > 0 )
		compiler_ld = compiler_cpp;

	requires_relink = 0;
    TAILQ_FOREACH(cf, &source_files, list)
    {
        if( cf->build == BUILD_NOBUILD )
			continue;

		printf("compiling %s\n", cf->name);
		cli_spawn_proc(cli_compile_source_file, cf);

		times[0].tv_usec = 0;
		times[0].tv_sec = cf->st.st_mtime;
		times[1] = times[0];

        if( utimes(cf->opath, times) == -1 )
			printf("utime(%s): %s\n", cf->opath, errno_s);

		requires_relink++;
	}

    free( assets_header );

    if( bopt->cf_flavor == NULL || !strstr(bopt->cf_flavor, "NOTLS=1") )
    {
        if( !cli_dir_exists("cert") )
        {
            cli_mkdir("cert", 0700);
            cli_generate_certs();
        }
    }

    if( bopt->single_binary )
    {
		requires_relink++;
        cli_vasprintf(&sofile, "%s", appl);
    }
    else
        cli_vasprintf(&sofile, "%s.so", appl);

    if( !cli_file_exists(sofile) && source_files_count > 0 )
		requires_relink++;

	free(sofile);

    if( requires_relink )
    {
		cli_spawn_proc(cli_link_application, bopt);
		printf("%s built successfully!\n", appl);
    }
    else
		printf("nothing to be done!\n");

    if( run_after == 0 )
		cli_buildopt_cleanup();
}
/*----------------------------------------------------------------------------*/
static void cli_clean( int argc, char **argv )
{
    if( cli_dir_exists(".objs") )
		cli_cleanup_files(".objs");
}
/*----------------------------------------------------------------------------*/
static void cli_distclean(int argc, char **argv )
{
    char pwd[PATH_MAX], *sofile;

    /* Clean objects file first */
    cli_clean( argc, argv );

    if( getcwd(pwd, sizeof(pwd)) == NULL ) {
        cli_fatal("could not get cwd: %s", errno_s);
    }

    appl = basename(pwd);
    cli_vasprintf(&sofile, "%s.so", appl);
    if( unlink(sofile) == -1 && errno != ENOENT )
        printf("couldn't unlink %s: %s", sofile, errno_s);

    free( sofile );
}
/*----------------------------------------------------------------------------*/
static void cli_run(int argc, char **argv)
{
	run_after = 1;
	cli_build(argc, argv);

	/*
     * We are exec()'ing zfrog again, while we could technically set
	 * the right cli options manually and just continue running.
	 */
    cli_run_zfrog();
}
/*----------------------------------------------------------------------------*/
static void cli_reload(int argc, char **argv)
{
    int	fd;
    size_t len;
    pid_t pid;
    char *buf = NULL;

    cli_file_open("zfrog.pid", O_RDONLY, &fd);
	cli_file_read(fd, &buf, &len);
	cli_file_close(fd);

    if( len == 0 ) {
        cli_fatal("reload: pid file is empty");
    }

	buf[len - 1] = '\0';

	pid = cli_strtonum(buf, 0, UINT_MAX);

    if( kill(pid, SIGHUP) == -1 ) {
        cli_fatal("failed to reload: %s", errno_s);
    }

	printf("reloaded application\n");
}
/*----------------------------------------------------------------------------*/
static void cli_info( int argc, char **argv )
{
    size_t len;
    struct buildopt	*bopt = NULL;
    char *features = NULL;

	TAILQ_INIT(&mime_types);
	TAILQ_INIT(&build_options);

	cli_flavor_load();
	bopt = cli_buildopt_new("_default");
	cli_buildopt_parse("conf/build.conf");

	printf("active flavor\t %s\n", flavor);
    printf("output type  \t %s\n", (bopt->single_binary) ? "binary" : "dso");

    if( bopt->single_binary )
    {
        printf("zfrog source  \t %s\n", bopt->cf_source);
        printf("zfrog features\t %s\n", bopt->cf_flavor);
    }
    else
    {
        cli_features(bopt, &features, &len);
        printf("zfrog binary  \t %s/bin/zfrog\n", PREFIX);
        printf("zfrog features\t %.*s\n", (int)len, features);
		free(features);
	}
}
/*----------------------------------------------------------------------------*/
static void file_create_src(void)
{
    char *name = NULL;

    cli_vasprintf(&name, "%s/src/%s.c", appl, appl);
	cli_file_create(name, src_data, strlen(src_data));
	free(name);
}
/*----------------------------------------------------------------------------*/
static void file_create_config(void)
{
    int	l;
    char *name, *data;

    cli_vasprintf(&name, "%s/conf/%s.conf", appl, appl);
	l = cli_vasprintf(&data, config_data, appl, appl);
	cli_file_create(name, data, l);
	free(name);
	free(data);

    cli_vasprintf(&name, "%s/conf/build.conf", appl);
	l = cli_vasprintf(&data, build_data, appl);
	cli_file_create(name, data, l);
	free(name);
	free(data);
}
/*----------------------------------------------------------------------------*/
static void cli_mkdir( const char *fpath, int mode )
{
    if( mkdir(fpath, mode) == -1 )
        cli_fatal("cli_mkdir(%s): %s", fpath, errno_s);
}
/*----------------------------------------------------------------------------*/
static int cli_file_exists(const char *fpath)
{
    struct stat	st;

    if( stat(fpath, &st) == -1 )
        return 0;

    if( !S_ISREG(st.st_mode) )
        return 0;

    return 1;
}
/*----------------------------------------------------------------------------*/
static int cli_file_requires_build(struct stat *fst, const char *opath)
{
	struct stat	ost;

    if( stat(opath, &ost) == -1 )
    {
        if( errno == ENOENT )
            return 1;
        cli_fatal("stat(%s): %s", opath, errno_s);
	}

	return (fst->st_mtime != ost.st_mtime);
}
/*----------------------------------------------------------------------------*/
static int cli_dir_exists(const char *fpath)
{
    struct stat	st;

    if( stat(fpath, &st) == -1 )
        return 0;

    if( !S_ISDIR(st.st_mode) )
        return 0;

    return 1;
}
/*----------------------------------------------------------------------------*/
static void cli_file_open(const char *fpath, int flags, int *fd)
{
    if( (*fd = open(fpath, flags, 0644)) == -1 )
        cli_fatal("cli_file_open(%s): %s", fpath, errno_s);
}
/*----------------------------------------------------------------------------*/
static void cli_file_read(int fd, char **buf, size_t *len)
{
	struct stat	st;
    char *p = NULL;
    ssize_t	ret;
    size_t offset, bytes;

    if( fstat(fd, &st) == -1 ) {
        cli_fatal("fstat(): %s", errno_s);
    }

    if( st.st_size > USHRT_MAX ) {
        cli_fatal("cli_file_read: way too big");
    }

	offset = 0;
	bytes = st.st_size;
	p = cli_malloc(bytes);

    while( offset != bytes )
    {
		ret = read(fd, p + offset, bytes - offset);
        if( ret == -1 )
        {
			if (errno == EINTR)
				continue;
            cli_fatal("read(): %s", errno_s);
		}

        if( ret == 0 )
            cli_fatal("unexpected EOF");

		offset += (size_t)ret;
	}

	*buf = p;
	*len = bytes;
}
/*----------------------------------------------------------------------------*/
static void cli_file_close(int fd)
{
    if( close(fd) == -1 )
		printf("warning: close() %s\n", errno_s);
}
/*----------------------------------------------------------------------------*/
static void cli_file_writef(int fd, const char *fmt, ...)
{
    int	l;
    char *buf = NULL;
    va_list	args;

	va_start(args, fmt);
	l = vasprintf(&buf, fmt, args);
	va_end(args);

    if( l == -1 ) {
        cli_fatal("cli_file_writef");
    }

	cli_file_write(fd, buf, l);
	free(buf);
}
/*----------------------------------------------------------------------------*/
static void cli_file_write(int fd, const void *buf, size_t len)
{
    ssize_t	r;
    const uint8_t *d = buf;
    size_t written = 0;

    while( written != len )
    {
		r = write(fd, d + written, len - written);
        if( r == -1 )
        {
            if( errno == EINTR )
				continue;
            cli_fatal("cli_file_write: %s", errno_s);
		}

		written += r;
	}
}
/*----------------------------------------------------------------------------*/
static void cli_file_create(const char *name, const char *data, size_t len)
{
    int fd;

	cli_file_open(name, O_CREAT | O_TRUNC | O_WRONLY, &fd);
	cli_file_write(fd, data, len);
	cli_file_close(fd);

	printf("created %s\n", name);
}
/*----------------------------------------------------------------------------*/
static void cli_write_asset(const char *n, const char *e, struct buildopt *bopt)
{
    cli_file_writef(s_fd, "extern const uint8_t asset_%s_%s[];\n", n, e);
    cli_file_writef(s_fd, "extern const uint32_t asset_len_%s_%s;\n", n, e);
	cli_file_writef(s_fd, "extern const time_t asset_mtime_%s_%s;\n", n, e);
	cli_file_writef(s_fd, "extern const char *asset_sha256_%s_%s;\n", n, e);

    if( bopt->flavor_nohttp == 0 )
    {
        cli_file_writef(s_fd, "int asset_serve_%s_%s(struct http_request *);\n", n, e);
	}
}
/*----------------------------------------------------------------------------*/
static void cli_build_asset(char *fpath, struct dirent *dp)
{
    struct stat st;
    SHA256_CTX sctx;
    off_t off;
    void *base = NULL;
    struct mime_type *mime = NULL;
    struct buildopt *bopt = NULL;
    const char *mime_type;
    int in, out, i, len;
    uint8_t *d, digest[SHA256_DIGEST_LENGTH];
    char *cpath, *ext, *opath, *p, *name;
    char hash[(SHA256_DIGEST_LENGTH * 2) + 1];

	bopt = cli_buildopt_default();

    /* Ignore hidden files and some editor files */
    if( dp->d_name[0] == '.' || strrchr(dp->d_name, '~') || strrchr(dp->d_name, '#') ) {
        return;
    }

	name = cli_strdup(dp->d_name);

	/* Grab the extension as we're using it in the symbol name. */
    if( (ext = strrchr(name, '.')) == NULL ) {
        cli_fatal("couldn't find ext in %s", name);
    }

	/* Replace dots, spaces, etc etc with underscores. */
    for( p = name; *p != '\0'; p++ ) {
        if( *p == '.' || isspace(*p) || *p == '-' )
			*p = '_';
	}

    /* Grab inode information */
    if( stat(fpath, &st) == -1 )
        cli_fatal("stat: %s %s", fpath, errno_s);

    /* If this file was empty, skip it */
    if( st.st_size == 0 )
    {
		printf("skipping empty asset %s\n", name);
        free( name );
		return;
	}

    cli_vasprintf(&opath, ".objs/%s.o", name);
    cli_vasprintf(&cpath, ".objs/%s.c", name);

    /* Check if the file needs to be built */
    if( !cli_file_requires_build(&st, opath) )
    {
		*(ext)++ = '\0';
		cli_write_asset(name, ext, bopt);
		*ext = '_';

		cli_add_source_file(name, cpath, opath, &st, BUILD_NOBUILD);
		free(name);
		return;
	}

    /* Open the file we're converting */
	cli_file_open(fpath, O_RDONLY, &in);

    /* mmap our in file */
    if( (base = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, in, 0)) == MAP_FAILED )
        cli_fatal("mmap: %s %s", fpath, errno_s);

    /* Create the c file where we will write too */
	cli_file_open(cpath, O_CREAT | O_TRUNC | O_WRONLY, &out);

    /* No longer need name so cut off the extension */
	printf("building asset %s\n", dp->d_name);
	*(ext)++ = '\0';

    /* Start generating the file */
	cli_file_writef(out, "/* Auto generated */\n");
	cli_file_writef(out, "#include <sys/types.h>\n\n");
    cli_file_writef(out, "#include <zfrog.h>\n");
    cli_file_writef(out, "#include <cf_http.h>\n\n");
	cli_file_writef(out, "#include \"assets.h\"\n\n");

    /* Write the file data as a byte array */
	cli_file_writef(out, "const u_int8_t asset_%s_%s[] = {\n", name, ext);
	d = base;
    for( off = 0; off < st.st_size; off++ )
		cli_file_writef(out, "0x%02x,", *d++);

	/*
	 * Always NUL-terminate the asset, even if this NUL is not included in
	 * the actual length. This way assets can be cast to char * without
     * any additional thinking for the developer
	 */
	cli_file_writef(out, "0x00");

    /* Calculate the SHA256 digest of the contents */
    SHA256_Init(&sctx);
    SHA256_Update(&sctx, base, st.st_size);
    SHA256_Final(digest, &sctx);

    for( i = 0; i < (int)sizeof(digest); i++ )
    {
        len = snprintf(hash + (i * 2), sizeof(hash) - (i * 2), "%02x", digest[i]);
        if( len == -1 || (size_t)len >= sizeof(hash) )
            cli_fatal("failed to convert SHA256 digest to hex");
	}

	mime = NULL;
    TAILQ_FOREACH(mime, &mime_types, list)
    {
        if( !strcasecmp(mime->ext, ext) )
			break;
	}

    if( mime != NULL )
		mime_type = mime->type;
	else
		mime_type = "text/plain";

    /* Add the meta data */
	cli_file_writef(out, "};\n\n");
    cli_file_writef(out, "const u_int32_t asset_len_%s_%s = %" PRIu32 ";\n", name, ext, (u_int32_t)st.st_size );
    cli_file_writef(out, "const time_t asset_mtime_%s_%s = %" PRI_TIME_T ";\n", name, ext, st.st_mtime );

    if( bopt->flavor_nohttp == 0 )
    {
        cli_file_writef(out, "const char *asset_sha256_%s_%s = \"\\\"%s\\\"\";\n", name, ext, hash);
        cli_file_writef(out, http_serveable_function, name, ext, name, ext, name, ext, name, ext, mime_type);
	}

	/* Write the file symbols into assets.h so they can be used. */
	cli_write_asset(name, ext, bopt);

    /* Cleanup static file source */
    if( munmap(base, st.st_size) == -1 ) {
        cli_fatal("munmap: %s %s", fpath, errno_s);
    }

	/* Cleanup fds */
	cli_file_close(in);
	cli_file_close(out);

	/* Restore the original name */
	*--ext = '.';

    /* Register the .c file now (cpath is free'd later) */
	cli_add_source_file(name, cpath, opath, &st, BUILD_C);
	free(name);
}
/*----------------------------------------------------------------------------*/
static void cli_add_source_file(char* name, char* fpath, char* opath, struct stat* st, int build)
{
    struct cfile *cf = NULL;

	source_files_count++;
	cf = cli_malloc(sizeof(*cf));

	cf->st = *st;
	cf->build = build;
	cf->fpath = fpath;
	cf->opath = opath;
	cf->name = cli_strdup(name);

	TAILQ_INSERT_TAIL(&source_files, cf, list);
}
/*----------------------------------------------------------------------------*/
static void cli_register_source_file(char* fpath, struct dirent* dp)
{
    struct stat st;
    char *ext, *opath;
    int	build;

    if( (ext = strrchr(fpath, '.')) == NULL || (strcmp(ext, ".c") && strcmp(ext, ".cpp")) )
		return;

    if( stat(fpath, &st) == -1 )
        cli_fatal("stat(%s): %s", fpath, errno_s);

    if( !strcmp(ext, ".cpp") )
		cxx_files_count++;

    cli_vasprintf(&opath, ".objs/%s.o", dp->d_name);

    if( !cli_file_requires_build(&st, opath) )
    {
		build = BUILD_NOBUILD;
    }
    else if (!strcmp(ext, ".cpp"))
    {
		build = BUILD_CXX;
    }
    else
    {
		build = BUILD_C;
	}

	cli_add_source_file(dp->d_name, fpath, opath, &st, build);
}
/*----------------------------------------------------------------------------*/
static void cli_register_file( char* fpath, struct dirent* dp )
{
    struct stat st, ost;
    char *opath, *ext, *fname;

    if( (ext = strrchr(fpath, '.')) == NULL || strcmp(ext, ".c") )
		return;

    if( stat(fpath, &st) == -1 ) {
        cli_fatal("stat(%s): %s", fpath, errno_s);
    }

	*ext = '\0';
    if( (fname = basename(fpath)) == NULL )
        cli_fatal("basename failed");

    cli_vasprintf(&opath, ".objs/%s.o", fname);

    /* Silently ignore non existing object files for zfrog source files. */
    if( stat(opath, &ost) == -1 )
    {
		free(opath);
		return;
	}

	cli_add_source_file(dp->d_name, fpath, opath, &st, BUILD_NOBUILD);
}
/*----------------------------------------------------------------------------*/
static void cli_file_remove(char *fpath, struct dirent *dp)
{
    if( unlink(fpath) == -1 )
		fprintf(stderr, "couldn't unlink %s: %s", fpath, errno_s);
}
/*----------------------------------------------------------------------------*/
static void cli_find_files(const char *path, void (*cb)(char *, struct dirent *))
{
    DIR	*d = NULL;
    struct stat	st;
    struct dirent *dp = NULL;
    char *fpath = NULL;

    if( (d = opendir(path)) == NULL )
        cli_fatal("cli_find_files: opendir(%s): %s", path, errno_s);

    while( (dp = readdir(d)) != NULL )
    {
        if( !strcmp(dp->d_name, ".") || !strcmp(dp->d_name, "..") )
			continue;

        cli_vasprintf(&fpath, "%s/%s", path, dp->d_name);

        if( stat(fpath, &st) == -1 )
        {
			fprintf(stderr, "stat(%s): %s\n", fpath, errno_s);
			free(fpath);
			continue;
		}

        if( S_ISDIR(st.st_mode) )
        {
			cli_find_files(fpath, cb);
			free(fpath);
        }
        else if( S_ISREG(st.st_mode) )
        {
			cb(fpath, dp);
        }
        else
        {
			fprintf(stderr, "ignoring %s\n", fpath);
			free(fpath);
		}
	}

	closedir(d);
}
/*----------------------------------------------------------------------------*/
static void cli_generate_certs(void)
{
    BIGNUM	*e;
    FILE *fp = NULL;
    time_t now;
    X509_NAME *name = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *x509 = NULL;
    RSA	*kpair = NULL;
    char issuer[64];

    /* Write out DH parameters */
	cli_file_create("dh2048.pem", dh2048_data, strlen(dh2048_data));

    /* Create new certificate */
    if( (x509 = X509_new()) == NULL )
        cli_fatal("X509_new(): %s", ssl_errno_s);

    /* Generate version 3 */
    if( !X509_set_version(x509, 2) )
        cli_fatal("X509_set_version(): %s", ssl_errno_s);

	/* Generate RSA keys. */
    if( (pkey = EVP_PKEY_new()) == NULL )
        cli_fatal("EVP_PKEY_new(): %s", ssl_errno_s);

    if( (kpair = RSA_new()) == NULL )
        cli_fatal("RSA_new(): %s", ssl_errno_s);

    if( (e = BN_new()) == NULL )
        cli_fatal("BN_new(): %s", ssl_errno_s);

    if( !BN_set_word(e, 65537) )
        cli_fatal("BN_set_word(): %s", ssl_errno_s);

    if( !RSA_generate_key_ex(kpair, 2048, e, NULL) )
        cli_fatal("RSA_generate_key_ex(): %s", ssl_errno_s);

    BN_free( e );

    if( !EVP_PKEY_assign_RSA(pkey, kpair) )
        cli_fatal("EVP_PKEY_assign_RSA(): %s", ssl_errno_s);

    /* Set serial number to current timestamp */
	time(&now);
    if( !ASN1_INTEGER_set(X509_get_serialNumber(x509), now) )
        cli_fatal("ASN1_INTEGER_set(): %s", ssl_errno_s);

    /* Not before and not after dates */
    if( !X509_gmtime_adj(X509_get_notBefore(x509), 0) )
        cli_fatal("X509_gmtime_adj(): %s", ssl_errno_s);

    if( !X509_gmtime_adj(X509_get_notAfter(x509), (long)60 * 60 * 24 * 3000) )
        cli_fatal("X509_gmtime_adj(): %s", ssl_errno_s);

    /* Attach the pkey to the certificate */
    if( !X509_set_pubkey(x509, pkey) )
        cli_fatal("X509_set_pubkey(): %s", ssl_errno_s);

    /* Set certificate information */
    if( (name = X509_get_subject_name(x509)) == NULL )
        cli_fatal("X509_get_subject_name(): %s", ssl_errno_s);

    snprintf(issuer, sizeof(issuer), "zfrog autogen: %s", appl);

    if( !X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char *)"RU", -1, -1, 0) )
        cli_fatal("X509_NAME_add_entry_by_txt(): C %s", ssl_errno_s);

    if( !X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char *)issuer, -1, -1, 0) )
        cli_fatal("X509_NAME_add_entry_by_txt(): O %s", ssl_errno_s);

    if( !X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char *)"localhost", -1, -1, 0) )
        cli_fatal("X509_NAME_add_entry_by_txt(): CN %s", ssl_errno_s);

    if( !X509_set_issuer_name(x509, name) )
        cli_fatal("X509_set_issuer_name(): %s", ssl_errno_s);

    if( !X509_sign(x509, pkey, EVP_sha256()) )
        cli_fatal("X509_sign(): %s", ssl_errno_s);

    if( (fp = fopen("cert/key.pem", "w")) == NULL )
        cli_fatal("fopen(cert/key.pem): %s", errno_s);

    if( !PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) )
        cli_fatal("PEM_write_PrivateKey(): %s", ssl_errno_s);

    fclose(fp);

    if( (fp = fopen("cert/server.pem", "w")) == NULL )
        cli_fatal("fopen(cert/server.pem): %s", errno_s);

    if( !PEM_write_X509(fp, x509) ) {
        cli_fatal("PEM_write_X509(%s)", errno_s);
    }

	fclose(fp);

	EVP_PKEY_free(pkey);
	X509_free(x509);
}
/*----------------------------------------------------------------------------*/
static void cli_compile_source_file(void *arg)
{
    struct cfile *cf = NULL;
    int	idx, i;
    char **flags;
    char *compiler = NULL;
    int	flags_count;
    char *args[32 + CFLAGS_MAX];

	cf = arg;

    switch( cf->build )
    {
	case BUILD_C:
		compiler = compiler_c;
		flags = cflags;
		flags_count = cflags_count;
		break;
	case BUILD_CXX:
		compiler = compiler_cpp;
		flags = cxxflags;
		flags_count = cxxflags_count;
		break;
	default:
        cli_fatal("cli_compile_file: unexpected file type: %d", cf->build);
		break;
	}

	idx = 0;
	args[idx++] = compiler;

	for (i = 0; i < flags_count; i++)
		args[idx++] = flags[i];

	args[idx++] = "-c";
	args[idx++] = cf->fpath;
	args[idx++] = "-o";
	args[idx++] = cf->opath;
	args[idx] = NULL;

	execvp(compiler, args);
    cli_fatal("failed to start '%s': %s", compiler, errno_s);
}
/*----------------------------------------------------------------------------*/
static void cli_link_application(void *arg)
{
    struct cfile *cf = NULL;
    struct buildopt	*bopt = NULL;
    int	idx, i;
    char *output = NULL;
    char *args[source_files_count + 11 + LD_FLAGS_MAX];

	bopt = arg;

    if( bopt->single_binary )
        cli_vasprintf(&output, "%s", appl);
	else
        cli_vasprintf(&output, "%s.so", appl);

	idx = 0;
	args[idx++] = compiler_ld;

	TAILQ_FOREACH(cf, &source_files, list)
		args[idx++] = cf->opath;

    for( i = 0; i < ldflags_count; i++ )
		args[idx++] = ldflags[i];

	args[idx++] = "-o";
	args[idx++] = output;
	args[idx] = NULL;

	execvp(compiler_ld, args);
    cli_fatal("failed to start '%s': %s", compiler_ld, errno_s);
}
/*----------------------------------------------------------------------------*/
static void cli_compile_zfrog( void *arg )
{
    struct buildopt *bopt = arg;
    int	idx, i, fcnt;
    char *obj, *args[20], pwd[MAXPATHLEN], *flavors[7];

    if( getcwd(pwd, sizeof(pwd)) == NULL )
        cli_fatal("could not get cwd: %s", errno_s);

    cli_vasprintf(&obj, "OBJDIR=%s/.objs", pwd);

    if( putenv(obj) != 0 ) {
        cli_fatal("cannot set OBJDIR for building zfrog");
    }

    fcnt = cli_split_string(bopt->cf_flavor, " ", flavors, 7);

#if defined(OpenBSD) || defined(__FreeBSD_version) || \
    defined(NetBSD) || defined(__DragonFly_version)
	args[0] = "gmake";
#else
	args[0] = "make";
#endif

	args[1] = "-s";
	args[2] = "-C";
    args[3] = bopt->cf_source;
	args[4] = "objects";

	idx = 5;
    for( i = 0; i < fcnt; i++ )
    {
		printf("using flavor %s\n", flavors[i]);
		args[idx++] = flavors[i];
	}

    args[idx++] = "CF_SINGLE_BINARY=1";
	args[idx] = NULL;

	execvp(args[0], args);
    cli_fatal("failed to start '%s': %s", args[0], errno_s);
}
/*----------------------------------------------------------------------------*/
static void cli_run_zfrog(void)
{
    struct buildopt	*bopt = NULL;
    char *args[4], *cpath, *cmd, *flags;

	bopt = cli_buildopt_default();

    if( bopt->single_binary )
    {
		cpath = NULL;
		flags = "-fnr";
        cli_vasprintf(&cmd, "./%s", appl);
    }
    else
    {
		flags = "-fnrc";
        cli_vasprintf(&cmd, "%s/bin/zfrog", PREFIX);
        cli_vasprintf(&cpath, "conf/%s.conf", appl);
	}

	args[0] = cmd;
	args[1] = flags;

    if( cpath != NULL )
    {
		args[2] = cpath;
		args[3] = NULL;
    }
    else
		args[2] = NULL;

	execvp(args[0], args);
    cli_fatal("failed to start '%s': %s", args[0], errno_s);
}
/*----------------------------------------------------------------------------*/
static void cli_buildopt_parse( const char* path )
{
    FILE* fp = NULL;
    const char* env = NULL;
    struct buildopt* bopt = NULL;
    char buf[BUFSIZ], *p, *t;

    if( (fp = fopen(path, "r")) == NULL ) {
        cli_fatal("cli_buildopt_parse: fopen(%s): %s", path, errno_s);
    }

	bopt = NULL;

    while( (p = cli_read_line(fp, buf, sizeof(buf))) != NULL )
    {
        if( strlen(p) == 0 )
			continue;

        if( bopt != NULL && !strcmp(p, "}") )
        {
			bopt = NULL;
			continue;
		}

        if( bopt == NULL )
        {
            if( (t = strchr(p, '=')) == NULL )
            {
                if( (t = strchr(p, ' ')) == NULL )
                    cli_fatal("unexpected '%s'", p);

                *(t)++ = '\0';

                if( strcmp(t, "{") )
                    cli_fatal("expected '{', got '%s'", t);

                bopt = cli_buildopt_new(p);
                continue;
            }
		}
        else if( (t = strchr(p, '=')) == NULL )
        {
			printf("bad buildopt line: '%s'\n", p);
			continue;
		}

		*(t)++ = '\0';

		p = cli_text_trim(p, strlen(p));
		t = cli_text_trim(t, strlen(t));

        if( !strcasecmp(p, "cflags") )
			cli_buildopt_cflags(bopt, t);
        else if( !strcasecmp(p, "cxxflags") )
			cli_buildopt_cxxflags(bopt, t);
        else if( !strcasecmp(p, "ldflags") )
			cli_buildopt_ldflags(bopt, t);
        else if( !strcasecmp(p, "single_binary") )
			cli_buildopt_single_binary(bopt, t);
        else if( !strcasecmp(p, "cf_source") )
            cli_buildopt_source(bopt, t);
        else if( !strcasecmp(p, "cf_flavor") )
            cli_buildopt_flavor(bopt, t);
        else if( !strcasecmp(p, "mime_add") )
			cli_buildopt_mime(bopt, t);
        else
			printf("ignoring unknown option '%s'\n", p);
	}

    /* Close configuration file */
    fclose( fp );

    if( (env = getenv("ZFROG_SOURCE")) != NULL )
        cli_buildopt_source(NULL, env);

    if( (env = getenv("ZFROG_FLAVOR")) != NULL )
        cli_buildopt_flavor(NULL, env);
}
/*----------------------------------------------------------------------------*/
static struct buildopt* cli_buildopt_new(const char *name)
{
    struct buildopt	*bopt = NULL;

	bopt = cli_malloc(sizeof(*bopt));
	bopt->cflags = NULL;
	bopt->cxxflags = NULL;
	bopt->ldflags = NULL;
	bopt->flavor_nohttp = 0;
	bopt->single_binary = 0;
    bopt->cf_source = NULL;
    bopt->cf_flavor = NULL;
	bopt->name = cli_strdup(name);

	TAILQ_INSERT_TAIL(&build_options, bopt, list);
    return bopt;
}
/*----------------------------------------------------------------------------*/
static struct buildopt* cli_buildopt_find(const char *name)
{
    struct buildopt	*bopt = NULL;

    TAILQ_FOREACH(bopt, &build_options, list)
    {
        if( !strcmp(bopt->name, name) )
            return bopt;
	}

    return NULL;
}
/*----------------------------------------------------------------------------*/
static struct buildopt * cli_buildopt_default(void)
{
    struct buildopt	*bopt = NULL;

    if( (bopt = cli_buildopt_find("_default")) == NULL )
        cli_fatal("no _default buildopt options");

    return bopt;
}
/*----------------------------------------------------------------------------*/
static void cli_buildopt_cleanup(void)
{
    struct buildopt *bopt, *next;
    struct mime_type *mime, *mnext;

    for( bopt = TAILQ_FIRST(&build_options); bopt != NULL; bopt = next )
    {
		next = TAILQ_NEXT(bopt, list);
		TAILQ_REMOVE(&build_options, bopt, list);

        if( bopt->cflags != NULL )
			cli_buf_free(bopt->cflags);
        if( bopt->cxxflags != NULL )
			cli_buf_free(bopt->cxxflags);
        if( bopt->ldflags != NULL )
			cli_buf_free(bopt->ldflags);
        if( bopt->cf_source != NULL )
            free(bopt->cf_source);
        if( bopt->cf_flavor != NULL )
            free(bopt->cf_flavor);

		free(bopt);
	}

    for( mime = TAILQ_FIRST(&mime_types); mime != NULL; mime = mnext )
    {
		mnext = TAILQ_NEXT(mime, list);
		TAILQ_REMOVE(&mime_types, mime, list);
		free(mime->type);
		free(mime->ext);
		free(mime);
	}
}
/*----------------------------------------------------------------------------*/
static void cli_buildopt_cflags(struct buildopt *bopt, const char *string)
{
    if( bopt == NULL )
		bopt = cli_buildopt_default();

    if( bopt->cflags == NULL )
		bopt->cflags = cli_buf_alloc(128);

	cli_buf_appendf(bopt->cflags, "%s ", string);
}
/*----------------------------------------------------------------------------*/
static void cli_buildopt_cxxflags(struct buildopt *bopt, const char *string)
{
    if( bopt == NULL )
		bopt = cli_buildopt_default();

    if( bopt->cxxflags == NULL )
		bopt->cxxflags = cli_buf_alloc(128);

	cli_buf_appendf(bopt->cxxflags, "%s ", string);
}
/*----------------------------------------------------------------------------*/
static void cli_buildopt_ldflags(struct buildopt *bopt, const char *string)
{
    if( bopt == NULL )
		bopt = cli_buildopt_default();

    if( bopt->ldflags == NULL )
		bopt->ldflags = cli_buf_alloc(128);

	cli_buf_appendf(bopt->ldflags, "%s ", string);
}
/*----------------------------------------------------------------------------*/
static void cli_buildopt_single_binary(struct buildopt *bopt, const char *string)
{
    if( bopt == NULL )
		bopt = cli_buildopt_default();
	else
        cli_fatal("single_binary only supported in global context");

    if( !strcmp(string, "yes") )
		bopt->single_binary = 1;
	else
		bopt->single_binary = 0;
}
/*----------------------------------------------------------------------------*/
static void cli_buildopt_source(struct buildopt *bopt, const char *string)
{
    if( bopt == NULL )
		bopt = cli_buildopt_default();
	else
        cli_fatal("cf_source only supported in global context");

    if( bopt->cf_source != NULL )
        free(bopt->cf_source);

    bopt->cf_source = cli_strdup(string);
}
/*----------------------------------------------------------------------------*/
static void cli_buildopt_flavor(struct buildopt *bopt, const char *string)
{
    int	cnt, i;
    char *p, *copy, *flavors[10];

    if( bopt == NULL )
		bopt = cli_buildopt_default();
	else
        cli_fatal("cf_flavor only supported in global context");

    if( bopt->cf_flavor != NULL ) {
        free(bopt->cf_flavor);
    }

	copy = cli_strdup(string);
	cnt = cli_split_string(copy, " ", flavors, 10);

    for( i = 0; i < cnt; i++ )
    {
        if( (p = strchr(flavors[i], '=')) == NULL )
            cli_fatal("invalid flavor %s", string);

		*p = '\0';

        if( !strcmp(flavors[i], "NOHTTP") )
			bopt->flavor_nohttp = 1;
	}

    bopt->cf_flavor = cli_strdup(string);
	free(copy);
}
/*----------------------------------------------------------------------------*/
static void cli_buildopt_mime(struct buildopt *bopt, const char *ext)
{
    struct mime_type *mime = NULL;
    char *type = NULL;

    if( bopt == NULL )
		bopt = cli_buildopt_default();
	else
        cli_fatal("mime_add only supported in global context");

    if( (type = strchr(ext, ':')) == NULL ) {
        cli_fatal("no type given in %s", ext);
    }

	*(type)++ = '\0';
    TAILQ_FOREACH(mime, &mime_types, list)
    {
        if( !strcmp(mime->ext, ext) )
            cli_fatal("duplicate extension %s found", ext);
	}

	mime = cli_malloc(sizeof(*mime));
	mime->ext = cli_strdup(ext);
	mime->type = cli_strdup(type);

	TAILQ_INSERT_TAIL(&mime_types, mime, list);
}
/* ----------------------------------------------------------------------------*/
static void cli_build_flags_common( struct buildopt *bopt, struct cli_buf *buf )
{
    size_t len = 0;
    char *data = NULL;
    char* path = NULL;  /* Temporary path variable */
    char pwd[PATH_MAX]; /* Current exe path */

    /* Get current exe startup path */
    cli_proc_path( pwd, sizeof(pwd) );

    /* Add global includes */
    cli_buf_appendf(buf, "-fPIC -Isrc -Isrc/include -Iobj/include ");

    /* Try to find  include folder in 'PREFIX' */
    cli_vasprintf(&path, "%s/include", PREFIX);

    if( cli_dir_exists( path ) )
        cli_buf_appendf(buf, "-I%s/include ", PREFIX);

    /* Delete temporary buffer */
    free( path );

    /* Try to find 'include' folder in startup folder */
    cli_vasprintf(&path, "%s/include", pwd);

    if( cli_dir_exists( path ) )
    {
        cli_buf_appendf(buf, "-I%s/include ", pwd);
        cli_buf_appendf(buf, "-I%s/include/cstl ", pwd);
    }

    /* Delete temporary buffer */
    free( path );

    /* Try to find 'include' folder in startup folder */
    cli_vasprintf(&path, "%s/obj/include", pwd);

    if( cli_dir_exists( path ) )
        cli_buf_appendf(buf, "-I%s/obj/include ", pwd);

    /* Delete temporary buffer */
    free( path );

#if defined(__MACH__)
	/* Add default openssl include path from homebrew / ports under OSX. */
	cli_buf_appendf(buf, "-I/opt/local/include ");
	cli_buf_appendf(buf, "-I/usr/local/opt/openssl/include ");
#endif

    if( bopt->single_binary == 0 )
    {
        cli_features(bopt, &data, &len);
		cli_buf_append(buf, data, len);
		cli_buf_appendf(buf, " ");
		free(data);
	}
}
/* ----------------------------------------------------------------------------*/
static void cli_build_cflags( struct buildopt *bopt )
{
    size_t len;
    struct buildopt *obopt = NULL;
    char *string, *buf;

    if( (obopt = cli_buildopt_find(flavor)) == NULL )
        cli_fatal("no such build flavor: %s", flavor);

    if( bopt->cflags == NULL )
		bopt->cflags = cli_buf_alloc(128);

    /* Add common */
	cli_build_flags_common(bopt, bopt->cflags);

    if( obopt != NULL && obopt->cflags != NULL )
    {
        cli_buf_append(bopt->cflags, obopt->cflags->data, obopt->cflags->offset);
	}

    if( bopt->single_binary )
    {
        cli_features(bopt, &buf, &len);
		cli_buf_append(bopt->cflags, buf, len);
		cli_buf_appendf(bopt->cflags, " ");
		free(buf);
	}

	string = cli_buf_stringify(bopt->cflags, NULL);
	printf("CFLAGS=%s\n", string);
	cflags_count = cli_split_string(string, " ", cflags, CFLAGS_MAX);
}
/* ----------------------------------------------------------------------------*/
static void cli_build_cxxflags(struct buildopt *bopt)
{
    struct buildopt *obopt = NULL;
    char *string = NULL;

    if( (obopt = cli_buildopt_find(flavor)) == NULL )
        cli_fatal("no such build flavor: %s", flavor);

    if( bopt->cxxflags == NULL )
		bopt->cxxflags = cli_buf_alloc(128);

	cli_build_flags_common(bopt, bopt->cxxflags);

    if( obopt != NULL && obopt->cxxflags != NULL )
    {
        cli_buf_append(bopt->cxxflags, obopt->cxxflags->data, obopt->cxxflags->offset);
	}

	string = cli_buf_stringify(bopt->cxxflags, NULL);
    if( cxx_files_count > 0 )
		printf("CXXFLAGS=%s\n", string);

	cxxflags_count = cli_split_string(string, " ", cxxflags, CXXFLAGS_MAX);
}
/* ----------------------------------------------------------------------------*/
static void cli_build_ldflags( struct buildopt *bopt )
{
    int	fd;
    size_t len;
    struct buildopt *obopt;
    char *string, *buf;

    if( (obopt = cli_buildopt_find(flavor)) == NULL )
        cli_fatal("no such build flavor: %s", flavor);

    if( bopt->ldflags == NULL )
		bopt->ldflags = cli_buf_alloc(128);

    if( bopt->single_binary == 0 )
    {
#if defined(__MACH__)
        cli_buf_appendf(bopt->ldflags, "-dynamiclib -undefined suppress -flat_namespace ");
#else
		cli_buf_appendf(bopt->ldflags, "-shared ");
#endif
    }
    else
    {
        cli_file_open(".obj/ldflags", O_RDONLY, &fd);
		cli_file_read(fd, &buf, &len);
		cli_file_close(fd);
        if( len == 0 )
            cli_fatal(".obj/ldflags is empty");
        len--;

		cli_buf_append(bopt->ldflags, buf, len);
		cli_buf_appendf(bopt->ldflags, " ");
        free( buf );
	}

    if( obopt != NULL && obopt->ldflags != NULL )
    {
        cli_buf_append(bopt->ldflags, obopt->ldflags->data, obopt->ldflags->offset);
    }

	string = cli_buf_stringify(bopt->ldflags, NULL);
	printf("LDFLAGS=%s\n", string);
	ldflags_count = cli_split_string(string, " ", ldflags, LD_FLAGS_MAX);
}
/* ----------------------------------------------------------------------------*/
static void cli_flavor_load(void)
{
    FILE *fp = NULL;
    char buf[BUFSIZ], pwd[MAXPATHLEN], *p, *conf;

    if( getcwd(pwd, sizeof(pwd)) == NULL ) {
        cli_fatal("could not get cwd: %s", errno_s);
    }

	appl = basename(pwd);

    if( appl == NULL ) {
        cli_fatal("basename: %s", errno_s);
    }

	appl = cli_strdup(appl);
    cli_vasprintf(&conf, "conf/%s.conf", appl);

    if( !cli_dir_exists("conf") || !cli_file_exists(conf) )
        cli_fatal("%s doesn't appear to be a zfrog app", appl);

    free( conf );

    if( (fp = fopen(".flavor", "r")) == NULL )
    {
		flavor = cli_strdup("dev");
		return;
	}

    if( fgets(buf, sizeof(buf), fp) == NULL )
        cli_fatal("failed to read flavor from file");

    if( (p = strchr(buf, '\n')) != NULL )
		*p = '\0';

	flavor = cli_strdup(buf);
    fclose(fp);
}
/* ----------------------------------------------------------------------------*/
static void cli_features( struct buildopt *bopt, char **out, size_t *outlen )
{
    int	fd;
    size_t len;
    char *path = NULL;
    char *data = NULL;

    if( bopt->single_binary )
    {
        cli_vasprintf(&path, ".obj/features");
    }
    else
    {
        /* Try to find first installed zfrog features */
        cli_vasprintf(&path, "%s/share/zfrog/features", PREFIX);

        if( !cli_file_exists( path ) )
        {
            char pwd[PATH_MAX]; /* current folder build <app name>*/

            if( getcwd(pwd, sizeof(pwd)) == NULL ) {
                cli_fatal("could not get cwd: %s", errno_s);
            }

            /* Delete temporary path buffer */
            free( path );
            path = NULL;

            /* Try to find in local folder */
            cli_vasprintf(&path, "%s/features", pwd);

            if( !cli_file_exists( path ) )
            {
                /* Try to find 'features' in exe path */
                if( !cli_proc_path( pwd, sizeof(pwd) ) )
                {
                    /* Delete temporary path buffer */
                    free( path );
                    path = NULL;

                    /* Try to find in local folder */
                    cli_vasprintf(&path, "%s/features", pwd);

                    if( !cli_file_exists( path ) )
                        cli_fatal("failed to find 'features' file in path [%s]", pwd);
                }
                else
                    cli_fatal("failed to find 'features' file in path [%s]", pwd);
            }
        }
	}

	cli_file_open(path, O_RDONLY, &fd);
	cli_file_read(fd, &data, &len);
	cli_file_close(fd);
    free( path );

    if( len == 0 ) {
        cli_fatal(".objs/features is empty");
    }

    len--;

	*out = data;
	*outlen = len;
}
/* ----------------------------------------------------------------------------*/
static void cli_flavor_change( const char *name )
{
    FILE *fp = NULL;
    int	ret;
    struct buildopt	*bopt = NULL;

    if( (bopt = cli_buildopt_find(name)) == NULL ) {
        cli_fatal("no such flavor: %s", name);
    }

    if( (fp = fopen(".flavor.tmp", "w")) == NULL ) {
        cli_fatal("failed to open temporary file to save flavor");
    }

	ret = fprintf(fp, "%s\n", name);
    if( ret == -1 || (size_t)ret != (strlen(name) + 1) )
        cli_fatal("failed to write new build flavor");

    fclose(fp);

    if( rename(".flavor.tmp", ".flavor") == -1 ) {
        cli_fatal("failed to replace build flavor");
    }

	cli_clean(0, NULL);
}
/* ----------------------------------------------------------------------------*/
static void cli_spawn_proc(void (*cb)(void *), void *arg)
{
    pid_t pid;
    int	status;

	pid = fork();
    switch( pid )
    {
	case -1:
        cli_fatal("cli_compile_cfile: fork() %s", errno_s);
		/* NOTREACHED */
	case 0:
		cb(arg);
        cli_fatal("cli_spawn_proc: %s", errno_s);
		/* NOTREACHED */
	default:
		break;
	}

    if( waitpid(pid, &status, 0) == -1 )
        cli_fatal("couldn't wait for child %d", pid);

    if( WEXITSTATUS(status) || WTERMSIG(status) || WCOREDUMP(status) )
        cli_fatal("subprocess trouble, check output");
}
/* ----------------------------------------------------------------------------*/
static int cli_vasprintf(char **out, const char *fmt, ...)
{
    int	l;
    va_list args;

	va_start(args, fmt);
	l = vasprintf(out, fmt, args);
	va_end(args);

    if( l == -1 )
        cli_fatal("cli_vasprintf");

    return l;
}
/* ----------------------------------------------------------------------------*/
static void cli_cleanup_files(const char *spath)
{
	cli_find_files(spath, cli_file_remove);

    if( rmdir(spath) == -1 && errno != ENOENT )
		printf("couldn't rmdir %s\n", spath);
}
/* ----------------------------------------------------------------------------*/
static void* cli_malloc(size_t len)
{
    void *ptr = NULL;

    if( (ptr = calloc(1, len)) == NULL )
        cli_fatal("calloc: %s", errno_s);

    return ptr;
}
/* ----------------------------------------------------------------------------*/
static void* cli_realloc(void *ptr, size_t len)
{
    void *nptr = NULL;

    if( (nptr = realloc(ptr, len)) == NULL )
        cli_fatal("realloc: %s", errno_s);

    return nptr;
}
/* ----------------------------------------------------------------------------*/
static char* cli_strdup(const char *string)
{
    char *copy = NULL;

    if( (copy = strdup(string)) == NULL )
        cli_fatal("strdup: %s", errno_s);

    return copy;
}
/* ----------------------------------------------------------------------------*/
struct cli_buf* cli_buf_alloc(size_t initial)
{
    struct cli_buf *buf = NULL;

	buf = cli_malloc(sizeof(*buf));

	if (initial > 0)
		buf->data = cli_malloc(initial);
	else
		buf->data = NULL;

	buf->length = initial;
	buf->offset = 0;

    return buf;
}
/* ----------------------------------------------------------------------------*/
void cli_buf_free( struct cli_buf *buf )
{
	free(buf->data);
	buf->data = NULL;
	buf->offset = 0;
	buf->length = 0;
	free(buf);
}
/* ----------------------------------------------------------------------------*/
void cli_buf_append( struct cli_buf *buf, const void *d, size_t len )
{
    if( (buf->offset + len) < len )
        cli_fatal("overflow in cli_buf_append");

    if( (buf->offset + len) > buf->length )
    {
		buf->length += len;
		buf->data = cli_realloc(buf->data, buf->length);
	}

	memcpy((buf->data + buf->offset), d, len);
	buf->offset += len;
}
/* ----------------------------------------------------------------------------*/
void cli_buf_appendv(struct cli_buf *buf, const char *fmt, va_list args)
{
    int	l;
    va_list copy;
    char *b, sb[BUFSIZ];

	va_copy(copy, args);

	l = vsnprintf(sb, sizeof(sb), fmt, args);
    if( l == -1 )
        cli_fatal("cli_buf_appendv(): vsnprintf error");

    if( (size_t)l >= sizeof(sb) )
    {
		l = vasprintf(&b, fmt, copy);
        if( l == -1 )
            cli_fatal("cli_buf_appendv(): error or truncation");
    }
    else
    {
		b = sb;
	}

	cli_buf_append(buf, b, l);
    if( b != sb )
		free(b);

	va_end(copy);
}
/* ----------------------------------------------------------------------------*/
void cli_buf_appendf(struct cli_buf *buf, const char *fmt, ...)
{
    va_list	args;

	va_start(args, fmt);
	cli_buf_appendv(buf, fmt, args);
	va_end(args);
}
/* ----------------------------------------------------------------------------*/
char* cli_buf_stringify(struct cli_buf *buf, size_t *len)
{
    char c;

    if( len != NULL )
		*len = buf->offset;

	c = '\0';
	cli_buf_append(buf, &c, sizeof(c));

    return (char *)buf->data;
}
/* ----------------------------------------------------------------------------*/
static int cli_split_string(char *input, const char *delim, char **out, size_t ele)
{
    int	count;
    char **ap;

    if( ele == 0 ) {
        return 0;
    }

	count = 0;
    for( ap = out; ap < &out[ele - 1] && (*ap = strsep(&input, delim)) != NULL; )
    {
        if( **ap != '\0' )
        {
			ap++;
			count++;
		}
	}

	*ap = NULL;
    return count;
}
/* ----------------------------------------------------------------------------*/
static char* cli_read_line(FILE *fp, char *in, size_t len)
{
    char *p, *t;

    if( fgets(in, len, fp) == NULL ) {
        return NULL;
    }

	p = in;
	in[strcspn(in, "\n")] = '\0';

    while( isspace(*(unsigned char *)p) )
		p++;

    if( p[0] == '#' || p[0] == '\0' )
    {
		p[0] = '\0';
        return p;
	}

    for( t = p; *t != '\0'; t++ )
    {
        if( *t == '\t' )
			*t = ' ';
	}

    return p;
}
/* ----------------------------------------------------------------------------*/
static char* cli_text_trim(char *string, size_t len)
{
    char *end = NULL;

    if( len == 0 ) {
        return string;
    }

	end = (string + len) - 1;
    while( isspace(*(unsigned char *)string) && string < end )
		string++;

    while( isspace(*(unsigned char *)end) && end > string )
		*(end)-- = '\0';

    return string;
}
/* ----------------------------------------------------------------------------*/
static long long cli_strtonum(const char *str, long long min, long long max)
{
    long long l;
    char *ep = NULL;

    if( min > max )
        cli_fatal("cli_strtonum: min > max");

	errno = 0;
	l = strtoll(str, &ep, 10);
    if( errno != 0 || str == ep || *ep != '\0' )
        cli_fatal("strtoll(): %s", errno_s);

    if( l < min )
        cli_fatal("cli_strtonum: value < min");

    if( l > max )
        cli_fatal("cli_strtonum: value > max");

    return l;
}
/****************************************************************
 *  Helper function to fatal exit cli application
 ****************************************************************/
static void cli_fatal(const char *fmt, ...)
{
    va_list	args;
    char buf[2048];

	va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
	va_end(args);

    if( command != NULL )
        printf("zfrog %s: %s\n", command->name, buf);
	else
        printf("zfrog: %s\n", buf);

	exit(1);
}
/****************************************************************
 *  Helper function to get proc path
 ****************************************************************/
static int cli_proc_path( void *buf, size_t len )
{
#ifdef __linux__
    ssize_t path_len = 0;
    char exe_path[ PATH_MAX ];
    char* path = NULL;

    path_len = readlink( "/proc/self/exe", exe_path, sizeof(exe_path) );

    if( path_len < 0 )
        return -1;

    if( path_len >= (ssize_t)len )
    {
        errno = EOVERFLOW;
        return -1;
    }
    /* Set end of string */
    exe_path[path_len] = '\0';
    /* Get path of exe path */
    path = dirname( exe_path );
    /* Copy to destination buffer */
    strcpy( (char *)buf, path );

#elif __FreeBSD__
    size_t path_len = len;
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PATHNAME, -1 };

    if( sysctl(mib, N_ELEMENTS(mib), buf, &path_len, NULL, 0) < 0 )
        return CF_RESULT_ERROR;
#else
    errno = ENOSYS;
    return -1;
#endif

    return 0;
}
