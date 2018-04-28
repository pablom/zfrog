# Crazy Frog Makefile

CC?=gcc
AR?=ar

PREFIX?=/usr/share/zfrog/
OBJDIR?=obj
OBJDIR_CSTL?=obj/cstl
LIBDIR?=$(OBJDIR)/lib

ZFROG=zfrog
ZFROG_CLI=zfrog_cli
CSTL_LIB=libcstl.a

INSTALL_DIR=$(PREFIX)/bin
INCLUDE_DIR=$(PREFIX)/include/zfrog
SHARE_DIR=$(PREFIX)/share/zfrog

FEATURES=
FEATURES_INC=

OSNAME = $(shell uname -s | sed -e 's/[-_].*//g' | tr A-Z a-z)
TARGET = $(shell uname -s | tr '[A-Z]' '[a-z]' 2>/dev/null || echo unknown)

CFLAGS  += -Wall -Werror -Wmissing-declarations -Wshadow -Wstrict-prototypes
CFLAGS  += -Wpointer-arith -Wcast-qual -Wsign-compare -Wshadow -pedantic -fstack-protector-all
CFLAGS  += -Iinclude -Iinclude/cstl 
CFLAGS  += -I$(OBJDIR)/include
CFLAGS  += -m64

LDFLAGS += -m64
LDFLAGS += -L$(LIBDIR)

LDFLAGS_CLI = $(LDFLAGS)

# Download urls for dependency libraries
OPENSSL_URL=https://www.openssl.org/source/openssl-1.1.0h.tar.gz
YAJL_URL=https://github.com/lloyd/yajl/archive/2.1.0.tar.gz
LUAJIT_URL=https://luajit.org/download/LuaJIT-2.0.5.tar.gz
LIBSODIUM_URL=https://github.com/jedisct1/libsodium/releases/download/1.0.16/libsodium-1.0.16.tar.gz

DEPS =

###########################################################################
#   zfrog  sources
###########################################################################
S_SRC=  src/cf_main.c src/cf_buf.c src/cf_config.c src/cf_connection.c src/cf_timer.c \
        src/cf_domain.c src/cf_memory.c src/cf_msg.c src/cf_module.c src/cf_network.c \
        src/cf_mem_pool.c src/cf_utils.c src/cf_worker.c src/cf_runtime.c

###########################################################################
#   zfrog cli sources
###########################################################################
S_SRC_CLI= src/cf_cli.c

###########################################################################
#   cstl  sources
###########################################################################
S_SRC_CSTL = src/cstl/cf_cstl_memory.c src/cstl/cf_cstl_pair.c src/cstl/cf_cstl_set.c \
             src/cstl/cf_cstl_map.c src/cstl/cf_cstl_vector.c src/cstl/cf_cstl_list.c \
             src/cstl/cf_cstl_iterator.c src/cstl/cf_cstl_algorithm.c src/cstl/cf_cstl_stack.c \
             src/cstl/cf_cstl_queue.c src/cstl/cf_cstl_tree.c


# Single binary configuration
ifeq ($(CF_SINGLE_BINARY), 1)
    CFLAGS+=-DCF_SINGLE_BINARY
    FEATURES+=-DCF_SINGLE_BINARY
endif

###########################################################################
#   Debug support
###########################################################################
ifeq ($(CF_DEBUG), 1)
    CFLAGS += -DCF_DEBUG -g -ggdb
    CFLAGS += -O0
    FEATURES += -DCF_DEBUG
else
    CFLAGS += -O3
endif
###########################################################################
#   HTTP support
###########################################################################
ifeq ($(CF_NO_HTTP), 1)
    CFLAGS += -DCF_NO_HTTP
    FEATURES += -DCF_NO_HTTP
else
    S_SRC+= src/cf_auth.c src/cf_accesslog.c src/cf_http.c src/cf_websocket.c\
            src/cf_validator.c
endif
###########################################################################
#   TLS support
###########################################################################
ifeq ($(CF_NO_TLS), 1)
    CFLAGS += -DCF_NO_TLS
    FEATURES += -DCF_NO_TLS
else
    S_SRC += src/cf_keymgr.c src/cf_pkcs11.c
    ifneq ($(WITH_OPENSSL),)
        CFLAGS  += -I$(WITH_OPENSSL)/include
        LDFLAGS += -L$(WITH_OPENSSL)/lib -lssl -lcrypto
        LDFLAGS_CLI += -L$(WITH_OPENSSL)/lib -lssl -lcrypto
    else
        LDFLAGS += -lssl -lcrypto
        LDFLAGS_CLI += -lssl -lcrypto
        DEPS += $(LIBDIR)/libssl.a
    endif
endif
###########################################################################
#   Tasks support
###########################################################################
ifeq ($(CF_TASKS), 1)
    S_SRC += src/cf_tasks.c
    LDFLAGS += -lpthread
    CFLAGS += -DCF_TASKS
    FEATURES += -DCF_TASKS
endif
###########################################################################
#   JsonRPC support
###########################################################################
ifeq ($(CF_JSONRPC), 1)
    S_SRC += src/cf_jsonrpc.c
    CFLAGS += -DCF_JSONRPC
    FEATURES += -DCF_JSONRPC
    ifneq ($(WITH_YAJL),)
        CFLAGS  += -I$(WITH_YAJL)/include
        LDFLAGS += -L$(WITH_YAJL)/lib -lyajl
    else
        ifneq ($(YAJL_SO),)
            LDFLAGS += -lyajl
        else
            LDFLAGS += -lyajl_s
        endif
        DEPS += $(LIBDIR)/libyajl_s.a
    endif
endif
###########################################################################
#   PostgreSQL support
###########################################################################
ifeq ($(CF_PGSQL), 1)
    S_SRC+=src/cf_pgsql.c
    LDFLAGS+=-L$(shell pg_config --libdir) -lpq
    CFLAGS+=-I$(shell pg_config --includedir) -DCF_PGSQL \
        -DPGSQL_INCLUDE_PATH="\"$(shell pg_config --includedir)\""
    FEATURES+=-DCF_PGSQL
    FEATURES_INC+=-I$(shell pg_config --includedir)
endif
###########################################################################
#   Oracle SQL support
###########################################################################
ifeq ($(CF_ORACLE), 1)
    S_SRC+=src/cf_oci.c
    LDFLAGS+=-Llib -lclntsh -Wl,-rpath-link=lib
    CFLAGS+=-DCF_ORACLE -Iinclude/oci
    FEATURES+=-DCF_ORACLE
endif
###########################################################################
#   MySQL support
###########################################################################
ifeq ($(CF_MYSQL), 1)
    S_SRC+=src/cf_mysql.c
    CFLAGS+=-DCF_MYSQL
    FEATURES+=-DCF_MYSQL
endif
###########################################################################
#   Python support
###########################################################################
ifeq ($(CF_PYTHON), 1)
    S_SRC+=src/cf_python.c
    LDFLAGS+=$(shell python3-config --ldflags)
    CFLAGS+=$(shell python3-config --includes) -DCF_PYTHON
    FEATURES+=-DCF_PYTHON
    FEATURES_INC+=$(shell python3-config --includes)
endif
###########################################################################
#   Lua support
###########################################################################
ifeq ($(CF_LUA), 1)
    S_SRC += src/cf_lua.c
    CFLAGS += -DCF_LUA
    FEATURES += -DCF_LUA
    ifneq ($(WITH_LUAJIT),)
		CFLAGS  += -I$(WITH_LUAJIT)/include
		LDFLAGS += -L$(WITH_LUAJIT)/lib -lluajit
	else
		DEPS += $(LIBDIR)/libluajit-5.1.a
		LDFLAGS += -lm $(LIBDIR)/libluajit-5.1.a
	endif
endif
###########################################################################
#   Redis support
###########################################################################
ifeq ($(CF_REDIS), 1)
    S_SRC += src/cf_redis.c
    CFLAGS += -DCF_REDIS
    FEATURES += -DCF_REDIS
endif
###########################################################################
#   CTemplate support
###########################################################################
ifeq ($(CF_CTEMPL), 1)
    CFLAGS += -DCF_CTEMPL
    S_SRC += src/cf_ctemplate.c
endif
###########################################################################
#   Mustache template support
###########################################################################
ifeq ($(CF_TMUSTACHE), 1)
    CFLAGS += -DCF_TMUSTACHE
    S_SRC += src/cf_mustach.c
endif

###########################################################################
#   Linux (i686)
###########################################################################
ifeq ($(TARGET), linux)
        S_SRC += src/cf_linux.c
        CFLAGS += -D_GNU_SOURCE=1 -std=c99
        LDFLAGS += -rdynamic -ldl
###########################################################################
#   MacOS
###########################################################################
else ifeq ($(TARGET), darwin)
        S_SRC += src/cf_bsd.c
###########################################################################
#   Solaris (Sparc)
###########################################################################
else ifeq ($(TARGET), sunos)
        CC=gcc
        S_SRC += src/cf_solaris.c
        SUN_VERSION=$(shell uname -r | sed -e 's/\.\([0-9]\{1,1\}\)$/0\1/' -e 's/\.//')
        #CFLAGS += -D_GNU_SOURCE=1 -std=gnu99
        CFLAGS += -D_PTHREADS -D_POSIX_C_SOURCE=200112L
        LDFLAGS += -ldl -lsocket -lnsl
###########################################################################
#   FreeBSD
###########################################################################
else ifeq ($(TARGET), freebsd)
        S_SRC += src/cf_bsd.c
###########################################################################
#   AIX (power pc)
###########################################################################
else ifeq ($(TARGET), aix)
        S_SRC += src/cf_aix.c
endif

###########################################################################
S_OBJS= $(S_SRC:src/%.c=$(OBJDIR)/%.o)
S_OBJS_CLI= $(S_SRC_CLI:src/%.c=$(OBJDIR)/%.o)
S_OBJS_CSTL= $(S_SRC_CSTL:src/cstl/%.c=$(OBJDIR_CSTL)/%.o)

$(ZFROG): $(OBJDIR) $(S_OBJS)
	$(CC) $(S_OBJS) $(LDFLAGS) -o $(ZFROG)
	@echo $(FEATURES) > features

$(ZFROG_CLI): $(OBJDIR) $(S_OBJS_CLI)
	$(CC) $(S_OBJS_CLI) $(LDFLAGS_CLI) -o $(ZFROG_CLI)

$(CSTL_LIB): $(OBJDIR_CSTL) $(S_OBJS_CSTL)
	$(AR) rcs $(LIBDIR)/libcstl.a $(S_OBJS_CSTL)
	ranlib $(LIBDIR)/libcstl.a

objects: $(OBJDIR) $(S_OBJS)
	@echo $(LDFLAGS) > $(OBJDIR)/ldflags
	@echo "$(FEATURES) $(FEATURES_INC)" > $(OBJDIR)/features

all: $(DEPS) $(CSTL_LIB) $(ZFROG) $(ZFROG_CLI)

$(OBJDIR):
	@mkdir -p $@

$(OBJDIR_CSTL):
	@mkdir -p $(OBJDIR_CSTL)

install:
	mkdir -p $(SHARE_DIR)
	mkdir -p $(INCLUDE_DIR)
	mkdir -p $(INSTALL_DIR)
	install -m 555 $(ZFROG) $(INSTALL_DIR)/$(ZFROG)
	install -m 644 zfrog.features $(SHARE_DIR)/features
	install -m 644 include/*.h $(INCLUDE_DIR)
	install -m 555 $(ZFROG_CLI) $(INSTALL_DIR)/$(ZFROG_CLI)

uninstall:
	rm -f $(INSTALL_DIR)/$(CRAZY_FROG)
	rm -rf $(INCLUDE_DIR)

$(OBJDIR)/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR_CSTL)/%.o: src/cstl/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Download all dependencies library
deps:
	rm -rf deps
	mkdir -p deps
	wget -P $(PWD)/deps $(OPENSSL_URL)
	wget -P $(PWD)/deps $(LUAJIT_URL)
	wget -P $(PWD)/deps $(LIBSODIUM_URL)
	wget -O $(PWD)/deps/yajl-2.1.0.tar.gz $(YAJL_URL)

clean:
	find $(OBJDIR) -mindepth 1 -maxdepth 1 -type f -name \*.o -exec rm {} \;
	rm -rf $(ZFROG) $(ZFROG_CLI) $(OBJDIR_CSTL)

distclean:
	find . -type f -name \*.o -exec rm {} \;
	find examples -type f -name \*.so -exec rm {} \;
	rm -rf $(ZFROG) $(ZFROG_CLI) $(OBJDIR)

###########################################################################
#  Dependencies build section
###########################################################################
LUAJIT  := $(notdir $(patsubst %.tar.gz,%,$(wildcard deps/LuaJIT*.tar.gz)))
OPENSSL := $(notdir $(patsubst %.tar.gz,%,$(wildcard deps/openssl*.tar.gz)))
YAJL    := $(notdir $(patsubst %.tar.gz,%,$(wildcard deps/yajl*.tar.gz)))
LSODIUM := $(notdir $(patsubst %.tar.gz,%,$(wildcard deps/libsodium*.tar.gz)))

OPENSSL_OPTS = no-psk no-srp no-dtls no-idea --prefix=$(abspath $(OBJDIR))
LSODIUM_OPTS = --enable-shared=no --enable-static=yes --prefix=$(abspath $(OBJDIR))

ifneq ($(OPENSSL_SO),1)
	OPENSSL_OPTS += no-shared
endif

ifneq ($(CF_TASKS), 1)
	OPENSSL_OPTS += no-threads
endif

$(OBJDIR)/$(LUAJIT):  deps/$(LUAJIT).tar.gz | $(OBJDIR)
	@tar -C $(OBJDIR) -xf $<

$(OBJDIR)/$(OPENSSL): deps/$(OPENSSL).tar.gz | $(OBJDIR)
	@tar -C $(OBJDIR) -xf $<

$(OBJDIR)/$(YAJL):  deps/$(YAJL).tar.gz | $(OBJDIR)
	@tar -C $(OBJDIR) -xf $<

$(OBJDIR)/$(LSODIUM):  deps/$(LSODIUM).tar.gz | $(OBJDIR)
	@tar -C $(OBJDIR) -xf $<

$(LIBDIR)/libluajit-5.1.a: $(OBJDIR)/$(LUAJIT)
	@echo Building LuaJIT...
	@$(MAKE) -C $< PREFIX=$(abspath $(OBJDIR)) BUILDMODE=static install

$(LIBDIR)/libssl.a: $(OBJDIR)/$(OPENSSL)
	@echo Building OpenSSL...
ifeq ($(TARGET), darwin)
	@$(SHELL) -c "cd $< && ./Configure $(OPENSSL_OPTS) darwin64-x86_64-cc"
else
	@$(SHELL) -c "cd $< && ./config $(OPENSSL_OPTS)"
endif
	@$(MAKE) -C $< depend
	@$(MAKE) -C $<
	@$(MAKE) -C $< install_sw
	@touch $@

$(LIBDIR)/libyajl_s.a: $(OBJDIR)/$(YAJL)
	@echo Building Yet Another JSON Library...
	@$(SHELL) -c "cd $< && ./configure -p $(abspath $(OBJDIR))"
	@$(MAKE) -C $< install
	@touch $@

$(LIBDIR)/libsodium.a: $(OBJDIR)/$(LSODIUM)
	@echo Building libsodium Library...
	@$(SHELL) -c "cd $< && ./configure $(LSODIUM_OPTS)"
	@$(MAKE) -C $< install
	@touch $@

# Build only openssl
openssl: $(LIBDIR)/libssl.a

# Build only libsodium
libsodium: $(LIBDIR)/libsodium.a

########################################################################
#  Example applications build section
########################################################################
example-generic:
	cd examples/generic && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-jsonrpc:
	cd examples/jsonrpc && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-integers:
	cd examples/integers && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-cookies:
	cd examples/cookies && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-cpp:
	cd examples/cpp && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-headers:
	cd examples/headers && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-memtag:
	cd examples/memtag && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-messaging:
	cd examples/messaging && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-parameters:
	cd examples/parameters && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-sse:
	cd examples/sse && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-upload:
	cd examples/upload && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-video_stream:
	cd examples/video_stream && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-websocket:
	cd examples/websocket && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-ztunnel:
	cd examples/ztunnel && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-pipe_task:
	cd examples/pipe_task && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-lua:
	cd examples/lua && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-redis:
	cd examples/redis && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-redis-jsonrpc:
	cd examples/redis-jsonrpc && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean
########################################################################
# no HTTP support examples 
########################################################################
example-nohttp:
	cd examples/nohttp && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-sock_serv_echo:
	cd examples/sock_serv_echo && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-tls-proxy:
	cd examples/tls-proxy && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-tasks:
	cd examples/tasks && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean

example-json_yajl:
	cd examples/json_yajl && $(PWD)/$(ZFROG_CLI) build && $(PWD)/$(ZFROG_CLI) clean


# Build all test applications by default
example-all: example-generic example-integers example-websocket example-parameters example-memtag \
          example-headers example-cookies example-messaging


.DEFAULT_GOAL := all

.PHONY: all clean install uninstall

.SUFFIXES:
.SUFFIXES: .c .o .lua

vpath %.c   src
vpath %.h   src
vpath %.lua scripts
