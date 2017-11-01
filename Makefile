# Crazy Frog Makefile

CC?=gcc
AR?=ar
PREFIX?=/usr/share/zfrog/
OBJDIR?=obj
OBJDIR_CSTL?=obj/cstl

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
CFLAGS  += -Wpointer-arith -Wcast-qual -Wsign-compare -Wshadow -pedantic
CFLAGS  += -Iinclude -Iinclude/cstl
CFLAGS  += -m64

LDFLAGS += -m64

LDFLAGS_CLI = $(LDFLAGS) -Llib -lcrypto

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

#   Add specific os support
ifeq ($(TARGET), linux)
        S_SRC += src/cf_linux.c
        CFLAGS += -D_GNU_SOURCE=1 -std=c99
        LDFLAGS += -rdynamic -ldl
else ifeq ($(TARGET), darwin)
        S_SRC += src/cf_bsd.c
else ifeq ($(TARGET), sunos)
        CC=gcc
        S_SRC += src/cf_solaris.c
        SUN_VERSION=$(shell uname -r | sed -e 's/\.\([0-9]\{1,1\}\)$/0\1/' -e 's/\.//')
        #CFLAGS += -D_GNU_SOURCE=1 -std=gnu99
        CFLAGS += -D_PTHREADS -D_POSIX_C_SOURCE=200112L
        LDFLAGS += -ldl -lsocket -lnsl
else ifeq ($(TARGET), freebsd)
        S_SRC += src/cf_bsd.c
else ifeq ($(TARGET), aix)
        S_SRC += src/cf_aix.c
endif


ifeq ($(CF_SINGLE_BINARY), 1)
    CFLAGS+=-DCF_SINGLE_BINARY
    FEATURES+=-DCF_SINGLE_BINARY
endif

###########################################################################
#   Debug support
###########################################################################
ifeq ($(CF_DEBUG), 1)
    CFLAGS+=-DCF_DEBUG -g
    CFLAGS+=-O0
    FEATURES+=-DCF_DEBUG
else
    CFLAGS+=-O3
endif
###########################################################################
#   HTTP support
###########################################################################
ifeq ($(CF_NO_HTTP), 1)
    CFLAGS+=-DCF_NO_HTTP
    FEATURES+=-DCF_NO_HTTP
else
    S_SRC+= src/cf_auth.c src/cf_accesslog.c src/cf_http.c \
            src/cf_validator.c src/cf_websocket.c
endif
###########################################################################
#   TLS support
###########################################################################
ifeq ($(CF_NO_TLS), 1)
    CFLAGS+=-DCF_NO_TLS
    FEATURES+=-DCF_NO_TLS
else
    S_SRC += src/cf_keymgr.c src/cf_pkcs11.c
    CFLAGS += -Iinclude/pkcs11
    LDFLAGS += -Llib -lssl -lcrypto
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
    LDFLAGS += -lyajl
    CFLAGS+=-DCF_JSONRPC
    FEATURES+=-DCF_JSONRPC
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
#   OracleSQL support
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
		DEPS += $(OBJDIR)/lib/libluajit-5.1.a
	endif
endif
###########################################################################
#   Redis support
###########################################################################
ifeq ($(CF_REDIS), 1)
    S_SRC+=src/cf_redis.c
#    LDFLAGS+=-Llib -lhiredis
    CFLAGS+=-DCF_REDIS -Iinclude/hiredis
    FEATURES+=-DCF_REDIS
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
S_OBJS= $(S_SRC:src/%.c=$(OBJDIR)/%.o)
S_OBJS_CLI= $(S_SRC_CLI:src/%.c=$(OBJDIR)/%.o)
S_OBJS_CSTL= $(S_SRC_CSTL:src/cstl/%.c=$(OBJDIR_CSTL)/%.o)

$(ZFROG): $(OBJDIR) $(S_OBJS)
	$(CC) $(S_OBJS) $(LDFLAGS) -o $(ZFROG)
	@echo $(FEATURES) > features

$(ZFROG_CLI): $(OBJDIR) $(S_OBJS_CLI)
	$(CC) $(S_OBJS_CLI) $(LDFLAGS_CLI) -o $(ZFROG_CLI)

$(CSTL_LIB): $(OBJDIR_CSTL) $(S_OBJS_CSTL)
	$(AR) rcs $(OBJDIR_CSTL)/libcstl.a $(S_OBJS_CSTL)
	ranlib $(OBJDIR_CSTL)/libcstl.a

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

clean:
	find . -type f -name \*.o -exec rm {} \;
	rm -rf $(ZFROG) $(ZFROG_CLI) $(OBJDIR)


# Dependencies

LUAJIT  := $(notdir $(patsubst %.tar.gz,%,$(wildcard deps/LuaJIT*.tar.gz)))
OPENSSL := $(notdir $(patsubst %.tar.gz,%,$(wildcard deps/openssl*.tar.gz)))

OPENSSL_OPTS = no-shared no-psk no-srp no-dtls no-idea --prefix=$(abspath $(OBJDIR))

$(OBJDIR)/$(LUAJIT):  deps/$(LUAJIT).tar.gz
	@tar -C $(OBJDIR) -xf $<

$(OBJDIR)/$(OPENSSL): deps/$(OPENSSL).tar.gz
	@tar -C $(OBJDIR) -xf $<

$(OBJDIR)/lib/libluajit-5.1.a: $(OBJDIR)/$(LUAJIT)
	@echo Building LuaJIT...
	@$(MAKE) -C $< PREFIX=$(abspath $(OBJDIR)) BUILDMODE=static install

$(OBJDIR)/lib/libssl.a: $(OBJDIR)/$(OPENSSL)
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

.PHONY: all clean
.PHONY: $(OBJDIR)/version.o

.SUFFIXES:
.SUFFIXES: .c .o .lua

vpath %.c   src
vpath %.h   src
vpath %.lua scripts
