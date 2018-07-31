// cf_python.c

#include <sys/param.h>
#include <libgen.h>

#include "zfrog.h"

#ifndef CF_NO_HTTP
    #include "cf_http.h"
#endif

#ifdef CF_PGSQL
    #include "cf_pgsql.h"
#endif

#include "cf_python.h"
#include "cf_python_methods.h"

static PyMODINIT_FUNC   python_module_init(void);
static PyObject*        python_import(const char*);
static void             python_log_error(const char*);
static PyObject*        pyconnection_alloc(struct connection*);
static PyObject*        python_callable(PyObject*, const char*);

static void python_append_path(const char*);
static void python_push_integer(PyObject*, const char*, long);
static void python_push_type(const char*, PyObject*, PyTypeObject*);

#ifndef CF_NO_HTTP
    static PyObject *pyhttp_request_alloc(const struct http_request *);
    static int  python_coroutine_run(struct http_request*);
    static PyObject *pyhttp_file_alloc(struct http_file*);

    static int  python_runtime_http_request(void*, struct http_request*);
    static int  python_runtime_validator(void*, struct http_request*, const void*);
    static void python_runtime_wsmessage(void*, struct connection*, uint8_t, const void*, size_t);
#endif

#ifdef CF_PGSQL
    static PyObject *python_pgsql_alloc(struct http_request *, const char *, const char *);
#endif

static void python_runtime_execute(void*);
static int  python_runtime_onload(void*, int);
static void	python_runtime_configure(void*, int, char**);
static void python_runtime_connect(void*, struct connection*);

static void python_module_free(struct cf_module*);
static void python_module_reload(struct cf_module*);
static void python_module_load(struct cf_module*);
static void *python_module_getsym(struct cf_module*, const char*);

static void *python_malloc(void*, size_t);
static void *python_calloc(void*, size_t, size_t);
static void *python_realloc(void*, void*, size_t);
static void python_free(void*, void*);

struct cf_module_functions cf_python_module =
{
    .free = python_module_free,
    .load = python_module_load,
    .getsym = python_module_getsym,
    .reload = python_module_reload
};

struct cf_runtime cf_python_runtime =
{
    CF_RUNTIME_PYTHON,
#ifndef CF_NO_HTTP
    .http_request = python_runtime_http_request,
    .validator = python_runtime_validator,
    .wsconnect = python_runtime_connect,
    .wsmessage = python_runtime_wsmessage,
    .wsdisconnect = python_runtime_connect,
#endif
    .onload = python_runtime_onload,
    .connect = python_runtime_connect,
    .execute = python_runtime_execute,
    .configure = python_runtime_configure
};

static struct {
    const char *symbol;
    int         value;
} python_integers[] = {
    { "LOG_ERR", LOG_ERR },
    { "LOG_INFO", LOG_INFO },
    { "LOG_NOTICE", LOG_NOTICE },
    { "RESULT_OK", CF_RESULT_OK },
    { "RESULT_RETRY", CF_RESULT_RETRY },
    { "RESULT_ERROR", CF_RESULT_ERROR },
    { "MODULE_LOAD", CF_MODULE_LOAD },
    { "MODULE_UNLOAD", CF_MODULE_UNLOAD },
    { "CONN_PROTO_HTTP", CONN_PROTO_HTTP },
    { "CONN_PROTO_UNKNOWN", CONN_PROTO_UNKNOWN },
    { "CONN_PROTO_WEBSOCKET", CONN_PROTO_WEBSOCKET },
    { "CONN_STATE_ESTABLISHED", CONN_STATE_ESTABLISHED },

#ifndef CF_NO_HTTP
    { "HTTP_METHOD_GET", HTTP_METHOD_GET },
    { "HTTP_METHOD_PUT", HTTP_METHOD_PUT },
    { "HTTP_METHOD_HEAD", HTTP_METHOD_HEAD },
    { "HTTP_METHOD_POST", HTTP_METHOD_POST },
    { "HTTP_METHOD_DELETE", HTTP_METHOD_DELETE },
    { "HTTP_METHOD_OPTIONS", HTTP_METHOD_OPTIONS },
    { "HTTP_METHOD_PATCH", HTTP_METHOD_PATCH },
    { "WEBSOCKET_OP_TEXT", WEBSOCKET_OP_TEXT },
    { "WEBSOCKET_OP_BINARY", WEBSOCKET_OP_BINARY },
    { "WEBSOCKET_BROADCAST_LOCAL", WEBSOCKET_BROADCAST_LOCAL },
    { "WEBSOCKET_BROADCAST_GLOBAL", WEBSOCKET_BROADCAST_GLOBAL },
#endif

    { NULL, -1 }
};

static PyMemAllocatorEx allocator =
{
    .ctx     = NULL,
    .malloc  = python_malloc,
    .calloc  = python_calloc,
    .realloc = python_realloc,
    .free    = python_free
};

void cf_python_init(void)
{
    PyMem_SetAllocator(PYMEM_DOMAIN_OBJ, &allocator);
    PyMem_SetAllocator(PYMEM_DOMAIN_MEM, &allocator);
    PyMem_SetAllocator(PYMEM_DOMAIN_RAW, &allocator);
    PyMem_SetupDebugHooks();

    if( PyImport_AppendInittab("zfrog", &python_module_init) == -1 ) {
        cf_fatal("cf_python_init: failed to add new module");
    }

    Py_Initialize();
}

void cf_python_cleanup(void)
{
    if( Py_IsInitialized() )
    {
        PyErr_Clear();
        Py_Finalize();
    }
}

void cf_python_path(const char *path)
{
    python_append_path(path);
}

static void* python_malloc(void *ctx, size_t len)
{
    return mem_malloc(len);
}

static void* python_calloc(void *ctx, size_t memb, size_t len)
{
    return mem_calloc(memb, len);
}

static void* python_realloc(void *ctx, void *ptr, size_t len)
{
    return mem_realloc(ptr, len);
}

static void python_free(void *ctx, void *ptr)
{
    mem_free(ptr);
}

static void python_log_error(const char *function)
{
    PyObject *type, *value, *traceback;

    if( !PyErr_Occurred() || PyErr_ExceptionMatches(PyExc_StopIteration) )
        return;

    PyErr_Fetch(&type, &value, &traceback);

    if(type == NULL || value == NULL || traceback == NULL)
    {
        cf_log(LOG_ERR, "unknown python exception in '%s'", function);
        return;
    }

    cf_log( LOG_ERR,"python exception in '%s' - type:%s - value:%s - trace:%s",
            function,
            PyUnicode_AsUTF8AndSize(type, NULL),
            PyUnicode_AsUTF8AndSize(value, NULL),
            PyUnicode_AsUTF8AndSize(traceback, NULL));

    Py_DECREF(type);
    Py_DECREF(value);
    Py_DECREF(traceback);
}

static void python_module_free( struct cf_module *module )
{
    mem_free(module->path);
    Py_DECREF(module->handle);
    mem_free(module);
}

static void python_module_reload( struct cf_module *module )
{
    PyObject *handle = NULL;

    /* Clear errors */
    PyErr_Clear();

    if( (handle = PyImport_ReloadModule(module->handle)) == NULL)
    {
        python_log_error("python_module_reload");
        return;
    }

    Py_DECREF(module->handle);
    module->handle = handle;
}

static void python_module_load( struct cf_module *module )
{
    if( (module->handle = python_import(module->path)) == NULL )
        cf_fatal("%s: failed to import module", module->path);
}

static void * python_module_getsym( struct cf_module *module, const char *symbol )
{
    return python_callable(module->handle, symbol);
}

static void pyconnection_dealloc( struct pyconnection *pyc )
{
    PyObject_Del((PyObject *)pyc);
}
/****************************************************************
 *  Execute python function
 ****************************************************************/
static void python_runtime_execute( void *addr )
{
    PyObject *args, *pyret;

    PyObject *callable = (PyObject *)addr;

    if( (args = PyTuple_New(0)) == NULL )
        cf_fatal("python_runtime_execute: PyTuple_New failed");

    PyErr_Clear();
    pyret = PyObject_Call(callable, args, NULL);
    Py_DECREF(args);

    if( pyret == NULL )
    {
        python_log_error("python_runtime_execute");
        cf_fatal("failed to execute python call");
    }

    Py_DECREF(pyret);
}

static int python_runtime_onload( void *addr, int action )
{
    int ret;
    PyObject *pyret, *args, *pyact;

    PyObject *callable = (PyObject *)addr;

    if( (pyact = PyLong_FromLong(action)) == NULL ) {
        cf_fatal("python_runtime_onload: PyLong_FromLong failed");
    }

    if( (args = PyTuple_New(1)) == NULL ) {
        cf_fatal("python_runtime_onload: PyTuple_New failed");
    }

    if( PyTuple_SetItem(args, 0, pyact) != 0 ) {
        cf_fatal("python_runtime_onload: PyTuple_SetItem failed");
    }

    PyErr_Clear();
    pyret = PyObject_Call(callable, args, NULL);
    Py_DECREF(args);

    if( pyret == NULL )
    {
        python_log_error("python_runtime_onload");
        return CF_RESULT_ERROR;
    }

    if( !PyLong_Check(pyret) ) {
        cf_fatal("python_runtime_onload: unexpected return type");
    }

    ret = (int)PyLong_AsLong(pyret);
    Py_DECREF(pyret);

    return ret;
}

static void python_runtime_connect(void *addr, struct connection *c)
{
    PyObject *pyc, *pyret, *args;
    PyObject *callable = (PyObject *)addr;

    if( (pyc = pyconnection_alloc(c)) == NULL )
        cf_fatal("python_runtime_connect: pyc alloc failed");

    if( (args = PyTuple_New(1)) == NULL ) {
        cf_fatal("python_runtime_connect: PyTuple_New failed");
    }

    if( PyTuple_SetItem(args, 0, pyc) != 0 ) {
        cf_fatal("python_runtime_connect: PyTuple_SetItem failed");
    }

    PyErr_Clear();
    pyret = PyObject_Call(callable, args, NULL);
    Py_DECREF(args);

    if( pyret == NULL )
    {
        python_log_error("python_runtime_connect");
        cf_connection_disconnect(c);
    }

    Py_DECREF(pyret);
}

static void python_runtime_configure(void *addr, int argc, char **argv)
{
    int	i;
    PyObject *args, *pyret, *pyarg;

    PyObject* callable = (PyObject *)addr;

    if( (args = PyTuple_New(argc)) == NULL )
        cf_fatal("python_runtime_configure: PyTuple_New failed");

    for( i = 0; i < argc; i++ )
    {
        if( (pyarg = PyUnicode_FromString(argv[i])) == NULL )
            cf_fatal("python_runtime_configure: PyUnicode_FromString");

        if( PyTuple_SetItem(args, i, pyarg) != 0 )
            cf_fatal("python_runtime_configure: PyTuple_SetItem");
    }

    PyErr_Clear();
    pyret = PyObject_Call(callable, args, NULL);
    Py_DECREF(args);

    if( pyret == NULL )
    {
        python_log_error("python_runtime_configure");
        cf_fatal("failed to call configure method: wrong args?");
    }

    Py_DECREF(pyret);
}

static PyMODINIT_FUNC python_module_init(void)
{
    int i;
    PyObject *py_obj = NULL;

    if( (py_obj = PyModule_Create(&pycf_module)) == NULL )
        cf_fatal("python_module_init: failed to setup pyzfrog module");

    python_push_type("pyconnection", py_obj, &pyconnection_type);

    for( i = 0; python_integers[i].symbol != NULL; i++ )
    {
        python_push_integer(py_obj, python_integers[i].symbol, python_integers[i].value);
    }

#ifndef CF_NO_HTTP
    python_push_type("pyhttp_request", py_obj, &pyhttp_request_type);
    python_push_type("pyhttp_file", py_obj, &pyhttp_file_type);
#endif

    return py_obj;
}

static void python_append_path(const char *path)
{
    PyObject *mpath, *spath;

    if( (mpath = PyUnicode_FromString(path)) == NULL ) {
        cf_fatal("python_append_path: PyUnicode_FromString failed");
    }

    if( (spath = PySys_GetObject("path")) == NULL ) {
        cf_fatal("python_append_path: PySys_GetObject failed");
    }

    PyList_Append(spath, mpath);
    Py_DECREF(mpath);
}

static void python_push_type(const char *name, PyObject *module, PyTypeObject *type)
{
    if( PyType_Ready(type) == -1 )
        cf_fatal("python_push_type: failed to ready %s", name);

    Py_INCREF(type);

    if( PyModule_AddObject(module, name, (PyObject *)type) == -1 )
        cf_fatal("python_push_type: failed to push %s", name);
}

static void python_push_integer(PyObject *module, const char *name, long value)
{
    int ret;

    if( (ret = PyModule_AddIntConstant(module, name, value)) == -1 )
        cf_fatal("python_push_integer: failed to add %s", name);
}

static PyObject* python_log( PyObject *self, PyObject *args )
{
    int prio;
    const char *message = NULL;

    if( !PyArg_ParseTuple(args, "is", &prio, &message) )
        return NULL;

    cf_log(prio, "%s", message);

    Py_RETURN_TRUE;
}

static PyObject* python_listen(PyObject *self, PyObject *args)
{
    const char *ip, *port;

    if( !PyArg_ParseTuple(args, "ss", &ip, &port) )
        return NULL;

    if( !cf_server_bind(ip, port, NULL))
    {
        PyErr_SetString(PyExc_RuntimeError, "failed to listen");
        return NULL;
    }

    Py_RETURN_TRUE;
}

static PyObject* python_fatal( PyObject *self, PyObject *args )
{
    const char *reason = NULL;

    if( !PyArg_ParseTuple(args, "s", &reason) )
        reason = "python_fatal: PyArg_ParseTuple failed";

    cf_fatal("%s", reason);

    /* not reached */
    Py_RETURN_TRUE;
}

static PyObject* python_import( const char *path )
{
    PyObject *module = NULL;
    char *dir, *file, *copy, *p;

    copy = mem_strdup(path);

    if( (file = basename(copy)) == NULL )
        cf_fatal("basename: %s: %s", path, errno_s);
    if( (dir = dirname(copy)) == NULL )
        cf_fatal("dirname: %s: %s", path, errno_s);

    if( (p = strrchr(file, '.')) != NULL )
        *p = '\0';

    python_append_path(dir);
    module = PyImport_ImportModule(file);
    if( module == NULL )
        PyErr_Print();

    mem_free(copy);

    return module;
}

static PyObject* python_callable( PyObject *module, const char *symbol )
{
    PyObject *obj = NULL;

    if( (obj = PyObject_GetAttrString(module, symbol)) == NULL )
        return NULL;

    if( !PyCallable_Check(obj) )
    {
        Py_DECREF(obj);
        return NULL;
    }

    return obj;
}

static PyObject* pyconnection_alloc(struct connection *c)
{
    struct pyconnection *pyc = PyObject_New(struct pyconnection, &pyconnection_type);

    if( pyc == NULL ) {
        return NULL;
    }

    pyc->c = c;

    return (PyObject *)pyc;
}

static PyObject* pyconnection_disconnect( struct pyconnection *pyc, PyObject *args )
{
    cf_connection_disconnect( pyc->c );
    Py_RETURN_TRUE;
}

static PyObject* pyconnection_get_fd(struct pyconnection *pyc, void *closure)
{
    PyObject *fd = NULL;

    if( (fd = PyLong_FromLong(pyc->c->fd)) == NULL )
        return PyErr_NoMemory();

    return fd;
}

static PyObject * pyconnection_get_addr(struct pyconnection *pyc, void *closure)
{
    void *ptr;
    PyObject *result;
    char addr[INET6_ADDRSTRLEN];

    switch( pyc->c->addrtype )
    {
    case AF_INET:
        ptr = &pyc->c->addr.ipv4.sin_addr;
        break;
    case AF_INET6:
        ptr = &pyc->c->addr.ipv6.sin6_addr;
        break;
    default:
        PyErr_SetString(PyExc_RuntimeError, "invalid addrtype");
        return NULL;
    }

    if( inet_ntop(pyc->c->addrtype, ptr, addr, sizeof(addr)) == NULL )
    {
        PyErr_SetString(PyExc_RuntimeError, "inet_ntop failed");
        return NULL;
    }

    if( (result = PyUnicode_FromString(addr)) == NULL )
        return PyErr_NoMemory();

    return result;
}

#ifndef CF_NO_HTTP

static void pyhttp_dealloc( struct pyhttp_request *pyreq )
{
    Py_XDECREF(pyreq->data);
    PyObject_Del((PyObject *)pyreq);
}

static int python_coroutine_run( struct http_request *req )
{
    PyObject *item = NULL;

    for (;;)
    {
        PyErr_Clear();
        item = _PyGen_Send((PyGenObject *)req->py_coro, NULL);
        if( item == NULL )
        {
            python_log_error("coroutine");
            Py_DECREF(req->py_coro);
            req->py_coro = NULL;
            return CF_RESULT_OK;
        }

        if( item == Py_None )
        {
            Py_DECREF(item);
            break;
        }

        Py_DECREF(item);
    }

    return CF_RESULT_RETRY;
}

static int python_runtime_http_request(void *addr, struct http_request *req)
{
    PyObject *pyret, *pyreq, *args;

    PyObject *callable = (PyObject *)addr;

    if( req->py_coro != NULL )
        return python_coroutine_run(req);

    if( (pyreq = pyhttp_request_alloc(req)) == NULL )
        cf_fatal("python_runtime_http_request: pyreq alloc failed");

    if( (args = PyTuple_New(1)) == NULL ) {
        cf_fatal("python_runtime_http_request: PyTuple_New failed");
    }

    if( PyTuple_SetItem(args, 0, pyreq) != 0 ) {
        cf_fatal("python_runtime_http_request: PyTuple_SetItem failed");
    }

    PyErr_Clear();
    pyret = PyObject_Call(callable, args, NULL);
    Py_DECREF(args);

    if( pyret == NULL )
    {
        python_log_error("python_runtime_http_request");
        http_response(req, HTTP_STATUS_INTERNAL_ERROR, NULL, 0);
        return CF_RESULT_OK;
    }

    if( PyCoro_CheckExact(pyret) )
    {
        req->py_coro = pyret;
        return python_coroutine_run(req);
    }

    if( pyret != Py_None )
        cf_fatal("python_runtime_http_request: unexpected return type");

    Py_DECREF( pyret );

    return CF_RESULT_OK;
}

static int python_runtime_validator( void *addr, struct http_request *req, const void *data )
{
    int ret;
    PyObject *pyret, *pyreq, *args, *arg;

    PyObject *callable = (PyObject *)addr;

    if( (pyreq = pyhttp_request_alloc(req)) == NULL )
        cf_fatal("python_runtime_validator: pyreq alloc failed");

    if( req->flags & HTTP_VALIDATOR_IS_REQUEST )
    {
        if( (arg = pyhttp_request_alloc(data)) == NULL )
            cf_fatal("python_runtime_validator: pyreq failed");
    }
    else
    {
        if( (arg = PyUnicode_FromString(data)) == NULL )
            cf_fatal("python_runtime_validator: PyUnicode failed");
    }

    if( (args = PyTuple_New(2)) == NULL )
        cf_fatal("python_runtime_validator: PyTuple_New failed");

    if( PyTuple_SetItem(args, 0, pyreq) != 0 ||
        PyTuple_SetItem(args, 1, arg) != 0 ) {
        cf_fatal("python_runtime_vaildator: PyTuple_SetItem failed");
    }

    PyErr_Clear();
    pyret = PyObject_Call(callable, args, NULL);
    Py_DECREF(args);

    if( pyret == NULL )
    {
        python_log_error("python_runtime_validator");
        cf_fatal("failed to execute python call");
    }

    if( !PyLong_Check(pyret) ) {
        cf_fatal("python_runtime_validator: unexpected return type");
    }

    ret = (int)PyLong_AsLong(pyret);
    Py_DECREF(pyret);

    return ret;
}

static void python_runtime_wsmessage(void *addr, struct connection *c, uint8_t op, const void *data, size_t len)
{
    PyObject *args, *pyret, *pyc, *pyop, *pydata;

    PyObject *callable = (PyObject *)addr;

    if ((pyc = pyconnection_alloc(c)) == NULL)
        cf_fatal("python_runtime_wsmessage: pyc alloc failed");

    if ((pyop = PyLong_FromLong((long)op)) == NULL)
        cf_fatal("python_runtime_wsmessage: PyLong_FromLong failed");

    switch( op )
    {
    case WEBSOCKET_OP_TEXT:
        if( (pydata = PyUnicode_FromStringAndSize(data, len)) == NULL )
            cf_fatal("wsmessage: PyUnicode_AsUTF8AndSize failed");
        break;
    case WEBSOCKET_OP_BINARY:
        if( (pydata = PyBytes_FromStringAndSize(data, len)) == NULL )
            cf_fatal("wsmessage: PyBytes_FromString failed");
        break;
    default:
        cf_fatal("python_runtime_wsmessage: invalid op");
    }

    if ((args = PyTuple_New(3)) == NULL)
        cf_fatal("python_runtime_wsmessage: PyTuple_New failed");

    if (PyTuple_SetItem(args, 0, pyc) != 0 ||
        PyTuple_SetItem(args, 1, pyop) != 0 ||
        PyTuple_SetItem(args, 2, pydata) != 0)
        cf_fatal("python_runtime_wsmessage: PyTuple_SetItem failed");

    PyErr_Clear();
    pyret = PyObject_Call(callable, args, NULL);
    Py_DECREF(args);

    if( pyret == NULL )
    {
        python_log_error("python_runtime_wsconnect");
        cf_fatal("failed to execute python call");
    }

    Py_DECREF(pyret);
}

static PyObject* pyhttp_request_alloc(const struct http_request *req )
{
    union { const void *cp; void *p; }  ptr;
    struct pyhttp_request *pyreq = NULL;

    if( (pyreq = PyObject_New(struct pyhttp_request, &pyhttp_request_type)) == NULL ) {
        return NULL;
    }

    /*
     * Hack around all http apis taking a non-const pointer and us having
     * a const pointer for the req data structure. This is because we
     * could potentially be called from a validator where the argument
     * is a http_request pointer
     */
    ptr.cp = req;
    pyreq->req = ptr.p;
    pyreq->data = NULL;

    return (PyObject *)pyreq;
}

static PyObject* pyhttp_file_alloc(struct http_file *file)
{
    struct pyhttp_file *pyfile = NULL;

    if( (pyfile = PyObject_New(struct pyhttp_file, &pyhttp_file_type)) == NULL )
        return NULL;

    pyfile->file = file;

    return (PyObject *)pyfile;
}

static PyObject* pyhttp_response(struct pyhttp_request *pyreq, PyObject *args)
{
    const char *body = NULL;
    int status, len = -1;

    if( !PyArg_ParseTuple(args, "iy#", &status, &body, &len) )
        return NULL;

    if( len < 0 )
    {
        PyErr_SetString(PyExc_TypeError, "invalid length");
        return NULL;
    }

    http_response(pyreq->req, status, body, len);

    Py_RETURN_TRUE;
}

static PyObject* pyhttp_response_header(struct pyhttp_request *pyreq, PyObject *args)
{
    const char  *header, *value;

    if( !PyArg_ParseTuple(args, "ss", &header, &value) )
        return NULL;

    http_response_header(pyreq->req, header, value);

    Py_RETURN_TRUE;
}

static PyObject* pyhttp_request_header(struct pyhttp_request *pyreq, PyObject *args)
{
    const char *value = NULL;
    const char *header = NULL;
    PyObject *result = NULL;

    if( !PyArg_ParseTuple(args, "s", &header) )
        return NULL;

    if( !http_request_header(pyreq->req, header, &value) ) {
        Py_RETURN_NONE;
    }

    if( (result = PyUnicode_FromString(value)) == NULL )
        return PyErr_NoMemory();

    return result;
}

static PyObject* pyhttp_body_read(struct pyhttp_request *pyreq, PyObject *args)
{
    ssize_t ret;
    size_t  len;
    Py_ssize_t pylen;
    PyObject *result = NULL;
    uint8_t buf[1024];

    if( !PyArg_ParseTuple(args, "n", &pylen) || pylen < 0 )
    {
        PyErr_SetString(PyExc_TypeError, "invalid parameters");
        return NULL;
    }

    len = (size_t)pylen;
    if( len > sizeof(buf) )
    {
        PyErr_SetString(PyExc_RuntimeError, "len > sizeof(buf)");
        return NULL;
    }

    ret = http_body_read(pyreq->req, buf, len);
    if( ret == -1 )
    {
        PyErr_SetString(PyExc_RuntimeError, "http_body_read() failed");
        return NULL;
    }

    if( ret > INT_MAX )
    {
        PyErr_SetString(PyExc_RuntimeError, "ret > INT_MAX");
        return NULL;
    }

    if( (result = Py_BuildValue("ny#", ret, buf, (int)ret)) == NULL )
        return PyErr_NoMemory();

    return result;
}

static PyObject* pyhttp_populate_get(struct pyhttp_request *pyreq, PyObject *args)
{
    http_populate_get(pyreq->req);
    Py_RETURN_TRUE;
}

static PyObject* pyhttp_populate_post(struct pyhttp_request *pyreq, PyObject *args)
{
    http_populate_post(pyreq->req);
    Py_RETURN_TRUE;
}

static PyObject* pyhttp_argument(struct pyhttp_request *pyreq, PyObject *args)
{
    const char *name = NULL;
    PyObject *value = NULL;
    char *string = NULL;

    if( !PyArg_ParseTuple(args, "s", &name) )
        return NULL;

    if( !http_argument_get_string(pyreq->req, name, &string) ) {
        Py_RETURN_NONE;
    }

    if ((value = PyUnicode_FromString(string)) == NULL)
        return (PyErr_NoMemory());

    return value;
}

static PyObject* pyhttp_websocket_handshake(struct pyhttp_request *pyreq, PyObject *args)
{
    const char  *onconnect, *onmsg, *ondisconnect;

    if( !PyArg_ParseTuple(args, "sss", &onconnect, &onmsg, &ondisconnect) )
        return NULL;

    cf_websocket_handshake(pyreq->req, onconnect, onmsg, ondisconnect);

    Py_RETURN_TRUE;
}

static PyObject* pyconnection_websocket_send(struct pyconnection *pyc, PyObject *args)
{
    const char  *data = NULL;
    int op, len = -1;

    if( pyc->c->proto != CONN_PROTO_WEBSOCKET )
    {
        PyErr_SetString(PyExc_TypeError, "not a websocket connection");
        return NULL;
    }

    if( !PyArg_ParseTuple(args, "iy#", &op, &data, &len) )
        return NULL;

    if( len < 0 )
    {
        PyErr_SetString(PyExc_TypeError, "invalid length");
        return NULL;
    }

    switch( op )
    {
    case WEBSOCKET_OP_TEXT:
    case WEBSOCKET_OP_BINARY:
        break;
    default:
        PyErr_SetString(PyExc_TypeError, "invalid op parameter");
        return NULL;
    }

    cf_websocket_send(pyc->c, op, data, len);

    Py_RETURN_TRUE;
}

static PyObject* python_websocket_broadcast( PyObject *self, PyObject *args )
{
    struct connection *c = NULL;
    struct pyconnection *pyc = NULL;
    const char *data = NULL;
    PyObject *pysrc = NULL;
    int op, broadcast, len =-1;

    if( !PyArg_ParseTuple(args, "Oiy#i", &pysrc, &op, &data, &len, &broadcast) )
        return NULL;

    if( len < 0 )
    {
        PyErr_SetString(PyExc_TypeError, "invalid length");
        return NULL;
    }

    switch( op )
    {
    case WEBSOCKET_OP_TEXT:
    case WEBSOCKET_OP_BINARY:
        break;
    default:
        PyErr_SetString(PyExc_TypeError, "invalid op parameter");
        return NULL;
    }

    if( pysrc == Py_None ) {
        c = NULL;
    }
    else
    {
        if( !PyObject_TypeCheck(pysrc, &pyconnection_type) )
        {
            PyErr_SetString(PyExc_TypeError, "invalid parameters");
            return NULL;
        }

        pyc = (struct pyconnection *)pysrc;
        c = pyc->c;
    }

    cf_websocket_broadcast(c, op, data, len, broadcast);

    Py_RETURN_TRUE;
}

static PyObject* pyhttp_get_host(struct pyhttp_request *pyreq, void *closure)
{
    PyObject *host = NULL;

    if( (host = PyUnicode_FromString(pyreq->req->host)) == NULL )
        return PyErr_NoMemory();

    return host;
}

static PyObject* pyhttp_get_path(struct pyhttp_request *pyreq, void *closure)
{
    PyObject *path = NULL;

    if( (path = PyUnicode_FromString(pyreq->req->path)) == NULL )
        return PyErr_NoMemory();

    return path;
}

static PyObject* pyhttp_get_body(struct pyhttp_request *pyreq, void *closure)
{
    ssize_t  ret;
    struct cf_buf buf;
    PyObject *body = NULL;
    uint8_t data[BUFSIZ];

    /* Init buffer */
    cf_buf_init(&buf, 1024);

    if( !http_body_rewind(pyreq->req) )
    {
        PyErr_SetString(PyExc_RuntimeError,"http_body_rewind() failed");
        return NULL;
    }

    for(;;)
    {
        ret = http_body_read(pyreq->req, data, sizeof(data));
        if( ret == -1 )
        {
            cf_buf_cleanup(&buf);
            PyErr_SetString(PyExc_RuntimeError, "http_body_read() failed");
            return NULL;
        }

        if( ret == 0 )
            break;

        cf_buf_append(&buf, data, (size_t)ret);
    }

    body = PyBytes_FromStringAndSize((char *)buf.data, buf.offset);
    cf_buf_free(&buf);

    if( body == NULL )
        return PyErr_NoMemory();

    return body;
}

static PyObject* pyhttp_get_agent(struct pyhttp_request *pyreq, void *closure)
{
    PyObject *agent = NULL;

    if( pyreq->req->agent == NULL ) {
        Py_RETURN_NONE;
    }

    if( (agent = PyUnicode_FromString(pyreq->req->path)) == NULL )
        return PyErr_NoMemory();

    return agent;
}

static PyObject* pyhttp_get_method(struct pyhttp_request *pyreq, void *closure)
{
    PyObject *method = NULL;

    if( (method = PyLong_FromUnsignedLong(pyreq->req->method)) == NULL )
        return PyErr_NoMemory();

    return method;
}

static PyObject* pyhttp_get_body_path( struct pyhttp_request *pyreq, void *closure )
{
    PyObject *path = NULL;

    if( pyreq->req->http_body_path == NULL )
        Py_RETURN_NONE;

    if( (path = PyUnicode_FromString(pyreq->req->http_body_path)) == NULL )
        return (PyErr_NoMemory());

    return path;
}

static PyObject* pyhttp_get_connection( struct pyhttp_request *pyreq, void *closure )
{
    PyObject *pyc = NULL;

    if( pyreq->req->owner == NULL ) {
        Py_RETURN_NONE;
    }

    if( (pyc = pyconnection_alloc(pyreq->req->owner)) == NULL )
        return PyErr_NoMemory();

    return pyc;
}

static PyObject* pyhttp_file_get_name(struct pyhttp_file *pyfile, void *closure)
{
    PyObject *name = NULL;

    if( (name = PyUnicode_FromString(pyfile->file->name)) == NULL )
        return PyErr_NoMemory();

    return name;
}

static PyObject* pyhttp_file_get_filename(struct pyhttp_file *pyfile, void *closure)
{
    PyObject *name = NULL;

    if( (name = PyUnicode_FromString(pyfile->file->filename)) == NULL )
        return PyErr_NoMemory();

    return name;
}

static PyObject* pyhttp_file_lookup(struct pyhttp_request *pyreq, PyObject *args)
{
    const char  *name = NULL;
    struct http_file *file = NULL;
    PyObject *pyfile = NULL;

    if( !PyArg_ParseTuple(args, "s", &name) )
        return NULL;

    if( (file = http_file_lookup(pyreq->req, name)) == NULL ) {
        Py_RETURN_NONE;
    }

    if( (pyfile = pyhttp_file_alloc(file)) == NULL )
        return PyErr_NoMemory();

    return pyfile;
}

static void pyhttp_file_dealloc(struct pyhttp_file *pyfile)
{
    PyObject_Del((PyObject *)pyfile);
}

static PyObject* pyhttp_file_read(struct pyhttp_file *pyfile, PyObject *args)
{
    ssize_t ret;
    size_t len;
    Py_ssize_t pylen;
    PyObject *result = NULL;
    uint8_t buf[1024];

    if( !PyArg_ParseTuple(args, "n", &pylen) || pylen < 0 )
    {
        PyErr_SetString(PyExc_TypeError, "invalid parameters");
        return NULL;
    }

    if( (len = (size_t)pylen) > sizeof(buf) )
    {
        PyErr_SetString(PyExc_RuntimeError, "len > sizeof(buf)");
        return NULL;
    }

    if( (ret = http_file_read(pyfile->file, buf, len)) == -1 )
    {
        PyErr_SetString(PyExc_RuntimeError, "http_file_read() failed");
        return NULL;
    }

    if( ret > INT_MAX )
    {
        PyErr_SetString(PyExc_RuntimeError, "ret > INT_MAX");
        return NULL;
    }

    if( (result = Py_BuildValue("ny#", ret, buf, (int)ret)) == NULL )
        return PyErr_NoMemory();

    return result;
}

static PyObject* pyhttp_populate_multi(struct pyhttp_request *pyreq, PyObject *args)
{
    http_populate_multipart_form(pyreq->req);
    Py_RETURN_TRUE;
}

static PyObject* pyhttp_populate_cookies( struct pyhttp_request *pyreq, PyObject *args )
{
    http_populate_cookies(pyreq->req);
    Py_RETURN_TRUE;
}

static PyObject* pyhttp_cookie( struct pyhttp_request *pyreq, PyObject *args )
{
    const char  *name = NULL;
    PyObject    *value = NULL;
    char        *string = NULL;

    if( !PyArg_ParseTuple(args, "s", &name) )
        return NULL;

    if( !http_request_cookie(pyreq->req, name, &string) ) {
        Py_RETURN_NONE;
    }

    if( (value = PyUnicode_FromString(string)) == NULL )
        return (PyErr_NoMemory());

    return value;
}

#endif  /* CF_NO_HTTP */


#ifdef CF_PGSQL
static PyObject* python_pgsql_register( PyObject *self, PyObject *args )
{
    const char *db, *conninfo;

    if( !PyArg_ParseTuple(args, "ss", &db, &conninfo) )
        return NULL;

    cf_pgsql_register( db, conninfo );

    Py_RETURN_TRUE;
}

static void python_pgsql_dealloc(struct py_pgsql *pysql)
{
    mem_free(pysql->db);
    mem_free(pysql->query);
    cf_pgsql_cleanup(&pysql->sql);

    if( pysql->result != NULL )
        Py_DECREF( pysql->result );

    PyObject_Del( (PyObject *)pysql );
}

static PyObject* python_pgsql_alloc( struct http_request *req, const char *db, const char *query )
{
    struct py_pgsql *pysql = NULL;

    if( (pysql = PyObject_New(struct py_pgsql, &python_pgsql_type)) == NULL )
        return NULL;

    pysql->req = req;
    pysql->result = NULL;
    pysql->db = mem_strdup(db);
    pysql->query = mem_strdup(query);
    pysql->state = PYCF_PGSQL_PREINIT;

    memset( &pysql->sql, 0, sizeof(pysql->sql) );

    return (PyObject *)pysql;
}

static PyObject* python_pgsql_iternext( struct py_pgsql *pysql )
{
    switch( pysql->state )
    {
    case PYCF_PGSQL_PREINIT:
        cf_pgsql_init(&pysql->sql);
        cf_pgsql_bind_request(&pysql->sql, pysql->req);
        pysql->state = PYCF_PGSQL_INITIALIZE;
        /* fallthrough */
    case PYCF_PGSQL_INITIALIZE:
        if( !cf_pgsql_setup(&pysql->sql, pysql->db, CF_PGSQL_ASYNC) )
        {
            if( pysql->sql.state == CF_PGSQL_STATE_INIT )
                break;
            cf_pgsql_logerror( &pysql->sql );
            PyErr_SetString(PyExc_RuntimeError, "pgsql error");
            return NULL;
        }
        /* fallthrough */
    case PYCF_PGSQL_QUERY:
        if( !cf_pgsql_query(&pysql->sql, pysql->query))
        {
            cf_pgsql_logerror( &pysql->sql );
            PyErr_SetString(PyExc_RuntimeError, "pgsql error");
            return NULL;
        }
        pysql->state = PYCF_PGSQL_WAIT;
        break;
wait_again:
    case PYCF_PGSQL_WAIT:
        switch( pysql->sql.state )
        {
        case CF_PGSQL_STATE_WAIT:
            break;
        case CF_PGSQL_STATE_COMPLETE:
            PyErr_SetNone(PyExc_StopIteration);
            if( pysql->result != NULL )
            {
                PyErr_SetObject(PyExc_StopIteration,pysql->result);
                Py_DECREF(pysql->result);
            }
            else {
                PyErr_SetObject(PyExc_StopIteration, Py_None);
            }
            return NULL;
        case CF_PGSQL_STATE_ERROR:
            cf_pgsql_logerror( &pysql->sql );
            PyErr_SetString(PyExc_RuntimeError, "failed to perform query");
            return NULL;
        case CF_PGSQL_STATE_RESULT:
            if( !python_pgsql_result(pysql) )
                return NULL;
            goto wait_again;
        default:
            cf_pgsql_continue(pysql->req, &pysql->sql);
            goto wait_again;
        }
        break;
    default:
        PyErr_SetString(PyExc_RuntimeError, "bad python_pgsql state");
        return NULL;
    }

    /* tell caller to wait */
    Py_RETURN_NONE;
}

static PyObject* python_pgsql_await(PyObject *obj)
{
    Py_INCREF( obj );
    return obj;
}

int python_pgsql_result(struct py_pgsql *pysql)
{
    const char *val = NULL;
    char key[64];
    PyObject *list, *pyrow, *pyval;
    int rows, row, field, fields;

    if( (list = PyList_New(0)) == NULL )
    {
        PyErr_SetNone(PyExc_MemoryError);
        return CF_RESULT_ERROR;
    }

    rows = cf_pgsql_ntuples(&pysql->sql);
    fields = cf_pgsql_nfields(&pysql->sql);

    for( row = 0; row < rows; row++ )
    {
        if( (pyrow = PyDict_New()) == NULL )
        {
            Py_DECREF(list);
            PyErr_SetNone(PyExc_MemoryError);
            return CF_RESULT_ERROR;
        }

        for( field = 0; field < fields; field++ )
        {
            val = cf_pgsql_getvalue(&pysql->sql, row, field);

            pyval = PyUnicode_FromString(val);
            if( pyval == NULL )
            {
                Py_DECREF(pyrow);
                Py_DECREF(list);
                PyErr_SetNone(PyExc_MemoryError);
                return CF_RESULT_ERROR;
            }

            snprintf(key, sizeof(key), "%s", cf_pgsql_fieldname(&pysql->sql, field));

            if( PyDict_SetItemString(pyrow, key, pyval) == -1 )
            {
                Py_DECREF(pyval);
                Py_DECREF(pyrow);
                Py_DECREF(list);
                PyErr_SetString(PyExc_RuntimeError, "failed to add new value to row");
                return CF_RESULT_ERROR;
            }

            Py_DECREF(pyval);
        }

        if( PyList_Insert(list, row, pyrow) == -1 )
        {
            Py_DECREF(pyrow);
            Py_DECREF(list);
            PyErr_SetString(PyExc_RuntimeError, "failed to add new row to list");
            return CF_RESULT_ERROR;
        }

        Py_DECREF(pyrow);
    }

    pysql->result = list;
    cf_pgsql_continue(pysql->req, &pysql->sql);

    return CF_RESULT_OK;
}

static PyObject* pyhttp_pgsql( struct pyhttp_request *pyreq, PyObject *args )
{
    PyObject *obj = NULL;
    const char *db, *query;

    if( !PyArg_ParseTuple(args, "ss", &db, &query) )
        return NULL;

    if( (obj = python_pgsql_alloc(pyreq->req, db, query)) == NULL )
        return PyErr_NoMemory();

    Py_INCREF(obj);
    pyreq->data = obj;

    return (PyObject *)obj;
}
#endif /* CF_PGSQL */

