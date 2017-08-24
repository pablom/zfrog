// cf_python_methods.h

static PyObject	*python_log(PyObject *, PyObject *);
static PyObject	*python_fatal(PyObject *, PyObject *);
static PyObject	*python_listen(PyObject *, PyObject *);

#ifndef CF_NO_HTTP
    static PyObject	*python_websocket_broadcast(PyObject *, PyObject *);
#endif

#ifdef CF_PGSQL
    static PyObject	*python_pgsql_register(PyObject *, PyObject *);
#endif

#define METHOD(n, c, a)		{ n, (PyCFunction)c, a, NULL }
#define GETTER(n, g)		{ n, (getter)g, NULL, NULL, NULL }
#define SETTER(n, s)		{ n, NULL, (setter)g, NULL, NULL }
#define GETSET(n, g, s)		{ n, (getter)g, (setter)s, NULL, NULL }

static struct PyMethodDef pycf_methods[] =
{
    METHOD("log", python_log, METH_VARARGS),
    METHOD("fatal", python_fatal, METH_VARARGS),
    METHOD("listen", python_listen, METH_VARARGS),
#ifndef CF_NO_HTTP
    METHOD("websocket_broadcast", python_websocket_broadcast, METH_VARARGS),
#endif
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef pycf_module =
{
    PyModuleDef_HEAD_INIT, "zfrog", NULL, -1, pycf_methods
};

struct pyconnection
{
	PyObject_HEAD
	struct connection	*c;
};

static PyObject *pyconnection_disconnect(struct pyconnection *, PyObject *);

#ifndef CF_NO_HTTP
    static PyObject *pyconnection_websocket_send(struct pyconnection *, PyObject *);
#endif

static PyMethodDef pyconnection_methods[] = {
    METHOD("disconnect", pyconnection_disconnect, METH_NOARGS),
#ifndef CF_NO_HTTP
    METHOD("websocket_send", pyconnection_websocket_send, METH_VARARGS),
#endif
	METHOD(NULL, NULL, -1),
};

static PyObject	*pyconnection_get_fd(struct pyconnection *, void *);
static PyObject	*pyconnection_get_addr(struct pyconnection *, void *);

static PyGetSetDef pyconnection_getset[] = {
    GETTER("fd", pyconnection_get_fd),
    GETTER("addr", pyconnection_get_addr),
	GETTER(NULL, NULL),
};

static void	pyconnection_dealloc(struct pyconnection *);

static PyTypeObject pyconnection_type = {
	PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "zfrog.connection",
	.tp_doc = "struct connection",
	.tp_getset = pyconnection_getset,
	.tp_methods = pyconnection_methods,
	.tp_basicsize = sizeof(struct pyconnection),
	.tp_dealloc = (destructor)pyconnection_dealloc,
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

#ifndef CF_NO_HTTP

struct pyhttp_request
{
	PyObject_HEAD
	struct http_request	*req;
};

struct pyhttp_file
{
    PyObject_HEAD
    struct http_file *file;
};

static void	pyhttp_dealloc(struct pyhttp_request *);
static void	pyhttp_file_dealloc(struct pyhttp_file *);

static PyObject	*pyhttp_response(struct pyhttp_request *, PyObject *);
static PyObject *pyhttp_argument(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_body_read(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_file_lookup(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_populate_get(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_populate_post(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_populate_multi(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_request_header(struct pyhttp_request *, PyObject *);
static PyObject	*pyhttp_response_header(struct pyhttp_request *, PyObject *);
static PyObject *pyhttp_websocket_handshake(struct pyhttp_request *, PyObject *);

static PyMethodDef pyhttp_request_methods[] =
{
	METHOD("response", pyhttp_response, METH_VARARGS),
    METHOD("argument", pyhttp_argument, METH_VARARGS),
	METHOD("body_read", pyhttp_body_read, METH_VARARGS),
    METHOD("file_lookup", pyhttp_file_lookup, METH_VARARGS),
	METHOD("populate_get", pyhttp_populate_get, METH_NOARGS),
	METHOD("populate_post", pyhttp_populate_post, METH_NOARGS),
    METHOD("populate_multi", pyhttp_populate_multi, METH_NOARGS),
	METHOD("request_header", pyhttp_request_header, METH_VARARGS),
	METHOD("response_header", pyhttp_response_header, METH_VARARGS),
    METHOD("websocket_handshake", pyhttp_websocket_handshake, METH_VARARGS),
	METHOD(NULL, NULL, -1)
};

static int	pyhttp_set_state(struct pyhttp_request *, PyObject *, void *);

static PyObject	*pyhttp_get_host(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_path(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_body(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_agent(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_state(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_method(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_body_path(struct pyhttp_request *, void *);
static PyObject	*pyhttp_get_connection(struct pyhttp_request *, void *);


static PyGetSetDef pyhttp_request_getset[] =
{
	GETTER("host", pyhttp_get_host),
	GETTER("path", pyhttp_get_path),
	GETTER("body", pyhttp_get_body),
	GETTER("agent", pyhttp_get_agent),
	GETTER("method", pyhttp_get_method),
    GETTER("body_path", pyhttp_get_body_path),
	GETTER("connection", pyhttp_get_connection),
	GETSET("state", pyhttp_get_state, pyhttp_set_state),
	GETTER(NULL, NULL)
};

static PyTypeObject pyhttp_request_type =
{
	PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "zfrog.http_request",
	.tp_doc = "struct http_request",
	.tp_getset = pyhttp_request_getset,
	.tp_methods = pyhttp_request_methods,
	.tp_dealloc = (destructor)pyhttp_dealloc,
	.tp_basicsize = sizeof(struct pyhttp_request),
	.tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

static PyObject	*pyhttp_file_read(struct pyhttp_file *, PyObject *);

static PyMethodDef pyhttp_file_methods[] =
{
    METHOD("read", pyhttp_file_read, METH_VARARGS),
    METHOD(NULL, NULL, -1)
};

static PyObject	*pyhttp_file_get_name(struct pyhttp_file *, void *);
static PyObject	*pyhttp_file_get_filename(struct pyhttp_file *, void *);

static PyGetSetDef pyhttp_file_getset[] =
{
    GETTER("name", pyhttp_file_get_name),
    GETTER("filename", pyhttp_file_get_filename),
    GETTER(NULL, NULL)
};

static PyTypeObject pyhttp_file_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "zfrog.http_file",
    .tp_doc = "struct http_file",
    .tp_getset = pyhttp_file_getset,
    .tp_methods = pyhttp_file_methods,
    .tp_dealloc = (destructor)pyhttp_file_dealloc,
    .tp_basicsize = sizeof(struct pyhttp_file),
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

#endif


#ifdef CF_PGSQL

#define PYCF_PGSQL_INITIALIZE	1
#define PYCF_PGSQL_QUERY		2
#define PYCF_PGSQL_WAIT         3

struct py_pgsql
{
    PyObject_HEAD
    int		state;
    char	*db;
    char	*query;
    struct http_request	*req;
    PyObject *result;
    struct cf_pgsql	sql;
};

static void	python_pgsql_dealloc(struct py_pgsql *);
int	python_pgsql_result(struct py_pgsql *);

static PyObject	*python_pgsql_await(PyObject *);
static PyObject	*python_pgsql_iternext(struct py_pgsql *);

static PyAsyncMethods python_pgsql_async =
{
    (unaryfunc)python_pgsql_await,
    NULL,
    NULL
};

static PyTypeObject python_pgsql_type =
{
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "zfrog.pgsql",
    .tp_doc = "struct cf_pgsql",
    .tp_as_async = &python_pgsql_async,
    .tp_iternext = (iternextfunc)python_pgsql_iternext,
    .tp_basicsize = sizeof(struct py_pgsql),
    .tp_dealloc = (destructor)python_pgsql_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};
#endif

