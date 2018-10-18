// cf_python_methods.h


/* Forward function declaration */
static PyObject* python_log(PyObject*, PyObject*);
static PyObject* python_fatal(PyObject*, PyObject*);
static PyObject* python_fatalx( PyObject*, PyObject*);
static PyObject* python_bind(PyObject*, PyObject*);
static PyObject* python_bind_unix(PyObject*, PyObject*);
static PyObject* python_task_create(PyObject*, PyObject*);
static PyObject* python_socket_wrap(PyObject*, PyObject*);

#ifndef CF_NO_HTTP
    static PyObject* python_websocket_broadcast(PyObject*, PyObject*);
#endif

#ifdef CF_PGSQL
    static PyObject* python_pgsql_register(PyObject*, PyObject*);
#endif

#define METHOD(n, c, a)		{ n, (PyCFunction)c, a, NULL }
#define GETTER(n, g)		{ n, (getter)g, NULL, NULL, NULL }
#define SETTER(n, s)		{ n, NULL, (setter)g, NULL, NULL }
#define GETSET(n, g, s)		{ n, (getter)g, (setter)s, NULL, NULL }

static struct PyMethodDef pycf_methods[] =
{
    METHOD("log", python_log, METH_VARARGS),
    METHOD("fatal", python_fatal, METH_VARARGS),
    METHOD("fatalx", python_fatalx, METH_VARARGS),
    METHOD("bind", python_bind, METH_VARARGS),
    METHOD("bind_unix", python_bind_unix, METH_VARARGS),
    METHOD("task_create", python_task_create, METH_VARARGS),
    METHOD("socket_wrap", python_socket_wrap, METH_VARARGS),
#ifndef CF_NO_HTTP
    METHOD("websocket_broadcast", python_websocket_broadcast, METH_VARARGS),
#endif
#ifdef CF_PGSQL
    METHOD("register_database", python_pgsql_register, METH_VARARGS),
#endif
	{ NULL, NULL, 0, NULL }
};

static struct PyModuleDef pycf_module =
{
    PyModuleDef_HEAD_INIT, "zfrog", NULL, -1, pycf_methods
};


struct pysocket {
    PyObject_HEAD
    int			fd;
    int			family;
    int			protocol;
    PyObject	*socket;
    socklen_t	addr_len;
    union {
        struct sockaddr_in	ipv4;
        struct sockaddr_un	sun;
    } addr;
};

static PyObject* pysocket_send(struct pysocket*, PyObject*);
static PyObject* pysocket_recv(struct pysocket*, PyObject*);
static PyObject* pysocket_close(struct pysocket*, PyObject*);
static PyObject* pysocket_accept(struct pysocket*, PyObject*);
static PyObject* pysocket_connect(struct pysocket*, PyObject*);

static PyMethodDef pysocket_methods[] = {
    METHOD("recv", pysocket_recv, METH_VARARGS),
    METHOD("send", pysocket_send, METH_VARARGS),
    METHOD("close", pysocket_close, METH_NOARGS),
    METHOD("accept", pysocket_accept, METH_NOARGS),
    METHOD("connect", pysocket_connect, METH_VARARGS),
    METHOD(NULL, NULL, -1),
};

static void	pysocket_dealloc(struct pysocket *);


static PyTypeObject pysocket_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "zfrog.socket",
    .tp_doc = "zfrog socket implementation",
    .tp_methods = pysocket_methods,
    .tp_basicsize = sizeof(struct pysocket),
    .tp_dealloc = (destructor)pysocket_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

#define PYSOCKET_TYPE_ACCEPT	1
#define PYSOCKET_TYPE_CONNECT	2
#define PYSOCKET_TYPE_RECV      3
#define PYSOCKET_TYPE_SEND      4

struct pysocket_data {
    struct cf_event     evt;
    int                 fd;
    int                 type;
    void                *self;
    void                *coro;
    int                 state;
    size_t              length;
    struct cf_buf		buffer;
    struct pysocket		*socket;
};

struct pysocket_op {
    PyObject_HEAD
    struct pysocket_data	data;
};

static void	pysocket_op_dealloc(struct pysocket_op*);

static PyObject	*pysocket_op_await(PyObject *);
static PyObject	*pysocket_op_iternext(struct pysocket_op*);

static PyAsyncMethods pysocket_op_async = {
    (unaryfunc)pysocket_op_await,
    NULL,
    NULL
};

static PyTypeObject pysocket_op_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "zfrog.socketop",
    .tp_doc = "socket operation",
    .tp_as_async = &pysocket_op_async,
    .tp_iternext = (iternextfunc)pysocket_op_iternext,
    .tp_basicsize = sizeof(struct pysocket_op),
    .tp_dealloc = (destructor)pysocket_op_dealloc,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
};

struct pyconnection
{
	PyObject_HEAD
    struct connection  *c;
};

static PyObject* pyconnection_disconnect(struct pyconnection*, PyObject*);

#ifndef CF_NO_HTTP
    static PyObject* pyconnection_websocket_send(struct pyconnection*, PyObject*);
#endif

static PyMethodDef pyconnection_methods[] = {
    METHOD("disconnect", pyconnection_disconnect, METH_NOARGS),
#ifndef CF_NO_HTTP
    METHOD("websocket_send", pyconnection_websocket_send, METH_VARARGS),
#endif
	METHOD(NULL, NULL, -1),
};

static PyObject* pyconnection_get_fd(struct pyconnection*, void*);
static PyObject* pyconnection_get_addr(struct pyconnection*, void*);

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
    PyObject		    *data;
};

struct pyhttp_file
{
    PyObject_HEAD
    struct http_file *file;
};

static void	pyhttp_dealloc(struct pyhttp_request*);
static void	pyhttp_file_dealloc(struct pyhttp_file*);

static PyObject* pyhttp_cookie(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_response(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_argument(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_body_read(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_file_lookup(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_populate_get(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_populate_post(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_populate_multi(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_populate_cookies(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_request_header(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_response_header(struct pyhttp_request*, PyObject*);
static PyObject* pyhttp_websocket_handshake(struct pyhttp_request*, PyObject*);

#ifdef CF_PGSQL
    static PyObject* pyhttp_pgsql(struct pyhttp_request*, PyObject*);
#endif

static PyMethodDef pyhttp_request_methods[] =
{
#ifdef CF_PGSQL
    METHOD("pgsql", pyhttp_pgsql, METH_VARARGS),
#endif
    METHOD("cookie", pyhttp_cookie, METH_VARARGS),
	METHOD("response", pyhttp_response, METH_VARARGS),
    METHOD("argument", pyhttp_argument, METH_VARARGS),
	METHOD("body_read", pyhttp_body_read, METH_VARARGS),
    METHOD("file_lookup", pyhttp_file_lookup, METH_VARARGS),
	METHOD("populate_get", pyhttp_populate_get, METH_NOARGS),
	METHOD("populate_post", pyhttp_populate_post, METH_NOARGS),
    METHOD("populate_multi", pyhttp_populate_multi, METH_NOARGS),
    METHOD("populate_cookies", pyhttp_populate_cookies, METH_NOARGS),
	METHOD("request_header", pyhttp_request_header, METH_VARARGS),
	METHOD("response_header", pyhttp_response_header, METH_VARARGS),
    METHOD("websocket_handshake", pyhttp_websocket_handshake, METH_VARARGS),
	METHOD(NULL, NULL, -1)
};

static PyObject* pyhttp_get_host(struct pyhttp_request*, void*);
static PyObject* pyhttp_get_path(struct pyhttp_request*, void*);
static PyObject* pyhttp_get_body(struct pyhttp_request*, void*);
static PyObject* pyhttp_get_agent(struct pyhttp_request*, void*);
static PyObject* pyhttp_get_method(struct pyhttp_request*, void*);
static PyObject* pyhttp_get_body_path(struct pyhttp_request*, void*);
static PyObject* pyhttp_get_connection(struct pyhttp_request*, void*);


static PyGetSetDef pyhttp_request_getset[] =
{
	GETTER("host", pyhttp_get_host),
	GETTER("path", pyhttp_get_path),
	GETTER("body", pyhttp_get_body),
	GETTER("agent", pyhttp_get_agent),
	GETTER("method", pyhttp_get_method),
    GETTER("body_path", pyhttp_get_body_path),
	GETTER("connection", pyhttp_get_connection),
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

static PyObject* pyhttp_file_read(struct pyhttp_file*, PyObject*);

static PyMethodDef pyhttp_file_methods[] =
{
    METHOD("read", pyhttp_file_read, METH_VARARGS),
    METHOD(NULL, NULL, -1)
};

static PyObject* pyhttp_file_get_name(struct pyhttp_file*, void*);
static PyObject* pyhttp_file_get_filename(struct pyhttp_file*, void*);

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

#define PYCF_PGSQL_PREINIT	    1
#define PYCF_PGSQL_INITIALIZE	2
#define PYCF_PGSQL_QUERY		3
#define PYCF_PGSQL_WAIT         4

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

static PyObject* python_pgsql_await(PyObject*);
static PyObject* python_pgsql_iternext(struct py_pgsql*);

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

