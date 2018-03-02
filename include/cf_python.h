// cf_python.h

#ifndef __CF_PYTHON_H__
#define __CF_PYTHON_H__

#if defined(__cplusplus)
extern "C" {
#endif

#undef _POSIX_C_SOURCE
#undef _XOPEN_SOURCE

#include <Python.h>

void cf_python_init(void);
void cf_python_cleanup(void);
void cf_python_path(const char*);

PyObject* cf_python_callable(PyObject*, const char*);

extern struct cf_module_functions	cf_python_module;
extern struct cf_runtime            cf_python_runtime;

#if defined(__cplusplus)
}
#endif

#endif // __CF_PYTHON_H__
