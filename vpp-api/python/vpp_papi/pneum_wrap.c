#include <Python.h>
#include "pneum.h"

static PyObject *pneum_callback = NULL;

int
wrap_pneum_callback (char *data, int len)
{
  PyGILState_STATE gstate;
  PyObject *result;//, *arglist;

  gstate = PyGILState_Ensure();

  /* Time to call the callback */
  result = PyObject_CallFunction(pneum_callback, "y#", data, len);
  if (result)
    Py_DECREF(result);
  else
    PyErr_Print();

  PyGILState_Release(gstate);
  return (0);
}

static PyObject *
wrap_connect (PyObject *self, PyObject *args)
{
  char *name;
  int rv;
  PyObject *temp;

  if (!PyArg_ParseTuple(args, "sO:set_callback", &name, &temp))
    return (NULL);
  
  if (!PyCallable_Check(temp)) {
    PyErr_SetString(PyExc_TypeError, "parameter must be callable");
    return NULL;
  }

  Py_XINCREF(temp);         /* Add a reference to new callback */
  Py_XDECREF(pneum_callback);  /* Dispose of previous callback */
  pneum_callback = temp;       /* Remember new callback */

  Py_BEGIN_ALLOW_THREADS
  rv = pneum_connect(name);
  Py_END_ALLOW_THREADS
  return PyLong_FromLong(rv);
}

static PyObject *
wrap_disconnect (PyObject *self, PyObject *args)
{
  int rv;
  Py_BEGIN_ALLOW_THREADS
  rv = pneum_disconnect();
  Py_END_ALLOW_THREADS
  return PyLong_FromLong(rv);
}
static PyObject *
wrap_write (PyObject *self, PyObject *args)
{
  char *data;
  int len, rv;

  if (!PyArg_ParseTuple(args, "s#", &data, &len)) 
    return NULL;     
  Py_BEGIN_ALLOW_THREADS
  rv = pneum_write(data, len);
  Py_END_ALLOW_THREADS

  return PyLong_FromLong(rv);
}

void vl_msg_api_free(void *);

static PyObject *
wrap_read (PyObject *self, PyObject *args)
{
  char *data;
  int len, rv;

  Py_BEGIN_ALLOW_THREADS
  rv = pneum_read(&data, &len);
  Py_END_ALLOW_THREADS

  if (rv != 0) { Py_RETURN_NONE; }

  PyObject *ret = Py_BuildValue("y#", data, len);
  if (!ret) { Py_RETURN_NONE; }

  vl_msg_api_free(data);
  return ret;
}

static PyMethodDef vpp_api_Methods[] = {
  {"connect", wrap_connect, METH_VARARGS, "Connect to the VPP API."},
  {"disconnect", wrap_disconnect, METH_VARARGS, "Disconnect from the VPP API."},
  {"write", wrap_write, METH_VARARGS, "Write data to the VPP API."},
  {"read", wrap_read, METH_VARARGS, "Read data from the VPP API."},
  {NULL, NULL, 0, NULL}        /* Sentinel */
};

static struct PyModuleDef vpp_api_module = {
  PyModuleDef_HEAD_INIT,
  "vpp_api",   /* name of module */
   NULL, /* module documentation, may be NULL */
  -1,       /* size of per-interpreter state of the module,
	       or -1 if the module keeps state in global variables. */
  vpp_api_Methods
};

PyMODINIT_FUNC
PyInit_vpp_api (void)
{
  /* Ensure threading is initialised */
  if (!PyEval_ThreadsInitialized()) {
    PyEval_InitThreads();
  }
  return PyModule_Create(&vpp_api_module);
}
