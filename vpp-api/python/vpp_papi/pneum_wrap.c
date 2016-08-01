/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <Python.h>
#include "../pneum/pneum.h"

static PyObject *pneum_callback = NULL;

int
wrap_pneum_callback (char *data, int len)
{
  PyGILState_STATE gstate;
  PyObject *result;//, *arglist;

  gstate = PyGILState_Ensure();

  /* Time to call the callback */
#if PY_VERSION_HEX >= 0x03000000
  result = PyObject_CallFunction(pneum_callback, "y#", data, len);
#else
  result = PyObject_CallFunction(pneum_callback, "s#", data, len);
#endif
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
#if PY_VERSION_HEX >= 0x03000000
  PyObject *ret = Py_BuildValue("y#", data, len);
#else
  PyObject *ret = Py_BuildValue("s#", data, len);
#endif
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

#if PY_VERSION_HEX >= 0x03000000
PyMODINIT_FUNC
PyInit_vpp_api (void)
#else
void
initvpp_api (void)
#endif
{
#if PY_VERSION_HEX >= 0x03000000
  static struct PyModuleDef vpp_api_module = {
#if PY_VERSION_HEX >= 0x03020000
    PyModuleDef_HEAD_INIT,
#else
    {
      PyObject_HEAD_INIT(NULL)
      NULL, /* m_init */
      0,    /* m_index */
      NULL, /* m_copy */
    },
#endif
    (char *) "vpp_api",
    NULL,
    -1,
    vpp_api_Methods,
    NULL,
    NULL,
    NULL,
    NULL
  };
#endif

  /* Ensure threading is initialised */
  if (!PyEval_ThreadsInitialized()) {
    PyEval_InitThreads();
  }

#if PY_VERSION_HEX >= 0x03000000
  return PyModule_Create(&vpp_api_module);
#else
  Py_InitModule((char *) "vpp_api", vpp_api_Methods);
  return;
#endif
}
