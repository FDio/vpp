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
#include <vppinfra/hash.h>

static PyObject *pneum_callback = NULL;

static void
wrap_pneum_callback (unsigned char * data, int len)
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
}

static PyObject *
wrap_connect (PyObject *self, PyObject *args)
{
  char * name, * chroot_prefix = NULL;
  int rv;
  PyObject * temp = NULL;
  pneum_callback_t cb = NULL;

  if (!PyArg_ParseTuple(args, "s|Os:wrap_connect",
			&name, &temp, &chroot_prefix))
    return (NULL);

  if (temp)
    {
      if (!PyCallable_Check(temp))
	{
	  PyErr_SetString(PyExc_TypeError, "parameter must be callable");
	  return NULL;
	}

      Py_XINCREF(temp);         /* Add a reference to new callback */
      Py_XDECREF(pneum_callback);  /* Dispose of previous callback */
      pneum_callback = temp;       /* Remember new callback */
      cb = wrap_pneum_callback;
    }
  Py_BEGIN_ALLOW_THREADS
    rv = pneum_connect(name, chroot_prefix, cb);
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

  pneum_free(data);
  return ret;
}

static PyObject *
wrap_msg_table (PyObject *self, PyObject *args)
{
  int i = 0, rv = 0;
  hash_pair_t *hp;
  uword *h = pneum_msg_table_get_hash();
  PyObject *ret = PyList_New(pneum_msg_table_size());
  if (!ret) goto error;
  hash_foreach_pair (hp, h,
  ({
    PyObject *item = PyTuple_New(2);
    if (!item) goto error;
    rv = PyTuple_SetItem(item, 0, PyLong_FromLong((u32)hp->value[0]));
    if (rv) goto error;
    rv = PyTuple_SetItem(item, 1, PyString_FromString((char *)hp->key));
    if (rv) goto error;
    PyList_SetItem(ret, i, item);
    i++;
  }));

  return ret;

 error:
  /* TODO: Raise exception */
  printf("msg_table failed");
  Py_RETURN_NONE;
}

static PyMethodDef vpp_api_Methods[] = {
  {"connect", wrap_connect, METH_VARARGS, "Connect to the VPP API."},
  {"disconnect", wrap_disconnect, METH_VARARGS, "Disconnect from the VPP API."},
  {"write", wrap_write, METH_VARARGS, "Write data to the VPP API."},
  {"read", wrap_read, METH_VARARGS, "Read data from the VPP API."},
  {"msg_table", wrap_msg_table, METH_VARARGS, "Get API dictionary."},
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
