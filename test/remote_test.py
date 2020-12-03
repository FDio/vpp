#!/usr/bin/env python3

import inspect
import os
import reprlib
import unittest
from framework import VppTestCase
from multiprocessing import Process, Pipe
from pickle import dumps
import sys

from enum import IntEnum, IntFlag


class SerializableClassCopy(object):
    """
    Empty class used as a basis for a serializable copy of another class.
    """
    pass

    def __repr__(self):
        return '<SerializableClassCopy dict=%s>' % self.__dict__


class RemoteClassAttr(object):
    """
    Wrapper around attribute of a remotely executed class.
    """

    def __init__(self, remote, attr):
        self._path = [attr] if attr else []
        self._remote = remote

    def path_to_str(self):
        return '.'.join(self._path)

    def get_remote_value(self):
        return self._remote._remote_exec(RemoteClass.GET, self.path_to_str())

    def __repr__(self):
        return self._remote._remote_exec(RemoteClass.REPR, self.path_to_str())

    def __str__(self):
        return self._remote._remote_exec(RemoteClass.STR, self.path_to_str())

    def __getattr__(self, attr):
        if attr[0] == '_':
            if not (attr.startswith('__') and attr.endswith('__')):
                raise AttributeError('tried to get private attribute: %s ',
                                     attr)
        self._path.append(attr)
        return self

    def __setattr__(self, attr, val):
        if attr[0] == '_':
            if not (attr.startswith('__') and attr.endswith('__')):
                super(RemoteClassAttr, self).__setattr__(attr, val)
                return
        self._path.append(attr)
        self._remote._remote_exec(RemoteClass.SETATTR, self.path_to_str(),
                                  value=val)

    def __call__(self, *args, **kwargs):
        return self._remote._remote_exec(RemoteClass.CALL, self.path_to_str(),
                                         *args, **kwargs)


class RemoteClass(Process):
    """
    This class can wrap around and adapt the interface of another class,
    and then delegate its execution to a newly forked child process.
    Usage:
        # Create a remotely executed instance of MyClass
        object = RemoteClass(MyClass, arg1='foo', arg2='bar')
        object.start_remote()
        # Access the object normally as if it was an instance of your class.
        object.my_attribute = 20
        print object.my_attribute
        print object.my_method(object.my_attribute)
        object.my_attribute.nested_attribute = 'test'
        # If you need the value of a remote attribute, use .get_remote_value
        method. This method is automatically called when needed in the context
        of a remotely executed class. E.g.:
        if (object.my_attribute.get_remote_value() > 20):
            object.my_attribute2 = object.my_attribute
        # Destroy the instance
        object.quit_remote()
        object.terminate()
    """

    GET = 0       # Get attribute remotely
    CALL = 1      # Call method remotely
    SETATTR = 2   # Set attribute remotely
    REPR = 3      # Get representation of a remote object
    STR = 4       # Get string representation of a remote object
    QUIT = 5      # Quit remote execution

    PIPE_PARENT = 0  # Parent end of the pipe
    PIPE_CHILD = 1  # Child end of the pipe

    DEFAULT_TIMEOUT = 2  # default timeout for an operation to execute

    def __init__(self, cls, *args, **kwargs):
        super(RemoteClass, self).__init__()
        self._cls = cls
        self._args = args
        self._kwargs = kwargs
        self._timeout = RemoteClass.DEFAULT_TIMEOUT
        self._pipe = Pipe()  # pipe for input/output arguments

    def __repr__(self):
        return reprlib.repr(RemoteClassAttr(self, None))

    def __str__(self):
        return str(RemoteClassAttr(self, None))

    def __call__(self, *args, **kwargs):
        return self.RemoteClassAttr(self, None)()

    def __getattr__(self, attr):
        if attr[0] == '_' or not self.is_alive():
            if not (attr.startswith('__') and attr.endswith('__')):
                if hasattr(super(RemoteClass, self), '__getattr__'):
                    return super(RemoteClass, self).__getattr__(attr)
                raise AttributeError('missing: %s', attr)
        return RemoteClassAttr(self, attr)

    def __setattr__(self, attr, val):
        if attr[0] == '_' or not self.is_alive():
            if not (attr.startswith('__') and attr.endswith('__')):
                super(RemoteClass, self).__setattr__(attr, val)
                return
        setattr(RemoteClassAttr(self, None), attr, val)

    def _remote_exec(self, op, path=None, *args, **kwargs):
        """
        Execute given operation on a given, possibly nested, member remotely.
        """
        # automatically resolve remote objects in the arguments
        mutable_args = list(args)
        for i, val in enumerate(mutable_args):
            if isinstance(val, RemoteClass) or \
                    isinstance(val, RemoteClassAttr):
                mutable_args[i] = val.get_remote_value()
        args = tuple(mutable_args)
        for key, val in kwargs.items():
            if isinstance(val, RemoteClass) or \
                    isinstance(val, RemoteClassAttr):
                kwargs[key] = val.get_remote_value()
        # send request
        args = self._make_serializable(args)
        kwargs = self._make_serializable(kwargs)
        self._pipe[RemoteClass.PIPE_PARENT].send((op, path, args, kwargs))
        timeout = self._timeout
        # adjust timeout specifically for the .sleep method
        if path is not None and path.split('.')[-1] == 'sleep':
            if args and isinstance(args[0], (long, int)):
                timeout += args[0]
            elif 'timeout' in kwargs:
                timeout += kwargs['timeout']
        if not self._pipe[RemoteClass.PIPE_PARENT].poll(timeout):
            return None
        try:
            rv = self._pipe[RemoteClass.PIPE_PARENT].recv()
            rv = self._deserialize(rv)
            return rv
        except EOFError:
            return None

    def _get_local_object(self, path):
        """
        Follow the path to obtain a reference on the addressed nested attribute
        """
        obj = self._instance
        for attr in path:
            obj = getattr(obj, attr)
        return obj

    def _get_local_value(self, path):
        try:
            return self._get_local_object(path)
        except AttributeError:
            return None

    def _call_local_method(self, path, *args, **kwargs):
        try:
            method = self._get_local_object(path)
            return method(*args, **kwargs)
        except AttributeError:
            return None

    def _set_local_attr(self, path, value):
        try:
            obj = self._get_local_object(path[:-1])
            setattr(obj, path[-1], value)
        except AttributeError:
            pass
        return None

    def _get_local_repr(self, path):
        try:
            obj = self._get_local_object(path)
            return reprlib.repr(obj)
        except AttributeError:
            return None

    def _get_local_str(self, path):
        try:
            obj = self._get_local_object(path)
            return str(obj)
        except AttributeError:
            return None

    def _serializable(self, obj):
        """ Test if the given object is serializable """
        try:
            dumps(obj)
            return True
        except:
            return False

    def _make_obj_serializable(self, obj):
        """
        Make a serializable copy of an object.
        Members which are difficult/impossible to serialize are stripped.
        """
        if self._serializable(obj):
            return obj  # already serializable

        copy = SerializableClassCopy()

        """
        Dictionaries can hold complex values, so we split keys and values into
        separate lists and serialize them individually.
        """
        if (type(obj) is dict):
            copy.type = type(obj)
            copy.k_list = list()
            copy.v_list = list()
            for k, v in obj.items():
                copy.k_list.append(self._make_serializable(k))
                copy.v_list.append(self._make_serializable(v))
            return copy

        # copy at least serializable attributes and properties
        for name, member in inspect.getmembers(obj):
            # skip private members and non-writable dunder methods.
            if name[0] == '_':
                if name in ['__weakref__']:
                    continue
                if name in ['__dict__']:
                    continue
                if not (name.startswith('__') and name.endswith('__')):
                    continue
            if callable(member) and not isinstance(member, property):
                continue
            if not self._serializable(member):
                member = self._make_serializable(member)
            setattr(copy, name, member)
        return copy

    def _make_serializable(self, obj):
        """
        Make a serializable copy of an object or a list/tuple of objects.
        Members which are difficult/impossible to serialize are stripped.
        """
        if (type(obj) is list) or (type(obj) is tuple):
            rv = []
            for item in obj:
                rv.append(self._make_serializable(item))
            if type(obj) is tuple:
                rv = tuple(rv)
            return rv
        elif (isinstance(obj, IntEnum) or isinstance(obj, IntFlag)):
            return obj.value
        else:
            return self._make_obj_serializable(obj)

    def _deserialize_obj(self, obj):
        if (hasattr(obj, 'type')):
            if obj.type is dict:
                _obj = dict()
                for k, v in zip(obj.k_list, obj.v_list):
                    _obj[self._deserialize(k)] = self._deserialize(v)
            return _obj
        return obj

    def _deserialize(self, obj):
        if (type(obj) is list) or (type(obj) is tuple):
            rv = []
            for item in obj:
                rv.append(self._deserialize(item))
            if type(obj) is tuple:
                rv = tuple(rv)
            return rv
        else:
            return self._deserialize_obj(obj)

    def start_remote(self):
        """ Start remote execution """
        self.start()

    def quit_remote(self):
        """ Quit remote execution """
        self._remote_exec(RemoteClass.QUIT, None)

    def get_remote_value(self):
        """ Get value of a remotely held object """
        return RemoteClassAttr(self, None).get_remote_value()

    def set_request_timeout(self, timeout):
        """ Change request timeout """
        self._timeout = timeout

    def run(self):
        """
        Create instance of the wrapped class and execute operations
        on it as requested by the parent process.
        """
        self._instance = self._cls(*self._args, **self._kwargs)
        while True:
            try:
                rv = None
                # get request from the parent process
                (op, path, args,
                 kwargs) = self._pipe[RemoteClass.PIPE_CHILD].recv()
                args = self._deserialize(args)
                kwargs = self._deserialize(kwargs)
                path = path.split('.') if path else []
                if op == RemoteClass.GET:
                    rv = self._get_local_value(path)
                elif op == RemoteClass.CALL:
                    rv = self._call_local_method(path, *args, **kwargs)
                elif op == RemoteClass.SETATTR and 'value' in kwargs:
                    self._set_local_attr(path, kwargs['value'])
                elif op == RemoteClass.REPR:
                    rv = self._get_local_repr(path)
                elif op == RemoteClass.STR:
                    rv = self._get_local_str(path)
                elif op == RemoteClass.QUIT:
                    break
                else:
                    continue
                # send return value
                if not self._serializable(rv):
                    rv = self._make_serializable(rv)
                self._pipe[RemoteClass.PIPE_CHILD].send(rv)
            except EOFError:
                break
        self._instance = None  # destroy the instance


@unittest.skip("Remote Vpp Test Case Class")
class RemoteVppTestCase(VppTestCase):
    """ Re-use VppTestCase to create remote VPP segment

        In your test case:

        @classmethod
        def setUpClass(cls):
            # fork new process before client connects to VPP
            cls.remote_test = RemoteClass(RemoteVppTestCase)

            # start remote process
            cls.remote_test.start_remote()

            # set up your test case
            super(MyTestCase, cls).setUpClass()

            # set up remote test
            cls.remote_test.setUpClass(cls.tempdir)

        @classmethod
        def tearDownClass(cls):
            # tear down remote test
            cls.remote_test.tearDownClass()

            # stop remote process
            cls.remote_test.quit_remote()

            # tear down your test case
            super(MyTestCase, cls).tearDownClass()
    """

    def __init__(self):
        super(RemoteVppTestCase, self).__init__("emptyTest")

    # Note: __del__ is a 'Finalizer" not a 'Destructor'.
    # https://docs.python.org/3/reference/datamodel.html#object.__del__
    def __del__(self):
        if hasattr(self, "vpp"):
            self.vpp.poll()
            if self.vpp.returncode is None:
                self.vpp.terminate()
                self.vpp.communicate()

    @classmethod
    def setUpClass(cls, tempdir):
        # disable features unsupported in remote VPP
        orig_env = dict(os.environ)
        if 'STEP' in os.environ:
            del os.environ['STEP']
        if 'DEBUG' in os.environ:
            del os.environ['DEBUG']
        cls.tempdir_prefix = os.path.basename(tempdir) + "/"
        super(RemoteVppTestCase, cls).setUpClass()
        os.environ = orig_env

    @classmethod
    def tearDownClass(cls):
        super(RemoteVppTestCase, cls).tearDownClass()

    @unittest.skip("Empty test")
    def emptyTest(self):
        """ Do nothing """
        pass

    def setTestFunctionInfo(self, name, doc):
        """
        Store the name and documentation string of currently executed test
        in the main VPP for logging purposes.
        """
        self._testMethodName = name
        self._testMethodDoc = doc
