/**
 * This is an example program that show how to use the Movex API Client Interface in
 * the Linux environment.
 * 
 * When you compile/create your own programs and modules use the following commands:
 *
 *  gcc -o TestSock TestSock.c -L. -lMvxSock
 *
 * Note: 
 *
 */
#include <Python.h>
#include <structmember.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <locale.h>

#include "MvxSock.h"

#define LOBYTE(w)           ((unsigned char)(w))
#define HIBYTE(w)           ((unsigned char)(((unsigned short)(w) >> 8) & 0xFF))


static SERVER_ID comStruct;
static unsigned long result;
static unsigned long len;
static PyObject *PyMovexError;
static char errstr[1024];
static PyObject *OrderedDict;
static int DEBUG = 0;

PyObject *reportError(char *method, unsigned long result) {
    PyObject *unicodeError;

    snprintf(errstr, sizeof(errstr), "%s returned error %lu: %s", method, result, comStruct.Buff);
    unicodeError = PyUnicode_FromString(errstr);
    PyErr_SetObject(PyMovexError, unicodeError);
    return NULL;
}

static PyObject *
pymovex_connect(PyObject *self, PyObject *args, PyObject *kwargs) {
    char *host;
    int port;
    char *user;
    char *passwd;
    char *conoDivi = "";
    char *program;
    static char *kwlist[] = {"program", "host", "port", "user", "passwd"};

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "ssiss", kwlist, &program, &host, &port, &user, &passwd))
        return NULL;

    /*
     * If FPW is running remote or locally does not matter if you use
     * the host name by which it is known in your network.
     * If only locally on this server you can as well use 127.0.0.1.
     * It might as well be on another AS/400 in which case we write that IP-address
     * or its host name.
     * We name this test-program "MvxSock C-test"
     * We do NOT want encryption (0) so the last argument (CryptKey) is ignored.
     */
    memset(&comStruct, '\0', sizeof(SERVER_ID));

    if (DEBUG)
        fprintf(stderr, "Connecting with program %s, host %s, port %d, user %s\n", program, host, port, user);

    if ((result = MvxSockSetup(&comStruct, host, port, "MvxSock C-test", 0, "NotUsed")))
        return reportError("MvxSockSetup", result);

    if ((result = MvxSockInit(&comStruct, conoDivi, user, passwd, program)))
        return reportError("MvxSockInit", result);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pymovex_query(PyObject *self, PyObject *args) {
    char recvBuff[1000];
    char *sendBuff;
    int count;

    if (!PyArg_ParseTuple(args, "s", &sendBuff))
        return NULL;

    if (DEBUG)
        fprintf(stderr, "Query: |%s|\n", sendBuff);

    len = sizeof(recvBuff);
    count = 0;

    if ((result = MvxSockTrans(&comStruct, sendBuff, recvBuff, &len)))
        return reportError("MvxSockTrans", result);

    if (DEBUG) {
        fprintf(stderr, "Sent %zu bytes: %s\n", strlen(sendBuff), sendBuff);
        fprintf(stderr, "Got %zu bytes: %s\n", strlen(recvBuff), recvBuff);
    }

    while (strncmp(recvBuff, "REP  ", 5) == 0) {
        count++;
        len = 1000;
        if ((result = MvxSockReceive(&comStruct, recvBuff, &len)))
            return reportError("MvxSockReceive", result);

        if (DEBUG)
            fprintf(stderr, "Got %zu bytes: %s\n", strlen(recvBuff), recvBuff);
    }

    if (DEBUG)
        fprintf(stderr, "Got %d REP-lines.\n", count);

    Py_INCREF(Py_None);
    return Py_None;
}

typedef struct {
    PyObject_HEAD
    char *cmd;
    PyObject *outputFields;
    int firstResult;
} pymovex_fquery_MyIter;

PyObject *pymovex_fquery_MyIter_iter(PyObject *self) {
    Py_INCREF(self);
    return self;
}


PyObject *pymovex_next_result(PyObject *outputFields) {
    PyObject *d = PyObject_CallFunctionObjArgs(OrderedDict, NULL);
    Py_ssize_t pos;
    PyObject *key;
    char *c_key;
    char *value;

    for (pos = 0; pos < PyTuple_GET_SIZE(outputFields); pos++) {
        key = PyTuple_GetItem(outputFields, pos);
        PyObject *utf8_key = PyUnicode_AsUTF8String(key);
        c_key = PyBytes_AsString(utf8_key);
        value = MvxSockGetField(&comStruct, c_key);

        if (!value) {
            snprintf(errstr, sizeof(errstr), "No such field: %s", c_key);
            PyErr_SetString(PyMovexError, errstr);
            Py_XDECREF(utf8_key);  // Release the temporary utf8_key object
            return NULL;
        }

        PyObject *pyvalue = PyUnicode_Decode(value, strlen(value), "iso-8859-1", "replace");
        Py_INCREF(pyvalue);
        PyObject_SetItem(d, key, pyvalue);

        Py_XDECREF(utf8_key);  // Release the temporary utf8_key object
    }

    Py_INCREF(d);
    return d;
}

PyObject *pymovex_fquery_MyIter_iternext(PyObject *self) {
    char *cmd;
    pymovex_fquery_MyIter *p = (pymovex_fquery_MyIter *) self;

    if (p->firstResult)
        cmd = p->cmd;
    else
        cmd = NULL;

    if ((result = MvxSockAccess(&comStruct, cmd)))
        return reportError("MvxSockAccess", result);

    p->firstResult = 0;

    if (!MvxSockMore(&comStruct)) {
        /* Raising of standard StopIteration exception with empty value. */
        PyErr_SetNone(PyExc_StopIteration);
        if (DEBUG)
            fprintf(stderr, "No more results\n");
        return NULL;
    }

    return pymovex_next_result(p->outputFields);
}

static PyTypeObject pymovex_fquery_MyIterType = {
        PyVarObject_HEAD_INIT(NULL, 0)
        "_pymovex._fquery_MyIter",              /* tp_name */
        sizeof(pymovex_fquery_MyIter),          /* tp_basicsize */
        0,                                      /* tp_itemsize */
        0,                                      /* tp_dealloc */
        0,                                      /* tp_vectorcall_offset */
        0,                                      /* tp_getattr */
        0,                                      /* tp_setattr */
        0,                                      /* tp_reserved */
        0,                                      /* tp_repr */
        0,                                      /* tp_as_number */
        0,                                      /* tp_as_sequence */
        0,                                      /* tp_as_mapping */
        0,                                      /* tp_hash */
        0,                                      /* tp_call */
        0,                                      /* tp_str */
        0,                                      /* tp_getattro */
        0,                                      /* tp_setattro */
        0,                                      /* tp_as_buffer */
        Py_TPFLAGS_DEFAULT,                     /* tp_flags */
        "Internal myiter iterator object.",     /* tp_doc */
        0,                                      /* tp_traverse */
        0,                                      /* tp_clear */
        0,                                      /* tp_richcompare */
        0,                                      /* tp_weaklistoffset */
        pymovex_fquery_MyIter_iter,             /* tp_iter: __iter__() method */
        pymovex_fquery_MyIter_iternext,         /* tp_iternext: __next__() method */
};

int pymovex_set_fields(PyObject *fieldMap) {
    PyObject *key, *value, *string_value, *string_key;
    Py_ssize_t pos = 0;
    while (PyDict_Next(fieldMap, &pos, &key, &value)) {
        const char *skey;
        const char *svalue;

        // Make sure key is a string
        if (!PyUnicode_Check(key)) {
            string_key = PyObject_Str(key);
            if (string_key == NULL) {
                snprintf(errstr, sizeof(errstr), "Invalid parameter");
                PyErr_SetString(PyMovexError, errstr);
                return 0;
            }
            skey = PyUnicode_AsUTF8(string_key);
            snprintf(errstr, sizeof(errstr), "Bad parameter name: %s", skey);
            PyErr_SetString(PyMovexError, errstr);
            return 0;
        }

        skey = PyUnicode_AsUTF8(key);

        // Note: value could be an integer, so we have to call str(value) first
        if (!PyUnicode_Check(value)) {
            string_value = PyObject_Str(value);
            if (string_value == NULL) {
                snprintf(errstr, sizeof(errstr), "Cannot convert parameter %s to string", skey);
                PyErr_SetString(PyMovexError, errstr);
                return 0;
            }
        } else {
            string_value = value;
        }

        svalue = PyUnicode_AsUTF8(string_value);
        MvxSockSetField(&comStruct, (char *) skey, (char *) svalue);
        if (DEBUG)
            fprintf(stderr, "    Field: (%s, %s)\n", skey, svalue);
    }

    return 1;
}

static PyObject *pymovex_fquery(PyObject *self, PyObject *args) {
    PyObject *fieldMap;
    PyObject *outputFields;
    char *cmd;
    pymovex_fquery_MyIter *p;

    if (!PyArg_ParseTuple(args, "sOO", &cmd, &fieldMap, &outputFields)) {
        fprintf(stderr, "PyArg_ParseTuple in errore!\n");
        return NULL;
    }
    if (DEBUG)
        fprintf(stderr, "Command: %s\n", cmd);

    if (!pymovex_set_fields(fieldMap)) {
        fprintf(stderr, "Pymovex_set_fields in errore!\n");
        return NULL;
    }

    p = PyObject_New(pymovex_fquery_MyIter, &pymovex_fquery_MyIterType);

    if (!p) {
        fprintf(stderr, "PyObject_new in errore!\n");
        return NULL;
    }

    p->firstResult = 1;
    p->cmd = cmd;
    p->outputFields = outputFields;
    Py_INCREF(p);
    return (PyObject *) p;
}

static PyObject *pymovex_fquery_single(PyObject *self, PyObject *args) {
    PyObject *fieldMap;
    PyObject *outputFields;
    char *cmd;


    if (!PyArg_ParseTuple(args, "sOO", &cmd, &fieldMap, &outputFields))
        return NULL;

    if (DEBUG)
        fprintf(stderr, "Command: %s\n", cmd);

    if (!pymovex_set_fields(fieldMap))
        return NULL;

    if ((result = MvxSockAccess(&comStruct, cmd)))
        return reportError("MvxSockAccess", result);

    return pymovex_next_result(outputFields);
}

static PyObject *pymovex_close(PyObject *self, PyObject *args) {
    if ((result = MvxSockClose(&comStruct)))
        return reportError("MvxSockClose", result);

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject *pymovex_debug(PyObject *self, PyObject *args) {
    if (!PyArg_ParseTuple(args, "i", &DEBUG))
        return NULL;

    Py_INCREF(Py_None);
    return Py_None;
}

static PyMethodDef PyMovexMethods[] = {
        {"connect",       (PyCFunction) pymovex_connect, METH_VARARGS | METH_KEYWORDS, "Connect"},
        {"close",         pymovex_close,                 METH_VARARGS,                 "Close"},
        {"query",         pymovex_query,                 METH_VARARGS,                 "Query"},
        {"fquery",        pymovex_fquery,                METH_VARARGS,                 "Field-based query"},
        {"fquery_single", pymovex_fquery_single,         METH_VARARGS,                 "Field-based query with only one expected result"},
        {"debug",         pymovex_debug,                 METH_VARARGS,                 "Set debug option"},
        {NULL,            NULL,                          0,                            NULL}        /* Sentinel */
};

static struct PyModuleDef cModPyMovex =
        {
                PyModuleDef_HEAD_INIT,
                "_pymovex",    /* name of module */
                "",            /* module documentation, may be NULL */
                -1,            /* size of per-interpreter state of the module, or -1 if the module keeps state in global variables. */
                PyMovexMethods /* definition of methods exported by the library */
        };

PyMODINIT_FUNC PyInit__pymovex(void) {
    PyObject *m;

    m = PyModule_Create(&cModPyMovex);
    if (m == NULL)
        return NULL;  // Return NULL on failure

    // Create a new _pymovex.Error exception type
    PyMovexError = PyErr_NewException("_pymovex.Error", NULL, NULL);
    if (PyMovexError == NULL) {
        fprintf(stderr, "PyMovexError == NULL!\n");
        Py_DECREF(m);  // Release the created module
        return NULL;   // Return NULL on failure
    }

    // Add the Error object to the module
    if (PyModule_AddObject(m, "Error", PyMovexError) < 0) {
        fprintf(stderr, "PyModule_AddObject < 0!\n");
        Py_DECREF(PyMovexError);  // Release the created exception object
        Py_DECREF(m);             // Release the created module
        return NULL;              // Return NULL on failure
    }

    PyObject *collectionsMod = PyImport_ImportModule("collections");
    if (collectionsMod == NULL) {
        fprintf(stderr, "Error importing collections module\n");
        PyErr_Print();  // Print additional details about the exception
        return NULL;
    }

    OrderedDict = PyObject_GetAttrString(collectionsMod, "OrderedDict");
    if (OrderedDict == NULL) {
        fprintf(stderr, "Error getting OrderedDict attribute\n");
        PyErr_Print();  // Print additional details about the exception
        Py_DECREF(collectionsMod);  // Release the imported module
        return NULL;
    }

    return m;  // Return the created module
}
