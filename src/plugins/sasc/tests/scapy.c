#include <Python.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

// Function to build a packet and return binary representation
unsigned char *
scapy_build_packet(const char *packet_definition, size_t *packet_len) {
    unsigned char *packet_bytes = NULL;
    *packet_len = 0;

    // Prepare Python code to build and serialize the packet
    const char *python_code_template = "packet = %s\n"
                                       "raw_bytes = bytes(packet)\n";

    // Allocate memory for Python code string
    size_t code_len = strlen(python_code_template) + strlen(packet_definition) + 1;
    char *python_code = (char *)malloc(code_len);
    if (!python_code) {
        fprintf(stderr, "Memory allocation failed\n");
        return NULL;
    }

    snprintf(python_code, code_len, python_code_template, packet_definition);

    // Execute Python code
    PyRun_SimpleString(python_code);
    free(python_code);

    // Get the raw_bytes variable from the Python interpreter
    PyObject *main_module = PyImport_AddModule("__main__");
    PyObject *global_dict = PyModule_GetDict(main_module);
    PyObject *raw_bytes = PyDict_GetItemString(global_dict, "raw_bytes");

    if (raw_bytes && PyBytes_Check(raw_bytes)) {
        // Get size and data
        *packet_len = PyBytes_Size(raw_bytes);
        packet_bytes = (unsigned char *)malloc(*packet_len);
        if (!packet_bytes) {
            fprintf(stderr, "Memory allocation failed for packet bytes\n");
            return NULL;
        }
        memcpy(packet_bytes, PyBytes_AsString(raw_bytes), *packet_len);
    } else {
        fprintf(stderr, "Failed to build the packet or retrieve raw bytes\n");
    }

    return packet_bytes;
}

void
scapy_performance_test(void) {
    // Measure time to build 1000 packets
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);

    const char *test_packet = "IP(dst='8.8.8.8')/ICMP()";
    size_t packet_len;

    for (int i = 0; i < 1000; i++) {
        unsigned char *packet = scapy_build_packet(test_packet, &packet_len);
        if (packet) {
            free(packet);
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);

    double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;

    fprintf(stderr, "Time taken to build 1000 packets: %.3f seconds\n", time_taken);
    fprintf(stderr, "Average time per packet: %.3f ms\n", (time_taken) / 1000);
}

int
scapy_start(void) {
    // Initialize the Python virtual environment
    Py_Initialize();
    // Get the virtual environment path from the environment variable
    const char *pythonpath = getenv("PYTHONPATH");
    fprintf(stderr, "PYTHONPATH: %s\n", pythonpath);

    // Print out the uid
    fprintf(stderr, "UID: %d\n", getuid());

    void *python = dlopen("/usr/lib/aarch64-linux-gnu/libpython3.12.so", RTLD_NOW | RTLD_GLOBAL);
    if (!python) {
        fprintf(stderr, "Failed to load Python library\n");
        return -1;
    }
    int result = PyRun_SimpleString("from scapy.layers.inet import IP, ICMP, TCP, UDP\n"
                                    "from scapy.layers.l2 import Ether\n"
                                    "from scapy.packet import Packet, Raw\n");
    if (result != 0) {
        fprintf(stderr, "Failed to import Scapy\n");
    }
    return result;
}

void
scapy_stop(void) {
    Py_Finalize();
}

#if 0
int main() {
    // Initialize the Python interpreter
    Py_Initialize();

    // First packet
    const char* packet1 = "IP(dst='8.8.8.8')/ICMP()";
    size_t len1;
    unsigned char* pkt1 = build_packet(packet1, &len1);
    if (pkt1) {
        printf("Packet 1 built successfully. Length: %zu bytes\n", len1);
        free(pkt1);
    }

    // Second packet
    const char* packet2 = "Ether()/IP(dst='192.168.1.1')/TCP()";
    size_t len2;
    unsigned char* pkt2 = build_packet(packet2, &len2);
    if (pkt2) {
        printf("Packet 2 built successfully. Length: %zu bytes\n", len2);
        free(pkt2);
    }

    // Finalize the Python interpreter
    Py_Finalize();

    return 0;
}
#endif