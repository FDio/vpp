from __future__ import print_function
import os
import multiprocessing
import sys
import select
from time import sleep


# class Redirect(multiprocessing.Connection):
#     def write(self, obj):
#         self.send(obj)


def tester_method(w):
    os.dup2(w, sys.stdout.fileno())
    os.dup2(w, sys.stderr.fileno())

    for _ in range(3):
        print('This is a message!')

    sys.stderr.write('This is an error')

if __name__ == '__main__':
    r, w = os.pipe()

    print(r, w)
    reader = os.fdopen(r, 'r')

    process = multiprocessing.Process(None, tester_method, 'TESTER', (w,))
    process.start()

    # process.join()
    # while True:
    #     print('From pipe: %s' % reader.readline())

    #sleep(1)
    os.close(w)

    while process.is_alive():
        c = os.read(r, 1)
        sys.stdout.write(c)
    print('After dead')

    sys.stderr.write('Error outside')
    # print(os.read(r, 20))
    for line in reader:
        sys.stdout.write(line)

    # readable = select.select([r], [], [], 1)[0]
    # print(readable)
    #
    # while r.poll():
    #     sys.stdout.write(r.recv())

    reader.close()
