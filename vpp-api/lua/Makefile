all: libcough.so

libcough.so: cough.c
	gcc -o libcough.so -shared -fPIC cough.c
clean:
	rm -f libcough.so
