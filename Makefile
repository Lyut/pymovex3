PYTHON_CFLAGS=`python3-config --cflags`

all: _pymovex.so

clean:
	rm _pymovex.so

_pymovex.so: _pymovex.c
	gcc -g -shared -fPIC $(PYTHON_CFLAGS) -o _pymovex.so _pymovex.c -lMvxSock
