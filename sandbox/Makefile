CC=g++
CFLAGS=-fPIC -shared -ldl -Wall -Wextra -O2 -std=c++17
all: libsandbox.so
libsandbox.so: sandbox.cpp
	$(CC) $(CFLAGS) -o libsandbox.so sandbox.cpp
