CPP?=/usr/bin/g++
LIBS?=-luring
PEMPRE?=$(PWD)
CPPFLAGS?=-std=gnu++2c -Wall -Wextra -Wpedantic -Wno-unused-parameter -Wno-unused-variable -Wno-unused-function -Wno-missing-field-initializers -fconcepts-diagnostics-depth=2 -ggdb -DAIO_PEM_PREFIX=\"$(PEMPRE)\" -Iwolfssl/src
SRC:=$(wildcard */*.cpp)
HDR:=$(wildcard */*.h)
OBJ:=$(patsubst %.cpp,%.o,$(SRC))

.PHONY: all
all: server $(PEMPRE)/pkey.pem $(PEMPRE)/cert.pem

$(PEMPRE)/pkey%pem $(PEMPRE)/cert%pem: scripts/gencert.sh
	./scripts/gencert.sh "$(PEMPRE)"

%.o: %.cpp $(HDR)
	$(CPP) $(CPPFLAGS) -c $< -o $@
server: $(OBJ) libwolfssl.a
	$(CPP) $(CPPFLAGS) $^ $(LIBS) libwolfssl.a -o $@

libwolfssl.a: wolfssl/Makefile
	cd wolfssl && make src/libwolfssl.la && cp src/.libs/libwolfssl.a ..
wolfssl/Makefile: wolfssl/autogen.sh
	cd wolfssl && ./autogen.sh && CPP= ./configure --prefix=$(PWD) --disable-crypttests --enable-atomicuser --enable-static --disable-shared --disable-tlsv12
wolfssl/autogen.sh:
	git submodule update --init --recursive

.PHONY: clean
clean:
	rm -f $(OBJ) server $(PEMPRE)/pkey.pem $(PEMPRE)/cert.pem libwolfssl.a wolfssl/Makefile
