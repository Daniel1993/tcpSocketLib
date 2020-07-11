OBJS     := \
	src/tcpSocketLib.o \
	src/sslUtility.o \
	src/tcpServer.o \
#

LIBS     := \
	-L ./deps/threading -l threading -L /usr/local/opt/openssl/lib \
	-L ./deps/input_handler -l ssl -l crypto -l input_handler \
	-pthread 
INCS     := -I ./include -I ./deps/threading/include -I ./deps/input_handler/include
DEFS     := -Wall -Wcpp

CC       := gcc
CXX      := g++ -std=c++14
AR       := ar rcs

DEBUG    ?= 0

ifeq ($(DEBUG),1)
DEFS     += -g
endif

LIB      := tcpSocket

CFLAGS   := -c $(DEFS) $(INCS)
CXXFLAGS := -c $(DEFS) $(INCS)

LDFLAGS  := -L . -l $(LIB) $(LIBS)

all: deps lib$(LIB).a test/test test/test_ssl
	cd ./deps/threading     && $(MAKE) 
	cd ./deps/input_handler && $(MAKE) 
	# DONE

deps: threading input_handler

threading:
	cd ./deps/threading && $(MAKE)

input_handler:
	cd ./deps/input_handler && $(MAKE)

lib$(LIB).a: $(OBJS)
	@echo "Linking..."
	$(AR) $@ $(OBJS)

test/test: test/test.o
	$(CXX) $^ $(LDFLAGS) -o $@

test/test_ssl: test/test_ssl.o
	$(CXX) $^ $(LDFLAGS) -o $@

%.o:	%.c
	@echo "--- $<"
	$(CC) $(CFLAGS) -o $@ $<

%.o:	%.cpp
	@echo "--- $<"
	$(CXX) $(CXXFLAGS) -o $@ $<

clean: clean_deps
	rm -f $(OBJS) $(TEST_OBJS) lib$(LIB).a test/test test/test_ssl test/*.o

clean_deps:
	cd ./deps/threading && $(MAKE) clean
	cd ./deps/input_handler && $(MAKE) clean
