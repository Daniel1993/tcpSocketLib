INCLUDES := -I ./include -I ./src
#
DEFINES  :=
#
LIBS     := -lpthread -lm
#
CC       := gcc -std=c2x -Wall
CXX      := g++ -std=c++2a -Wall
AR       := ar rcs

### Add this if debug needed (GPU run much slower)
DEBUG_FLAGS  := -g

# this is needed for the barrier implementation
ifeq ($(DEBUG),1)
DEFINES += $(DEBUG_FLAGS)
endif

ifeq ($(USE_CSTD),1)
DEFINES += -DUSE_CSTD
endif

CFLAGS     := -c $(DEFINES) $(INCLUDES)
CXXFLAGS   := -c $(DEFINES) $(INCLUDES)
LDFLAGS    := $(LIBS)

LIB        := threading

OBJS       := \
	src/prod-cons.o \
	src/threading.o \
#

TEST       := \
	tests/main.o \
#

.PHONY:	all clean

all: lib$(LIB).a main
	# Done

# IMPORTANT: the order of the libraries matters
main: lib$(LIB).a tests/main.o $(OBJS)
	$(CXX) -o main tests/main.o -L . -l$(LIB) $(LIBS)

lib$(LIB).a: $(OBJS)
	@echo "Linking..."
	$(AR) $@ $(OBJS)

%.o:	%.c
	$(CC) $(CFLAGS) -o $@ $<

%.o:	%.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

run:
	make all

clean:
	rm -f lib$(LIB).a $(OBJS) $(TEST) main
