INCLUDES := -I ../../include -I ../../deps/threading/include -I ../../deps/input_handler/include
#
DEFINES  :=
# NOTE: TCP_SSL_helper must come first! order matters!
LIBS     := -L ../.. -l TCP_SSL_helper -L ../../deps/threading -l threading -L /usr/local/opt/openssl/lib \
	-L ../../deps/input_handler -l input_handler -l ssl -l crypto -lpthread -lm 

#
CC       := gcc -std=c11 -Wall
CXX      := g++ -std=c++17 -Wall
AR       := ar rcs

NODE0_ADDR ?= localhost
NODE1_ADDR ?= localhost
NODE2_ADDR ?= localhost
NODE3_ADDR ?= localhost
NODE4_ADDR ?= localhost
NODE5_ADDR ?= localhost

### Add this if debug needed (GPU run much slower)
DEBUG_FLAGS  := -g

# this is needed for the barrier implementation
ifeq ($(DEBUG),1)
DEFINES  += $(DEBUG_FLAGS)
endif

ifeq ($(PRODUTION),1)
DEFINES  += -DNDEBUG -O3
endif

CFLAGS     := -c $(DEFINES) $(INCLUDES)
CXXFLAGS   := -c $(DEFINES) $(INCLUDES)
LDFLAGS    := $(LIBS)

LIB        := threading

OBJS       :=       \
	keyManager.o      \
#

.PHONY:	all clean

all: keyManager
	# Done

# IMPORTANT: the order of the libraries matters
keyManager: $(OBJS)
	$(CXX) -o $@ $@.o $(LDFLAGS)

setup_keys: keyManager
	mkdir -p master_key_publ master_key_priv \
		node0_key_publ node0_key_priv \
		node1_key_publ node1_key_priv \
		node2_key_publ node2_key_priv \
		node3_key_publ node3_key_priv \
		node4_key_publ node4_key_priv \
		node5_key_publ node5_key_priv
	./keyManager OPERATION=CREATE_MASTER_KEY NAME=master
	./keyManager OPERATION=CREATE_KEY NAME=node0
	./keyManager OPERATION=CREATE_KEY NAME=node1
	./keyManager OPERATION=CREATE_KEY NAME=node2
	./keyManager OPERATION=CREATE_KEY NAME=node3
	./keyManager OPERATION=CREATE_KEY NAME=node4
	./keyManager OPERATION=CREATE_KEY NAME=node5

### TODO: send only the public keys
rsync_keys: setup_keys
	rsync -avz $(PWD)/. $(NODE0_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE1_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE2_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE3_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE4_ADDR):$(PWD)

%.o:	%.c
	$(CC) $(CFLAGS) -o $@ $<

%.o:	%.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

run:
	make all

clean:
	rm -fr *.o keyManager *_key_priv *_key_publ 
