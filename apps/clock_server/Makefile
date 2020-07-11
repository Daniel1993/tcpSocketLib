INCLUDES := -I ../include -I ../deps/threading/include -I ../deps/input_handler/include
#
DEFINES  :=
# NOTE: tcpSocket must come first! order matters!
LIBS     := -L .. -l tcpSocket -L ../deps/threading -l threading -L /usr/local/opt/openssl/lib \
	-L ../deps/input_handler -l input_handler -l ssl -l crypto -lpthread -lm 

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
	clockServer.o       \
#

.PHONY:	all clean

all: keyManager clockServer
	# Done

# IMPORTANT: the order of the libraries matters
keyManager: $(OBJS)
	$(CXX) -o $@ $@.o $(LDFLAGS)

clockServer: $(OBJS)
	$(CXX) -o $@ $@.o $(LDFLAGS)

setup_keys: keyManager
	$(MAKE) -C ../key_manager

### TODO: send only the public keys
rsync_keys: setup_keys
	rsync -avz $(PWD)/. $(NODE0_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE1_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE2_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE3_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE4_ADDR):$(PWD)

start_node0: clockServer
	./clockServer ID=node0 PORT=16120 MASTER_CERT=./master_key_publ/cert_publ_key.pem KEY=./node0_key_priv/priv_key.pem \
		node1=$(NODE1_ADDR),16121,./node1_key_publ/publ_key.pem \
		node2=$(NODE2_ADDR),16122,./node2_key_publ/publ_key.pem \
		node3=$(NODE3_ADDR),16123,./node3_key_publ/publ_key.pem \
		node4=$(NODE4_ADDR),16124,./node4_key_publ/publ_key.pem \
		node5=$(NODE5_ADDR),16125,./node5_key_publ/publ_key.pem

start_node1: clockServer
	./clockServer ID=node1 PORT=16121 MASTER_CERT=./master_key_publ/cert_publ_key.pem KEY=./node1_key_priv/priv_key.pem \
		node0=$(NODE0_ADDR),16120,./node0_key_publ/publ_key.pem \
		node2=$(NODE2_ADDR),16122,./node2_key_publ/publ_key.pem \
		node3=$(NODE3_ADDR),16123,./node3_key_publ/publ_key.pem \
		node4=$(NODE4_ADDR),16124,./node4_key_publ/publ_key.pem \
		node5=$(NODE5_ADDR),16125,./node5_key_publ/publ_key.pem

start_node2: clockServer
	./clockServer ID=node2 PORT=16122 MASTER_CERT=./master_key_publ/cert_publ_key.pem KEY=./node2_key_priv/priv_key.pem \
		node0=$(NODE0_ADDR),16120,./node0_key_publ/publ_key.pem \
		node1=$(NODE1_ADDR),16121,./node1_key_publ/publ_key.pem \
		node3=$(NODE3_ADDR),16123,./node3_key_publ/publ_key.pem \
		node4=$(NODE4_ADDR),16124,./node4_key_publ/publ_key.pem \
		node5=$(NODE5_ADDR),16125,./node5_key_publ/publ_key.pem

start_node3: clockServer
	./clockServer ID=node3 PORT=16123 MASTER_CERT=./master_key_publ/cert_publ_key.pem KEY=./node3_key_priv/priv_key.pem \
		node0=$(NODE0_ADDR),16120,./node0_key_publ/publ_key.pem \
		node1=$(NODE1_ADDR),16121,./node1_key_publ/publ_key.pem \
		node2=$(NODE2_ADDR),16122,./node2_key_publ/publ_key.pem \
		node4=$(NODE4_ADDR),16124,./node4_key_publ/publ_key.pem \
		node5=$(NODE5_ADDR),16125,./node5_key_publ/publ_key.pem

start_node4: clockServer
	./clockServer ID=node4 PORT=16124 MASTER_CERT=./master_key_publ/cert_publ_key.pem KEY=./node4_key_priv/priv_key.pem \
		node0=$(NODE0_ADDR),16120,./node0_key_publ/publ_key.pem \
		node1=$(NODE1_ADDR),16121,./node1_key_publ/publ_key.pem \
		node2=$(NODE2_ADDR),16122,./node2_key_publ/publ_key.pem \
		node3=$(NODE3_ADDR),16123,./node3_key_publ/publ_key.pem \
		node5=$(NODE5_ADDR),16125,./node5_key_publ/publ_key.pem

start_node5: clockServer
	./clockServer ID=node5 PORT=16125 MASTER_CERT=./master_key_publ/cert_publ_key.pem KEY=./node5_key_priv/priv_key.pem \
		node0=$(NODE0_ADDR),16120,./node0_key_publ/publ_key.pem \
		node1=$(NODE1_ADDR),16121,./node1_key_publ/publ_key.pem \
		node2=$(NODE2_ADDR),16122,./node2_key_publ/publ_key.pem \
		node3=$(NODE3_ADDR),16123,./node3_key_publ/publ_key.pem \
		node4=$(NODE4_ADDR),16124,./node4_key_publ/publ_key.pem

%.o:	%.c
	$(CC) $(CFLAGS) -o $@ $<

%.o:	%.cpp
	$(CXX) $(CXXFLAGS) -o $@ $<

run:
	make all

clean:
	rm -fr *.o clockServer *_key_priv *_key_publ 
