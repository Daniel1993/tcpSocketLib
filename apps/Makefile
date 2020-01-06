INCLUDES := -I ../include -I ../deps/threading/include -I ../deps/input_handler/include
#
DEFINES  :=
# NOTE: tcpSocket must come first! order matters!
LIBS     := -L .. -l tcpSocket -L ../deps/threading -l threading \
	-L ../deps/input_handler -l input_handler -l crypto -l ssl -lpthread -lm 
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
DEFINES += $(DEBUG_FLAGS)
endif

ifeq ($(PRODUTION),1)
DEFINES += -DNDEBUG -O3
endif

CFLAGS     := -c $(DEFINES) $(INCLUDES)
CXXFLAGS   := -c $(DEFINES) $(INCLUDES)
LDFLAGS    := $(LIBS)

LIB        := threading

OBJS       := \
	keyManager.o \
	heartbeat.o \
#

.PHONY:	all clean

all: keyManager heartbeat
	# Done

# IMPORTANT: the order of the libraries matters
keyManager: $(OBJS)
	$(CXX) -o $@ $@.o $(LDFLAGS)

heartbeat: $(OBJS)
	$(CXX) -o $@ $@.o $(LDFLAGS)

setup_keys: keyManager
	mkdir -p master_key_publ master_key_priv \
		node0_key_publ node0_key_priv \
		node1_key_publ node1_key_priv \
		node2_key_publ node2_key_priv \
		node3_key_publ node3_key_priv \
		node4_key_publ node4_key_priv \
		node5_key_publ node5_key_priv
	./keyManager OPERATION=CREATE_MASTER_KEY DIR_PUBL=./master_key_publ DIR_PRIV=./master_key_priv
	./keyManager OPERATION=CREATE_KEY MASTER_KEY=./master_key_priv/priv_key.pem DIR_PUBL=./node0_key_publ DIR_PRIV=./node0_key_priv
	./keyManager OPERATION=CREATE_KEY MASTER_KEY=./master_key_priv/priv_key.pem DIR_PUBL=./node1_key_publ DIR_PRIV=./node1_key_priv
	./keyManager OPERATION=CREATE_KEY MASTER_KEY=./master_key_priv/priv_key.pem DIR_PUBL=./node2_key_publ DIR_PRIV=./node2_key_priv
	./keyManager OPERATION=CREATE_KEY MASTER_KEY=./master_key_priv/priv_key.pem DIR_PUBL=./node3_key_publ DIR_PRIV=./node3_key_priv
	./keyManager OPERATION=CREATE_KEY MASTER_KEY=./master_key_priv/priv_key.pem DIR_PUBL=./node4_key_publ DIR_PRIV=./node4_key_priv
	./keyManager OPERATION=CREATE_KEY MASTER_KEY=./master_key_priv/priv_key.pem DIR_PUBL=./node5_key_publ DIR_PRIV=./node5_key_priv

### TODO: send only the public keys
rsync_keys: setup_keys
	rsync -avz $(PWD)/. $(NODE0_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE1_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE2_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE3_ADDR):$(PWD)
	rsync -avz $(PWD)/. $(NODE4_ADDR):$(PWD)

start_node0: heartbeat
	./heartbeat ID=node0 PORT=16120 KEY=./node0_key_priv/priv_key.pem \
		node1=$(NODE1_ADDR),16121,./node1_key_publ/publ_key.pem \
		node2=$(NODE2_ADDR),16122,./node2_key_publ/publ_key.pem \
		node3=$(NODE3_ADDR),16123,./node3_key_publ/publ_key.pem \
		node4=$(NODE4_ADDR),16124,./node4_key_publ/publ_key.pem \
		node5=$(NODE5_ADDR),16125,./node5_key_publ/publ_key.pem

start_node1: heartbeat
	./heartbeat ID=node1 PORT=16121 KEY=./node1_key_priv/priv_key.pem \
		node0=$(NODE0_ADDR),16120,./node0_key_publ/publ_key.pem \
		node2=$(NODE2_ADDR),16122,./node2_key_publ/publ_key.pem \
		node3=$(NODE3_ADDR),16123,./node3_key_publ/publ_key.pem \
		node4=$(NODE4_ADDR),16124,./node4_key_publ/publ_key.pem \
		node5=$(NODE5_ADDR),16125,./node5_key_publ/publ_key.pem

start_node2: heartbeat
	./heartbeat ID=node2 PORT=16122 KEY=./node2_key_priv/priv_key.pem \
		node0=$(NODE0_ADDR),16120,./node0_key_publ/publ_key.pem \
		node1=$(NODE1_ADDR),16121,./node1_key_publ/publ_key.pem \
		node3=$(NODE3_ADDR),16123,./node3_key_publ/publ_key.pem \
		node4=$(NODE4_ADDR),16124,./node4_key_publ/publ_key.pem \
		node5=$(NODE5_ADDR),16125,./node5_key_publ/publ_key.pem

start_node3: heartbeat
	./heartbeat ID=node3 PORT=16123 KEY=./node3_key_priv/priv_key.pem \
		node0=$(NODE0_ADDR),16120,./node0_key_publ/publ_key.pem \
		node1=$(NODE1_ADDR),16121,./node1_key_publ/publ_key.pem \
		node2=$(NODE2_ADDR),16122,./node2_key_publ/publ_key.pem \
		node4=$(NODE4_ADDR),16124,./node4_key_publ/publ_key.pem \
		node5=$(NODE5_ADDR),16125,./node5_key_publ/publ_key.pem

start_node4: heartbeat
	./heartbeat ID=node4 PORT=16124 KEY=./node4_key_priv/priv_key.pem \
		node0=$(NODE0_ADDR),16120,./node0_key_publ/publ_key.pem \
		node1=$(NODE1_ADDR),16121,./node1_key_publ/publ_key.pem \
		node2=$(NODE2_ADDR),16122,./node2_key_publ/publ_key.pem \
		node3=$(NODE3_ADDR),16123,./node3_key_publ/publ_key.pem \
		node5=$(NODE5_ADDR),16125,./node5_key_publ/publ_key.pem

start_node5: heartbeat
	./heartbeat ID=node5 PORT=16125 KEY=./node5_key_priv/priv_key.pem \
		node0=$(NODE0_ADDR),16120,./node0_key_publ/publ_key.pem \
		node1=$(NODE1_ADDR),16121,./node1_key_publ/publ_key.pem \
		node2=$(NODE2_ADDR),16122,./node2_key_publ/publ_key.pem \
		node3=$(NODE3_ADDR),16123,./node3_key_publ/publ_key.pem \
		node4=$(NODE4_ADDR),16124,./node4_key_publ/publ_key.pem

%.o:	%.c
	@echo ""
	$(CC) $(CFLAGS) -o $@ $<

%.o:	%.cpp
	@echo ""
	$(CXX) $(CXXFLAGS) -o $@ $<

run:
	make all

clean:
	rm -f *.o keyManager heartbeat
