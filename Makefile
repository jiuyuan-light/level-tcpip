export CC = gcc
# $(source get_env.sh)
export ROOT_DIR=$(shell git rev-parse --show-toplevel)

# ASAN
NEED_ASAN=y
ifeq ($(NEED_ASAN),y)
ASAN=-fsanitize=address -fno-omit-frame-pointer
else
ASAN= -fsanitize=thread
endif
CFLAGS = -W -Wall -Wimplicit-function-declaration -Werror -Wno-unused-parameter -Wno-sign-compare
CPPFLAGS = -I include -Wall -Werror -pthread $(ASAN)
# -Lzlog-master/src -Izlog-master/src
# -lzlog
LIB_CC_FLAGS = -pthread -I${ROOT_DIR}/libhv-master/include/hv -I${ROOT_DIR}/zlog-master/src/
LIB_LD_FLAGS = libzlog.so.1.2 -Wl,-rpath=$(shell pwd) libhv.so $(LIB_CC_FLAGS)

EXTRA_CFLAGS = -Wno-address-of-packed-member -DDEBUG_TIMER -DDEBUG_SOCKET -DDEBUG_TCP -g3 -gdwarf-2
src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, build/%.o, $(src))
headers = $(wildcard include/*.h)
apps = apps/curl/curl

libhv:
	make clean -C ${ROOT_DIR}/libhv-master
	cd ${ROOT_DIR}/libhv-master && ./configure --enable-uds
	make BUILD_TYPE=DEBUG -C ${ROOT_DIR}/libhv-master
	cp ${ROOT_DIR}/libhv-master/lib/libhv.so ${ROOT_DIR}
	make clean -C ${ROOT_DIR}/libhv-master

libzlog:
	make clean -C ${ROOT_DIR}/zlog-master
	make OPTIMIZATION=-O0 -C ${ROOT_DIR}/zlog-master
	cp ${ROOT_DIR}/zlog-master/src/libzlog.so.1.2 ${ROOT_DIR}
	make clean -C ${ROOT_DIR}/zlog-master

lvl-ip: $(obj)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(EXTRA_CFLAGS) $(obj) $(LIB_LD_FLAGS) -o lvl-ip
	@echo
	@echo "lvl-ip needs CAP_NET_ADMIN:"
	sudo setcap cap_setpcap,cap_net_admin=ep lvl-ip

build/%.o: src/%.c ${headers}
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LIB_CC_FLAGS) $(EXTRA_CFLAGS) -c $< -o $@

debug: CFLAGS+= -DDEBUG_SOCKET -DDEBUG_TCP
debug:
	make lvl-ip
ifneq ($(MAKECMDGOALS),test)
	$(MAKE) -C tools
else
	$(MAKE) -C tools debug
endif
apps: $(apps)
ifneq ($(MAKECMDGOALS),test)
	$(MAKE) -C tools
else
	$(MAKE) -C tools debug
endif
	
	$(MAKE) -C apps/curl
	$(MAKE) -C apps/curl-poll

all: lvl-ip apps

test: debug apps cleanzlog
	@echo
	@echo "Networking capabilites are required for test dependencies:"
	which arping | sudo xargs setcap cap_net_raw=ep
	which tc | sudo xargs setcap cap_net_admin=ep
	@echo
	cd tests && ./test-run-all

clean: cleanzlog
	rm build/*.o lvl-ip -rf
	make clean -C tools
.PHONY=cleanzlog
cleanzlog:
	for file in $(shell ls ${ROOT_DIR}/logs/*.log); do cat /dev/null >$$file; done