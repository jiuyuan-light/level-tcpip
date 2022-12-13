CPPFLAGS = -I ../include -Wall -Werror

all: liblevelip

debug: CFLAGS+= -DDEBUG_API
debug: liblevelip

liblevelip: liblevelip.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -fPIC -shared -o liblevelip.so liblevelip.c -ldl $(ROOT_DIR)/libzlog.so.1.2 -Wl,-rpath=$(shell pwd)/../ -I${ROOT_DIR}/zlog-master/src/ -I${ROOT_DIR}/libhv-master/include/hv

.PHONY:
clean:
	rm liblevelip.so* -rf
