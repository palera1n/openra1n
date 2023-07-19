CFLAGS = -I$(shell pwd)/include -Wall -Wno-pointer-sign -fsanitize=address,undefined -g
CFLAGS +=  -fvisibility=hidden
CFLAGS += -Os
AR = ar
RANLIB = ranlib

ifeq ($(LIBUSB),1)
	CC = gcc
	CFLAGS += -DHAVE_LIBUSB
	LIBS += -lusb-1.0
else
	CC = xcrun -sdk macosx cc
	LIBS += -framework IOKit -framework CoreFoundation
endif

ifneq (,$(findstring MINGW, $(shell uname -s)))
	LIBS += -lws2_32
endif

export CC AR RANLIB CFLAGS LDFLAGS LIBS

all: openra1n libopenra1n

payloads:
	$(MAKE) -C payloads

lz4:
	$(MAKE) -C lz4

libopenra1n: payloads lz4
	$(MAKE) -C src

openra1n: payloads libopenra1n
	$(MAKE) -C tools

clean:
	$(MAKE) -C tools clean
	$(MAKE) -C src clean
	$(MAKE) -C lz4 clean
	$(MAKE) -C payloads clean

.PHONY: all clean payloads openra1n libopenra1n lz4
