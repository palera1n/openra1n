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

export CC AR RANLIB CFLAGS LDFLAGS LIBS

all: openra1n libopenra1n

include/payloads:
	@mkdir -p include/payloads

include/payloads/%.h: payloads/%.bin include/payloads
	xxd -i $< >> $@

payloads: $(patsubst %, include/payloads/%.h, lz4dec Pongo t7000 t7001 s8000 s8001 s8003 t8010 t8011 t8012 t8015)

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
	rm -rf include/payloads

.PHONY: all clean payloads openra1n libopenra1n lz4
