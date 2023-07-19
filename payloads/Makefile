PAYLOAD_NAMES = lz4dec Pongo t7000 t7001 s8000 s8001 s8003 t8010 t8011 t8012 t8015

all: payloads

payloads: $(patsubst %, %.o, $(PAYLOAD_NAMES))

%.o: %.c
	$(CC) -c $< $(CFLAGS)

%.c: %.bin
	xxd -i $< > $@

clean:
	find . -name '*.o' -delete
	find . -name '*.c' -delete

.PHONY: all payloads
