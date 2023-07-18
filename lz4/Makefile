OBJECTS += $(patsubst %.c, %.o, $(wildcard *.c))

all: $(OBJECTS)

%.o: %.c
	$(CC) -c -DOPENRA1N_INTERNAL -I../include $(CFLAGS) $<

clean:
	find . -name '*.o' -delete

.PHONY: all
