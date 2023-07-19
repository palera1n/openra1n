OBJECTS += $(patsubst %.c, %.o, $(wildcard *.c))

all: libopenra1n.a libopenra1n.so

libopenra1n.a: $(OBJECTS)
	ar rcs libopenra1n.a $(OBJECTS) ../lz4/*.o ../payloads/lz4dec.o
	$(RANLIB) libopenra1n.a

libopenra1n.so: $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) ../lz4/*.o ../payloads/lz4dec.o $(LIBS) -shared -o libopenra1n.so

%.o: %.c
	$(CC) -c -DOPENRA1N_INTERNAL -I../include $(CFLAGS) $<

clean:
	find . -name '*.o' -delete
	rm -f libopenra1n.a libopenra1n.so

.PHONY: all
