BIN = openra1n

all: $(BIN)

$(BIN): $(patsubst %, %.c, $(BIN))
	$(CC) $< $(CFLAGS) $(LDFLAGS) ../src/libopenra1n.a ../payloads/t*.o ../payloads/s*.o ../payloads/Pongo.o $(LIBS) -o $@

clean:
	rm -f $(BIN)

.PHONY: all
