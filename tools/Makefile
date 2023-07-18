BIN = openra1n

all: $(BIN)

$(BIN): $(patsubst %, %.c, $(BIN))
	$(CC) $(CFLAGS) $(LDFLAGS) $(LIBS) ../src/libopenra1n.a $< -o $@

clean:
	rm -f $(BIN)

.PHONY: all
