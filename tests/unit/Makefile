CFLAGS += -lcheck

test: test-filter.c
	$(CC) $(CFLAGS) -o test-filter ../../filter.c ../../disasm.c test-filter.c
	./test-filter
