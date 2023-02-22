CFLAGS += -lcheck

test: test-filter test-operations test-op-call
test-filter: test-filter.c
	$(CC) $(CFLAGS) -o test-filter ../../filter.c ../../disasm.c test-filter.c
	./test-filter

test-op-call: test_op_call.c ../../operations.c ../../operations.h ../../gluten.h
	$(CC) $(CFLAGS) -o test-op-call ../../operations.c test_op_call.c
	./test-op-call

test-operations: test_operations.c ../../operations.c ../../operations.h ../../common.h
	$(CC) $(CFLAGS) -o test-operations \
		../../common.c ../../operations.c \
		test_operations.c
	./test-operations
