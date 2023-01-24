CFLAGS += -lcheck

test: test-filter test-actions
test-filter: test-filter.c
	$(CC) $(CFLAGS) -o test-filter ../../filter.c ../../disasm.c test-filter.c
	./test-filter

test-actions: test_action_call.c ../../actions.c ../../actions.h
	$(CC) $(CFLAGS) -o test-action-call ../../actions.c test_action_call.c
	./test-action-call
