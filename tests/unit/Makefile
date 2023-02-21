CFLAGS += -lcheck

test: test-filter test-actions test-action-call
test-filter: test-filter.c
	$(CC) $(CFLAGS) -o test-filter ../../filter.c ../../disasm.c test-filter.c
	./test-filter

test-action-call: test_action_call.c ../../actions.c ../../actions.h ../../gluten.h
	$(CC) $(CFLAGS) -o test-action-call ../../actions.c test_action_call.c
	./test-action-call

test-actions: test_actions.c ../../actions.c ../../actions.h ../../common.h
	$(CC) $(CFLAGS) -o test-actions \
		../../common.c ../../actions.c \
		test_actions.c
	./test-actions
