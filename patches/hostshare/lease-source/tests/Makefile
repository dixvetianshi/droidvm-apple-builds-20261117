CC ?= cc
COMMON = -std=gnu11 -O1 -g -Wall -Wextra -Werror -pthread

lease_harness: lease_harness.c ../ghsm_lease_state.h ../ghsm_lease_uapi.h
	$(CC) $(COMMON) -fsanitize=address,undefined -o $@ lease_harness.c

lease_race_harness: lease_harness.c ../ghsm_lease_state.h ../ghsm_lease_uapi.h
	$(CC) $(COMMON) -fsanitize=thread -o $@ lease_harness.c

lease_impl_harness: lease_impl_harness.c ../ghsm_lease_impl.c.inc ../ghsm_lease_state.h ../ghsm_lease_uapi.h
	$(CC) $(COMMON) -Wno-unused-function -fsanitize=address,undefined -o $@ lease_impl_harness.c

lease_impl_race_harness: lease_impl_harness.c ../ghsm_lease_impl.c.inc ../ghsm_lease_state.h ../ghsm_lease_uapi.h
	$(CC) $(COMMON) -Wno-unused-function -fsanitize=thread -o $@ lease_impl_harness.c

test: lease_harness lease_race_harness lease_impl_harness lease_impl_race_harness
	./lease_harness
	TSAN_OPTIONS=halt_on_error=1 ./lease_race_harness
	./lease_impl_harness
	TSAN_OPTIONS=halt_on_error=1 ./lease_impl_race_harness

.PHONY: test
