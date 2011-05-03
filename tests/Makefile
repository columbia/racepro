
PROGS = hello_world fork_one_file fork_two_file fork_two_proc read_write_write \
	no_race no_race_pipe unlink_stat euid exit_exit_wait signal signal2 \
	toctou

all: $(PROGS)

test: all
	env PYTHONPATH=../src ./testall.py -v --all

clean:
	rm -f *.o *~ $(PROGS)

euid: euid.o
	gcc -o $@ $< -lpthread
