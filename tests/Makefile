
PROGS = hello_world fork_one_file fork_two_file fork_two_proc read_write_write \
	no_race no_race_pipe unlink_stat euid exit_exit_wait signal signal2

all: $(PROGS)

test: all
	python testall.py -v --all

clean:
	rm -f *.o *~ $(PROGS)

hello_world: hello_world.o
fork_one_file: fork_one_file.o
fork_two_file: fork_two_file.o
fork_two_proc: fork_two_proc.o
read_write_write: read_write_write.o
no_race: no_race.o
no_race_pipe: no_race_pipe.o
unlink_stat: unlink_stat.o
exit_exit_wait: exit_exit_wait.o
signal: signal.o
segfault: segfault.o
euid: euid.o
	gcc -o $@ $< -lpthread
