
PROGS = hello_world fork_one_file fork_two_file fork_two_proc read_write_write no_race

all: $(PROGS)

test: all
	python testall.py -v --all

clean:
	rm *.o *~ $(PROGS)

hello_world: hello_world.o
fork_one_file: fork_one_file.o
fork_two_file: fork_two_file.o
fork_two_proc: fork_two_proc.o
read_write_write: read_write_write.o
no_race: no_race.o
