
PROGS = hello_world fork_one_file fork_two_file read_write_write

all: $(PROGS)

test: all
	python testall.py -v --all

clean:
	rm *.o *~ $(PROGS)

hello_world: hello_world.o
fork_one_file: fork_one_file.o
fork_two_file: fork_two_file.o
read_write_write: read_write_write.o
