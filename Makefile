
all:
	make -C nsexec
	make -C tests

test:
	make -C tests test

clean:
	make -C nsexec clean
	make -C tests clean
	rm -f *.pyc *~
