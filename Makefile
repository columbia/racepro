
all:
	make -C tests

test:
	make -C tests test
clean:
	make -C tests clean
	rm -f *.pyc *~
