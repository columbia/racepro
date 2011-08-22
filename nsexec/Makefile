# *DOCUMENTATION*
#
# List of environment variables that may be set by caller:
#  KERNELSRC	- path of kernel sources (def: ../linux)
#  SUBARCH	- sub-architecture (def: extract with 'uname')
#  PREFIX	- prefix path for installation (def: /usr/local)
#

KERNELSRC ?= ../../linux-2.6-scribe

CFLAGS += -g $(WARNS) -I$(KERNELSRC)

PROGS = nsexec

all: $(PROGS)
	cp nsexec ../scripts

nsexec: genstack.o clone_x86_32.o nsexec.o
clone_x86_32.o: eclone.h
genstack.o:  genstack.h

clean:
	@rm -f $(PROGS) *~ *.o
