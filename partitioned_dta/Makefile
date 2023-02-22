#
# Don't modify below this line
#

include config.mak
include makefile.pin

ifeq ($(DEBUG_BUILD), 1)
EXTRA_FLAGS+=-O0 -g -ggdb
else
EXTRA_FLAGS+=-O3
endif
EXTRA_FLAGS+=-Wall -Werror -Wextra -Wno-unused-parameter


CFLAGS=$(EXTRA_FLAGS)
CXXFLAGS=$(EXTRA_FLAGS) -I./libdft
LDFLAGS=-L./libdft
LIB_FILES=libdft/libdft.a
TOOLS=partitioned_dta.so 
BINS=
HEADERS=

all:
	cd libdft && make
	make tools


.PHONY: clean tools tests distclean dist

tools: $(TOOLS) $(BINS)

partitioned_dta.so: partitioned_dta.o $(LIB_FILES)
	$(CXX) $(PIN_LDFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS) $(PIN_LIBS)

%.o: %.cpp $(HEADERS)
	$(CXX) $(PIN_CXXFLAGS) $(CXXFLAGS) -c $<

#tests:
	#cd tests && make

clean:
	rm -f $(TOOLS) $(BINS) *.o 
	cd libdft && make clean
	#cd tests && make clean
	
distclean:
	make clean

VNAME=partitoned_dta

dist:
	make distclean
	mkdir -p /tmp/$(VNAME)
	find . | grep -v '/\.' | cpio -dump /tmp/$(VNAME)/
	cd /tmp && rm -f $(VNAME).tar.gz && \
		tar -c $(VNAME) | gzip > $(VNAME).tar.gz
	mv /tmp/$(VNAME).tar.gz .
	rm -rf /tmp/$(VNAME)
	
