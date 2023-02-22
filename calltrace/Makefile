CC=gcc
CXX=g++
# CXXFLAGS=-O0 -g -gdwarf-2 -Wall #-Werror
CXXFLAGS=-O2 -Wall #-Winline #-Werror
LDFLAGS=
LIBS=

#
# PIN related stuff
#
PIN_INCLUDES=-I$(PIN_HOME)/extras/xed2-ia32/include 			\
	-I$(PIN_HOME)/source/include -I$(PIN_HOME)/source/include/gen	\
	-I$(PIN_HOME)/extras/components/include
PIN_CXXFLAGS=-Wno-unknown-pragmas $(PIN_OPT)				\
	 -DBIGARRAY_MULTIPLIER=1 -DUSING_XED -fno-strict-aliasing	\
	 -fomit-frame-pointer -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX	\
	 $(PIN_INCLUDES)
PIN_LDFLAGS=-Wl,--hash-style=sysv -shared -Wl,-Bsymbolic		\
	-Wl,--version-script=$(PIN_HOME)/source/include/pintool.ver	\
	-L$(PIN_HOME)/extras/xed2-ia32/lib				\
	-L$(PIN_HOME)/ia32/lib -L$(PIN_HOME)/ia32/lib-ext
PIN_LIBS=-lpin -lxed -ldwarf -lelf -ldl #-liberty


TOOLS= calltrace.so 

all: $(TOOLS) relate

.PHONY: clean


relate: relation.c
	gcc -o $@ $<

$(TOOLS): %.so: %.o
	$(CXX) $(PIN_LDFLAGS) $(LDFLAGS) -o $@ $^ $(PIN_LIBS) $(LIBS)

%.o: %.cpp
	$(CXX) $(PIN_CXXFLAGS) $(CXXFLAGS) -c $< 

clean:
	rm -f *.so *.o $(TOOLS) relate 
