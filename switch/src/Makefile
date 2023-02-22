
#EXTRA_FLAGS=-g -ggdb -O0
EXTRA_FLAGS=-O3
EXTRA_FLAGS+=-Wall -Werror -Wextra -Wno-unused-parameter
#
# Don't modify below this line
#

include ../config.mak
ifeq ($(ISOLATE_MEMORY), 1)
EXTRA_FLAGS+=-DISOLATE_MEMORY
endif

include makefile.pin

DFT_CXXFLAGS	+= -Wall -c -fomit-frame-pointer -std=c++0x -O3	\
		   -fno-strict-aliasing -fno-stack-protector	\
		   -DBIGARRAY_MULTIPLIER=1 -DUSING_XED		\
		   -DTARGET_IA32 -DHOST_IA32 -DTARGET_LINUX	\
		   -mtune=core2 -ggdb -DDEBUG_MEMTRACK



# variable definitions
PIN_CXXFLAGS+=$(EXTRA_FLAGS)
CXXFLAGS=$(EXTRA_FLAGS)
EXT_LIBS=-lsqlite3
ARFLAGS = rcsv
LDFLAGS=

DFT_OBJS = libdft_api.o libdft_core.o syscall_desc.o tagmap.o
ISRLIB_OBJS=libisr.o Image.o Key.o watchdog.o
ISRLIB=libisr.a
ISR_HEADERS=Image.h Key.h log.hpp watchdog.hpp


all: isr.so exec_wrapper

lib: $(ISRLIB) exec_wrapper
#.PHONY: all sanity clean null 

.PHONY: clean null

# get system information
OS=$(shell uname -o | grep Linux$)			# OS
ARCH=$(shell uname -m | grep 86$)			# arch
KVER=$(subst -, ,$(subst ., ,$(shell uname -r)))	# kernel version (temp)

# kernel version in compact format (e.g., 2.6.26-2-686-bigmem is 2626)
KERN_VER=$(join $(word 1,$(KVER)),$(join $(word 2,$(KVER)),$(word 3,$(KVER))))

all: $(DFT_OBJS) isr.so isr_wrapper.so exec_wrapper
	for i in $^; do \
		install $$i ../.;\
	done

#install: $(DFT_OBJS) isr.so isr_wrapper.so exec_wrapper
#	for i in $^; do \
#		install $$i ../.;\
#	done
sanity:
# check if PIN_HOME variable is defined
ifndef PIN_HOME
	$(error "PIN_HOME environment variable is not set")
endif
# check the OS (must be Linux)
ifeq ($(strip $(OS)),)
	$(error "This version of libdft is for Linux only")
endif
# check the architecture (must be x86, i386, i486, i686, ...)
ifeq ($(strip $(ARCH)),)
	$(error "This version of libdft is for x86 only")
endif
# update the kernel version (if necessary)
ifeq ($(strip $(shell grep LINUX_KERNEL linux_kernver.h | cut -f2)),0)
	sed -i 's/0/$(KERN_VER)/g' linux_kernver.h
endif

null: null.so

isr.so: isr.o $(ISRLIB) libisr.hpp $(DFT_OBJS) $(ISR_HEADERS)
	$(CXX) $(PIN_LDFLAGS) -o $@ -L./ -o $@ $< -lisr $(DFT_OBJS) $(PIN_LIBS) $(EXT_LIBS)

$(ISRLIB): $(ISRLIB_OBJS) $(ISR_HEADERS)
	$(AR) $(ARFLAGS) $@ $(ISRLIB_OBJS)

null.so: null.o
	$(CXX) $(PIN_LDFLAGS) -o $@ $^ $(PIN_LIBS)

#core.o: core.c switch.h
#	$(CXX) $(PIN_CXXFLAGS) $(PIN_INCLUDES) $(CXXFLAGS) -c $< 

# libdft_api
libdft_api.o: libdft_api.c libdft_api.h branch_pred.h
	$(CXX) $(DFT_CXXFLAGS) $(PIN_INCLUDES) -o $(@) $(@:.o=.c)

# libdft_core
libdft_core.o: libdft_core.c libdft_core.h branch_pred.h
	$(CXX) $(DFT_CXXFLAGS) $(PIN_INCLUDES) -o $(@) $(@:.o=.c)

# syscall_desc
syscall_desc.o: syscall_desc.c syscall_desc.h  branch_pred.h
	$(CXX) $(DFT_CXXFLAGS) $(PIN_INCLUDES) -o $(@) $(@:.o=.c)

# tagmap
tagmap.o: tagmap.c tagmap.h branch_pred.h
	$(CXX) $(DFT_CXXFLAGS) $(PIN_INCLUDES) -o $(@) $(@:.o=.c)

%.o: %.cpp
	$(CXX) $(PIN_CXXFLAGS) -c $<

Image.o: Image.cpp Image.h

Key.o: Key.cpp Key.h


exec_wrapper: exec_wrapper.c
	$(CC) -o $@ $(CXXFLAGS) $<


clean:
	rm -f *.so *.a *.o exec_wrapper
	sed -i 's/$(KERN_VER)/0/g' linux_kernver.h
