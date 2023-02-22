include config.mak

all:
	cd src && make
	for i in exec_wrapper isr.so; do\
		install src/$$i .;\
	done



.PHONY: clean

clean:
	cd src && make clean
	rm -f *.so exec_wrapper

distclean:
	make clean
	rm -rf encrypted_lib encrypted_bins image_keys.db

VNAME=$(shell cat VERSION)

dist:
	make distclean
	mkdir -p /tmp/$(VNAME)
	find . | grep -v '/\.' | cpio -dump /tmp/$(VNAME)/
	cd /tmp && rm -f $(VNAME).tar.gz && \
		tar -c $(VNAME) | gzip > $(VNAME).tar.gz
	mv /tmp/$(VNAME).tar.gz .
	rm -rf /tmp/$(VNAME)
	
