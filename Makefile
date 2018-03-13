
.PHONY: all clean

override CFLAGS := -D_GNU_SOURCE -std=gnu11 $(shell pcap-config --cflags) $(CFLAGS)
override LDFLAGS := $(shell pcap-config --libs) $(LDFLAGS)

all: virtwol

clean:
	rm -f virtwol virtwol.o
