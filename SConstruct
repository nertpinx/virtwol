#!/usr/bin/env python

env = Environment(CFLAGS='-std=gnu11 -D_GNU_SOURCE')
env.MergeFlags(['!pkg-config --cflags --libs libvirt',
                '!pcap-config --cflags --libs'])

env.Program(['virtwol.c'])
