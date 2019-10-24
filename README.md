# librtring

A multi-producer, multi-consumer, ring buffer amenable to memory
mapping between processes with priority inheriting locking and
signaling for synchronization.


## Building librtring

```
git clone https://github.com/harisokanovic/librtring.git
make
make check  # to run unit tests
```

Consider running ``test-latency --rt-priority 99`` to measure messaging
latency between RT tasks (SCHED_FIFO, highest priority). Requires root.


## rtpi dependency

This project uses the relatively new librtpi.so which is not yet
packaged by many distributions. It additionally uses a patch set for
inter-process mapping of mutexes and condvars that's not yet in mainline
rtpi. You may therefore need to build this library as well to
successfully use librtring.

Source with aforementioned patches:
https://github.com/harisokanovic/librtpi/tree/wip-rfc-api-change

Follow instructions in the enclosed README.md to build rtpi.

``source setup-local-rtpi-env.sh /path/to/rtpi.git`` to configure CFLAGS
and LD_LIBRARY_PATH for local rtpi dependency.


## Known issues/limitation

``git grep -i TODO`` to find code in need of improvement.

