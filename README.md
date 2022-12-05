
# Time Out Hash (TOH)

TOH is a solution for TCP/IP session tracking. It allows arbitrary data to be associated with a session.

The implementation assumes a high lookup to insert ratio - ie, one insert for
a TCP/IP session and a lookup for each packet. Because real-world packets may 
arrive out of order or may be missing entirely, TOH times out sessions rather 
than rely on a user to manually clear them. 

Timeout data is tracked using ring of pre-allocated trees. The trees keep track
of occupied rows in the hash of sessions. New sessions are inserted into the 
"active" tree. Lookups ensure a row is in or moved to the active tree. After a configurable delta all hash rows tracked by the oldest tree are cleared. The 
oldest tree then becomes the active tree.

The trees act as a sliding window and allows timeouts to execute over batches
of rows. The performance is significantly better than using a linked-list LRU
since pointers do not need to be updated for each lookup. The common case
lookup for a live TCP/IP session only requires a conventional hash lookup and
an integer comparison that confirms the row is tracked by the active table.

Benchmarks are included below.

# Building

Requires cmake and a recent gcc.

```
    mkdir build ; cd build ; cmake .. ; make
```

To test, run:

```
    ./tests/test_toth
```

Stress test:

```
    ./tests/test_toth -s
```

Test output includes benchmarks.

# Usage

...

The hash can be resized using toth_do_resize.

# Other included implementations

Two additional implementations are included for reference purposes.

* Linked List LRU (the conventional approach)
* Blue Green Hash (BGH)

BGH is inspired by connection draining blue-green deployments. It uses two
threads, and two hash tables. One thread which controls a periodic refresh.
During a refresh:

    * If a resize is necessary, a new hash is allocated and to meet past resource 
      requirements
    * When a lookup is performed, and the data is found in the old table, it is
      transitioned to the new table
    * All inserts go into the new table
    * After the timeout period, the previous hash is cleared

Since hash reallocation and cleanup are performed in their own thread, and 
timeouts are performed on coarse blocks, the performance impact is negligible.

Used by https://github.com/ajkeeton/pack_stat for TCP session stats


# Basic usage

    bgh_new(...)
    bgh_insert(...)
    bgh_lookup(...)
    bgh_clear(...) - optional, as sessions are timed out automatically
    bgh_free(...)
 
Hashes must be provided with a callback to free data:

    void free_cb(void *data_to_free) { ... }

# Sample

    ./sample/pcap_stats <pcap>

# BGH Configuration

To use with defaults (see bgh.h), just provide bgh_new with a callback to free
the data you insert. This can not be null.

    bgh_new(free_cb)

For more control over BGH's behavior, pass in a bgh_config_t to bgh_config_new. 

Initialize a config to the defaults:

    bgh_config_t config;
    bgh_init_config(&config);

    // Seconds between refresh periods. 0 to disable refreshes and therefore 
    // also timeouts. Refreshes are necessary to properly clean up the table.
    config.refresh_period = 120; 
    // Seconds to wait during the refresh period for active sessions to 
    // transition. Anything left in the old hash after this timeout will be removed
    config.timeout = 30;
    // Initial number of rows. Should be prime
    config.initial_rows = 100003;
    // Lower bounds to shrink to. If 0, the initial size is used
    // Should be prime
    config.min_rows = 26003;
    // Max number of rows we can grow to
    // Should be prime
    config.max_rows = 15485867;
    // Inserts are ignored if the hash reaches this percentage full
    // It will be scaled up with the next refresh (if configured to do so)
    config.hash_full_pct = 8;
    // If the hash reaches this percent of inserts, it will be scaled up
    config.scale_up_pct = 5;
    // At this percentage, the hash will be scaled down
    config.scale_down_pct = 0.05;
    
    bgh_t *tracker = bgh_config_new(&config, free_cb);

# BGH Autoscaling

The number of inserts is tracked. If it reaches the scale_up_pct or 
scale_down_pct, the hash will be resized during the new refresh period.

Note, prime.cc contains a partial list of prime numbers. When scaling up or 
down, BGH selects the next prime in the list in the direction of scaling.

# BGH Tests

To test, run:

    ./tests/test_bgh

# Benchmarks

On my Macbook, the total time for 8192 inserts, deletes, and 819200 lookups:

    - TOTH: ~150 ms
    - BGH: ~150 ms
    - Linked List LRU: ~6000 ms
    - STL map, with inserts only - no timeouts:  ~400 ms

