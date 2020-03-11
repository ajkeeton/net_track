#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <strings.h>
#include <assert.h>
#include <stdio.h>
#include <sys/time.h>
#include <map>
#include <list>
#include <vector>
#include <sys/time.h>
#include "../bgh/bgh.h"

extern "C" {
void *_draining_lookup_active(
        bgh_tbl_t *active, bgh_tbl_t *standby, bgh_key_t *key);
void *_draining_prefer_standby(
        bgh_tbl_t *active, bgh_tbl_t *standby, bgh_key_t *key);
bgh_stat_t bgh_insert_table(bgh_tbl_t *tbl, bgh_key_t *key, void *data);
int64_t _lookup_idx(bgh_tbl_t *table, bgh_key_t *key);
bgh_tbl_t 
    *bgh_new_tbl(uint64_t rows, uint64_t max_inserts, void (*free_cb)(void *));

int prime_total();
uint64_t prime_at_idx(int idx);
int prime_nearest_idx(uint64_t val);
uint64_t prime_larger_idx(int idx);
uint64_t prime_smaller_idx(int idx);
}
void free_cb(void *p) {
    free(p);
}

void nop_free_cb(void *p) {}

void assert_eq(void *p, const char *s) {
    assert(!strcmp((char *)p, s));
}

void assert_lookup_eq(bgh_tbl_t *t, bgh_key_t *key, const char *val) {
    int64_t idx = _lookup_idx(t, key);

    assert(idx >= 0);
    assert_eq(t->rows[idx]->data, val);
}

void assert_lookup_clear(bgh_tbl_t *t, bgh_key_t *key) {
    int64_t idx = _lookup_idx(t, key);
    assert(idx < 0 || !t->rows[idx]->data);
}

void assert_refresh_within(bgh_t *b, int seconds) {
    time_t start = time(NULL);

    while(!b->refreshing) {
        assert(time(NULL) - start <= seconds);
    }
}

void primes_test() {
    printf("%s\n", __func__);

    // Limit
    assert(prime_nearest_idx(0) == 0);
    assert(prime_nearest_idx(50046) == 0);
    assert(prime_nearest_idx(50047) == 0);
    // Rounds up
    assert(prime_nearest_idx(50048) == 1);
    assert(prime_nearest_idx(100002) == 1);
    assert(prime_nearest_idx(100004) == 2);

    assert(prime_smaller_idx(0) == 50047);
    assert(prime_smaller_idx(1) == 50047);
    assert(prime_larger_idx(1) == 200003);

    assert(prime_nearest_idx(16000000) == 26);
    assert(prime_larger_idx(26) == 17000023);
    assert(prime_larger_idx(31) == 20000003);
    // Limit
    assert(prime_larger_idx(32) == 20000003);
}

void basic() {
    printf("%s\n", __func__);

    bgh_config_t conf;
    bgh_config_init(&conf);
    conf.starting_rows = 31;
    conf.hash_full_pct = 50;

    bgh_t *tracker = bgh_config_new(&conf, free_cb);

    bgh_key_t key;
    // Bzero'ing to clean up pad bytes. Needed to prevent valgrind from complaining
    bzero(&key, sizeof(key)); 

    key.sip = 10;
    key.dip = 200;
    key.sport = 3000;
    key.dport = 5000;
    key.vlan = 5;

    // Add three (changing source IP)
    bgh_insert(tracker, &key, strdup("foo"));
    key.sip = 20;
    bgh_insert(tracker, &key, strdup("bar"));
    key.sip = 30;
    bgh_insert(tracker, &key, strdup("baz"));

    // Lookup each
    key.sip = 10;
    assert_eq(bgh_lookup(tracker, &key), "foo");

    key.sip = 20;
    assert_eq(bgh_lookup(tracker, &key), "bar");
    // Overwrite
    bgh_insert(tracker, &key, strdup("foobazzybar"));
    assert_eq(bgh_lookup(tracker, &key), "foobazzybar");

    key.sip = 30;
    assert_eq(bgh_lookup(tracker, &key), "baz");

    // Swap source and IP, should get same session data
    bgh_key_t key2;
    key2.dip = 30;
    key2.sip = 200;
    key2.dport = 3000;
    key2.sport = 5000;
    key2.vlan = 5;

    assert_eq(bgh_lookup(tracker, &key2), "baz");

    key.sip = 20;
    bgh_clear(tracker, &key);

    key.sip = 10;
    bgh_clear(tracker, &key);
    assert(!bgh_lookup(tracker, &key));

    // Already deleted
    bgh_clear(tracker, &key);
    assert(!bgh_lookup(tracker, &key));
    key.sip = 20;
    bgh_clear(tracker, &key);
    assert(!bgh_lookup(tracker, &key));
    key.sip = 30;
    bgh_clear(tracker, &key);
    assert(!bgh_lookup(tracker, &key));

    bgh_free(tracker);
}

#define NUM_ITS 8192
void timeouts() {
    printf("%s\n", __func__);

    bgh_config_t conf;
    bgh_config_init(&conf);
    conf.timeout = 1;
    conf.starting_rows = 31;
    conf.refresh_period = 2;

    bgh_t *tracker = bgh_config_new(&conf, free_cb);

    bgh_key_t key;
    // Bzero'ing to clean up pad bytes and prevent valgrind from complaining
    bzero(&key, sizeof(key)); 
    
    // Add three, but across the refresh + timeout period
    key.sip = 1;
    bgh_insert(tracker, &key, strdup("foo"));
    sleep(1);
    assert_eq(bgh_lookup(tracker, &key), "foo");

    assert(!tracker->refreshing);

    key.sip = 222;
    bgh_insert(tracker, &key, strdup("bar"));

    // wait for refresh to start
    assert_refresh_within(tracker, 2);

    // Make sure we still have both 
    assert(tracker->active->inserted == 2);

    // Table is draining.
    // Let "1" expire, lookup "2" (thereby refreshing it), and insert "3"
    // Wait .5 seconds
    usleep(500000);
    assert(tracker->refreshing);
    assert(tracker->active->inserted == 2);
    assert(tracker->standby->inserted == 0);

    key.sip = 222;
    assert_eq(bgh_lookup(tracker, &key), "bar");
    assert(tracker->standby->inserted == 1);
    assert(tracker->active->inserted == 1);
    assert(!tracker->standby->collisions);

    key.sip = 3333;
    assert(!tracker->standby->collisions);
    bgh_insert(tracker, &key, strdup("baz"));
    assert(tracker->standby->inserted == 2);
    assert(tracker->active->inserted == 1);
    assert(!tracker->standby->collisions);

    // Lookup 2 again. Should be in the standby table
    key.sip = 222;
    assert_eq(bgh_lookup(tracker, &key), "bar");
    assert(!tracker->active->collisions);
    assert(!tracker->standby->collisions);
    usleep(600000);
    assert_eq(bgh_lookup(tracker, &key), "bar");

    assert(!tracker->refreshing);
    assert(!tracker->standby);
    assert(tracker->active->inserted == 2);
    assert(tracker->active->collisions == 0);

    // 1 is timed out and gone
    key.sip = 1;
    assert(!bgh_lookup(tracker, &key));
    key.sip = 222;
    assert_eq(bgh_lookup(tracker, &key), "bar");
    key.sip = 3333;
    assert_eq(bgh_lookup(tracker, &key), "baz");

    bgh_free(tracker);
}

void linear_probing() {
    printf("%s\n", __func__);

    bgh_config_t conf;
    bgh_config_init(&conf);
    conf.starting_rows = 13;
    conf.hash_full_pct = 100;
    conf.refresh_period = 0;

    bgh_t *tracker = bgh_config_new(&conf, nop_free_cb);

    bgh_key_t key1, key2;
    bzero(&key1, sizeof(key1)); 
    bzero(&key2, sizeof(key2)); 

    key1.sip = 10;
    key1.dip = 200;
    key1.sport = 3000;
    key1.dport = 4000; 
    // Same IPs, but diff ports, but def a hash collision
    key2.sip = 10;
    key2.dip = 200;
    key2.sport = 4000;
    key2.dport = 3000; 

    bgh_insert(tracker, &key1, (char*)"foo1");
    bgh_insert(tracker, &key2, (char*)"foo2");

    int64_t idx1 = _lookup_idx(tracker->active, &key1);
    int64_t idx2 = _lookup_idx(tracker->active, &key2);

    assert(idx1 == idx2-1);

    // Removed. No longer doing "hash healing" due to edge case and low value
    #if 0
    // Clear the first one. When we do the next lookup on the collided row, it
    // will adjust back by one
    bgh_clear(tracker, &key1);
    idx2 = _lookup_idx(tracker->active, &key2);
    assert(idx1 == idx2);
    #endif

    bgh_free(tracker);
}

struct key_cmp {
    bool operator()(const bgh_key_t &k1, const bgh_key_t &k2) const {
        // Have to compare going both directions
        if(((k1.sip == k2.sip &&
            k1.sport == k2.sport &&
            k1.dip == k2.dip && 
            k1.dport == k2.dport)
                ||
           (k1.sip == k2.dip && 
            k1.sport == k2.dport &&
            k1.dip == k2.sip && 
            k1.dport == k2.sport))
                && 
           k1.vlan == k2.vlan)
            return 0;

        return memcmp((void*)&k1, (void*)&k2, sizeof(bgh_key_t)) < 0;
    }
};

void bench() {
    printf("%s\n", __func__);

    bgh_t *tracker = bgh_new(nop_free_cb);
    bgh_key_t keys[NUM_ITS];
    memset(&keys, 0, sizeof(keys));

    bgh_key_t key;
    // Bzero'ing to clean up pad bytes and prevent valgrind from complaining
    bzero(&key, sizeof(key)); 

    for(int i=0; i<NUM_ITS; i++) {
        key.dip = rand();
        key.sip = rand();
        key.sport = (uint16_t)rand();
        key.dport = (uint16_t)rand();
        keys[i] = key;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t now = 1000000 * tv.tv_sec + tv.tv_usec;

    for(int i=0; i<NUM_ITS; i++) {
        bgh_insert(tracker, &keys[i], (char*)"foo");
    }

    assert(tracker->active->collisions < 10);

    for(int i=0; i<NUM_ITS*100; i++) {
        assert(bgh_lookup(tracker, &keys[i % NUM_ITS]));
    }

    for(int i=0; i<NUM_ITS; i++) 
        bgh_clear(tracker, &keys[i]);

    gettimeofday(&tv, NULL);
    uint64_t fin = 1000000 * tv.tv_sec + tv.tv_usec;
    printf("%d inserts, deletes, and %d lookups: %f ms\n", 
        NUM_ITS, NUM_ITS*100, float((fin - now))/1000);

    bgh_free(tracker);

    /////////////////////////
    // The STL map comparison
    std::map<bgh_key_t, char *, key_cmp> tree;
    gettimeofday(&tv, NULL);
    now = 1000000 * tv.tv_sec + tv.tv_usec;

    for(int i=0; i<NUM_ITS; i++) {
        tree[keys[i]] = (char*)"foo";
    }

    for(int i=0; i<NUM_ITS*100; i++) {
        auto it = tree.find(keys[i % NUM_ITS]);
        assert(it != tree.end());
    }

    for(int i=0; i<NUM_ITS; i++) {
        auto it = tree.find(keys[i]);
        tree.erase(keys[i]);
    }

    gettimeofday(&tv, NULL);
    fin = 1000000 * tv.tv_sec + tv.tv_usec;
    printf("STL map: %f ms\n", float((fin - now))/1000);
}

void time_draining() {
    printf("%s\n", __func__);

    bgh_config_t conf;
    bgh_config_init(&conf);
    conf.starting_rows = 10000141;
    conf.timeout = 2;
    conf.refresh_period = 7;

    bgh_t *tracker = bgh_config_new(&conf, nop_free_cb);

    assert(tracker->active->num_rows == 10000141);
    bgh_key_t key;
    // Bzero'ing to clean up pad bytes and prevent valgrind from complaining
    bzero(&key, sizeof(key)); 
    key.dport = (uint16_t)rand();
    key.dip = rand();

    bgh_key_t keys[NUM_ITS];
    memset(&keys, 0, sizeof(keys));

    for(int i=0; i<NUM_ITS; i++) {
        keys[i] = key;
        keys[i].sip = rand();
    }

    printf("Running for %ds before draining starts. Num keys: %u\n", 
        tracker->config.refresh_period - 2, NUM_ITS);

    uint64_t total = 0;
    time_t start = time(NULL);

    // First, insert for refresh_period/2
    while(time(NULL) - start < conf.refresh_period/2 - 1) {
        assert(bgh_insert(tracker, &keys[total % NUM_ITS], (void*)"nodelete")
             != BGH_FULL);
        total++;
    }
    printf("%llu inserts\n", total);

    // Run for refresh_period - 1 and count number of lookup 
    total = 0;
    start = time(NULL);
    while(time(NULL) - start < conf.refresh_period/2 - 1) {
        assert(bgh_lookup(tracker, &keys[total % NUM_ITS]));
        total++;
    }
    printf("%llu lookups \n", total);
    total = 0;
    start = time(NULL);

    puts("Totals while refreshing...");

    assert_refresh_within(tracker, 5);

    total = 0;
    start = time(NULL);
    while(time(NULL) - start < conf.refresh_period/2 - 1) {
        assert(bgh_insert(tracker, &keys[total % NUM_ITS], (void*)"nodelete") != BGH_FULL);
        total++;
    }
    printf("%llu inserts\n", total);

    total = 0;
    start = time(NULL);
    while(time(NULL) - start < conf.refresh_period/2 - 1) {
        assert(bgh_lookup(tracker, &keys[total % NUM_ITS]));
        total++;
    }
    printf("%llu lookups \n", total);

    bgh_free(tracker);
}

void drain() {
    printf("%s\n", __func__);

    bgh_config_t conf;
    bgh_config_init(&conf);
    conf.starting_rows = 17;
    conf.refresh_period = 0; // disables refresh

    bgh_t *tracker = bgh_config_new(&conf, free_cb);

    // This is only set during a refresh, so manually create it
    tracker->standby = bgh_new_tbl(16, 16, free_cb);

    bgh_key_t key;
    // Bzero'ing to clean up pad bytes and prevent valgrind from complaining
    bzero(&key, sizeof(key)); 

    key.sip = 111;
    bgh_insert_table(tracker->active, &key, strdup("first"));
    key.sip = 222;
    bgh_insert_table(tracker->active, &key, strdup("second"));

    key.sip = 111;

    // Internal functions
    // Confirm we move between tables correctly
    assert_lookup_eq(tracker->active, &key, "first");
    assert_lookup_eq(tracker->active, &key, "first");
    // this moves the entry from the active to the standby table
    assert_eq(
        _draining_lookup_active(tracker->active, tracker->standby, &key), "first");
    // Deleted from active table
    assert_lookup_clear(tracker->active, &key);
    // In standby
    assert_lookup_eq(tracker->standby, &key, "first");

    // Lookup standby "favors" the standby table
    assert_eq(
        _draining_prefer_standby(tracker->active, tracker->standby, &key), "first");

    key.sip = 222;

    // Confirm _draining_prefer_standby also moves from active to standby
    assert_lookup_eq(tracker->active, &key, "second");
    assert_eq(
        _draining_prefer_standby(tracker->active, tracker->standby, &key), "second");
    // Confirm no longer in active, only in standby
    assert_lookup_clear(tracker->active, &key);
    assert_lookup_eq(tracker->standby, &key, "second");

    bgh_free(tracker);
}

void resize() {
    printf("%s\n", __func__);

    bgh_config_t conf;
    bgh_config_init(&conf);
    conf.starting_rows = 100003;
    conf.refresh_period = 2;
    conf.timeout = 1;

    bgh_t *tracker = bgh_config_new(&conf, nop_free_cb);

    int nkeys = conf.starting_rows / 4;
    bgh_key_t keys[nkeys];
    memset(&keys, 0, sizeof(keys));

    bgh_key_t key;
    // Bzero'ing to clean up pad bytes and prevent valgrind from complaining
    bzero(&key, sizeof(key)); 

    for(int i=0; i<nkeys; i++) {
        key.dip = rand();
        key.sip = rand();
        key.sport = (uint16_t)rand();
        key.dport = (uint16_t)rand();
        keys[i] = key;
    }

    assert(tracker->active->num_rows == 100003);
    for(int i=0; i<nkeys; i++) 
        bgh_insert(tracker, &keys[i], (char*)"foo");

    sleep(4);
    assert(tracker->active->num_rows == 200003);
    sleep(4);
    assert(tracker->active->num_rows <= 100003);

    bgh_free(tracker);
}

std::vector<bgh_key_t> keys;

bgh_key_t gen_rand_key() {
    bgh_key_t key;
    bzero(&key, sizeof(key));  // for valgrind
    key.sport = (uint16_t)rand();
    key.dport = (uint16_t)rand();
    key.sip = rand();
    key.dip = rand();
    return key;
}

bgh_key_t get_rand_key() {
    return keys[rand() % keys.size()];
}

static int64_t inline nanos_total(struct timespec *start) {
    static struct timespec end, ret;
    clock_gettime(CLOCK_MONOTONIC, &end);

    if ((end.tv_nsec - start->tv_nsec) < 0) {
        ret.tv_sec = end.tv_sec - start->tv_sec - 1;
        ret.tv_nsec = 1000000000 + end.tv_nsec - start->tv_nsec;
    } else {
        ret.tv_sec = end.tv_sec - start->tv_sec;
        ret.tv_nsec = end.tv_nsec - start->tv_nsec;
    }

    return (uint64_t)ret.tv_sec * 1000000000L + ret.tv_nsec;
}

void stress() {
    puts("Starting long-running stress test");

    bgh_config_t conf;
    bgh_config_init(&conf);
    conf.starting_rows = 3000017;
    conf.timeout = 4;
    conf.refresh_period = 8;

    bgh_t *tracker = bgh_config_new(&conf, free_cb);

    for(int i=0; i<1024*512; i++) {
        keys.push_back(gen_rand_key());
    }

    // Will arbitrarily restrict or grow the max number of sessions over time
    int sessions_max = keys.size() / 2;

    time_t last_out = 0,
           last_state_change = 5,
           start = time(NULL);
    uint64_t failed_insert = 0,
             lookup_total_time = 0,
             lookup_count = 1, // hack to avoid /0 with first stat update
             insert_total_time = 0,
             insert_count = 1, // hack for first stat update
             iteration = 0;
    struct timespec tstart;

    while(1) {
        bgh_key_t key;

        time_t now = time(NULL);
        if(now - last_out > 2) {
            last_out = now;

            bgh_stats_t stats;
            bgh_get_stats(tracker, &stats);
            // print stats
            printf("\n%lus, iteration %llu, - Simulating %d sessions\n",
                    time(NULL) - start, iteration, sessions_max);
            printf("- inserted:       %llu\n", stats.inserted);
            printf("- collisions:     %llu\n", stats.collisions);
            printf("- table size:     %llu\n", stats.num_rows);
            printf("- in refresh:     %s\n", stats.in_refresh ? "yes" : "no");
            printf("- failed inserts: %llu\n", failed_insert);
            printf("- %% used:         %.1f\n", (float)stats.inserted / stats.num_rows * 100);
            printf("- Lookup time avg: %llu ns\n", lookup_total_time/lookup_count);
            printf("- Insert time avg: %llu ns\n", insert_total_time/insert_count);

            failed_insert = 0;
            lookup_total_time = lookup_count = 0,
            insert_total_time = insert_count  = 0;
        }

        if(now - last_state_change > 30) {
            sessions_max = rand() % keys.size();
            if(sessions_max < 100)
                sessions_max = 100;
            last_state_change = now;
        }

        if(now - start > 60*5)
            break;

        // New session
        if(!(rand() % 10)) {
            key = get_rand_key();
            void *d = strdup("data");

            clock_gettime(CLOCK_MONOTONIC, &tstart);
            if(bgh_insert(tracker, &key, d) != BGH_OK) {
                failed_insert++;
                free(d);
            } 
            else {
                insert_total_time += nanos_total(&tstart);
                insert_count++;
            }
        }

        // Lookup
        if(!(rand() % 2)) {
            key = keys[rand() % keys.size()];
            clock_gettime(CLOCK_MONOTONIC, &tstart);
            bgh_lookup(tracker, &key);
            lookup_total_time += nanos_total(&tstart);
            lookup_count++;
            // assert_eq(bgh_lookup(tracker, &key), "data");
        }

        // Clear
        if(!(rand() % 20)) {
            key = get_rand_key();
            bgh_clear(tracker, &key);
        }

        // Replace a key. The old session will timeout
        if(!(rand() % 20)) {
            keys[rand() % sessions_max] = gen_rand_key();
        }

        iteration++;
    }

    bgh_free(tracker);
}

int main(int argc, char **argv) {
    // Make rand repeatable
    srand(1);

    if(argc > 1 && !strcmp(argv[1], "-s")) {
        stress();
        return 0;
    }

    basic();
    linear_probing();
    primes_test();
    drain();
    resize();
    time_draining();
    timeouts();
    bench();

    // TODO: check hash distrib?
    return 0;
}
