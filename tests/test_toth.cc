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
#include "../toth/toth.h"

extern "C" {
toth_data_t *_insert_coll(
        toth_data_t *parent, toth_key_t *key, void *data);
void tot_do_timeouts(toth_t *tbl);
}

void free_cb(void *p) {
    free(p);
}

void nop_free_cb(void *p) {}

void assert_eq(void *p, const char *s) {
    assert(!strcmp((char *)p, s));
}

void assert_lookup_eq(toth_t *t,  toth_key_t &key, const char *s) {
    toth_data_t *d = toth_acquire(t, &key); 
    
    if(!s) {
        assert(!d);
        return;
    }

    assert_eq(d->user, s);

    toth_release(t, d);
}

void basic() {
    printf("%s\n", __func__);

    toth_config_t conf;
    toth_config_init(&conf);
    conf.starting_rows = 31;
    conf.hash_full_pct = 50;

    toth_t *tracker = toth_config_new(&conf, free_cb);

    toth_key_t key;
    // Bzero'ing to clean up pad bytes. Needed to prevent valgrind from complaining
    bzero(&key, sizeof(key)); 

    key.sip = 10;
    key.dip = 200;
    key.sport = 3000;
    key.dport = 5000;
    key.vlan = 5;

    // Add three (changing source IP)
    toth_insert(tracker, &key, strdup("foo"));
    key.sip = 20;
    toth_insert(tracker, &key, strdup("bar"));
    key.sip = 30;
    toth_insert(tracker, &key, strdup("baz"));

    // Lookup each
    key.sip = 10;
    assert_lookup_eq(tracker, key, "foo");

    key.sip = 20;
    assert_lookup_eq(tracker, key, "bar");
    
    key.sip = 30;
    assert_lookup_eq(tracker, key, "baz");
    key.sip = 20;

    // Overwrite    
    toth_insert(tracker, &key, strdup("foobazzybar"));
    assert_lookup_eq(tracker, key, "foobazzybar");

    key.sip = 30;
    assert_lookup_eq(tracker, key, "baz");

    // Swap source and IP, should get same session data
    toth_key_t key2;
    key2.dip = 30;
    key2.sip = 200;
    key2.dport = 3000;
    key2.sport = 5000;
    key2.vlan = 5;

    assert_lookup_eq(tracker, key2, "baz");

    key.sip = 20;
    toth_remove(tracker, &key);

    key.sip = 10;
    toth_data_t *d = toth_acquire(tracker, &key);
    toth_release(tracker, d);

    // Clear after release ... no boom
    toth_remove(tracker, &key);
    // Can't acquire again
    assert(!toth_acquire(tracker, &key));

    key.sip = 20;
    toth_remove(tracker, &key);
    assert(!toth_acquire(tracker, &key));
    key.sip = 30;
    toth_remove(tracker, &key);
    assert(!toth_acquire(tracker, &key));

    toth_free(tracker);
}

void timeouts() {
    printf("%s\n", __func__);

    toth_config_t conf;
    toth_config_init(&conf);
    conf.timeout = 1;
    conf.timeout_tables = 2;

    toth_t *tracker = toth_config_new(&conf, free_cb);

    tracker->timeout = 500000;

    toth_key_t key;
    // Bzero'ing to clean up pad bytes and prevent valgrind from complaining
    bzero(&key, sizeof(key)); 
    
    // Add three, but cross the refresh + timeout period
    key.sip = 1;
    toth_insert(tracker, &key, strdup("1"));
    usleep(550000);

    // next insert will trigger a timeout but of an empty table since we just started
    key.sip = 2;
    toth_insert(tracker, &key, strdup("2"));

    // Timeout 1
    usleep(550000);

    key.sip = 3;
    assert(toth_insert(tracker, &key, strdup("3")) == TOTH_OK);

    key.sip = 1;
    assert_lookup_eq(tracker, key, NULL);
    key.sip = 2;
    assert_lookup_eq(tracker, key, "2");
    key.sip = 3;
    assert_lookup_eq(tracker, key, "3");

    // Make sure lookups keep entries alive
    usleep(550000);
    // forcing timeout code to run without insert
    tot_do_timeouts(tracker);
    key.sip = 2;
    assert_lookup_eq(tracker, key, "2");

    usleep(550000);
    // NOTE: currently time outs only happen on insert
    // this insert should timeout "bar"
    key.sip = 4;
    toth_insert(tracker, &key, strdup("4"));

    usleep(550000);
    tot_do_timeouts(tracker);

    key.sip = 1;
    assert_lookup_eq(tracker, key, NULL);
    key.sip = 2;
    assert_lookup_eq(tracker, key, NULL);

    toth_free(tracker);
}

void collisions() {
    printf("%s\n", __func__);

    toth_config_t conf;
    toth_config_init(&conf);
    conf.starting_rows = 13;
    conf.max_col_per_row = 100;
    conf.hash_full_pct = 1000; // hack to allow lots of collisions

    toth_t *tracker = toth_config_new(&conf, free_cb);

    toth_key_t key1, key2;
    bzero(&key1, sizeof(key1)); 
    bzero(&key2, sizeof(key2)); 

    key1.sip = 10;
    key1.dip = 200;
    key1.sport = 3000;
    key1.dport = 4000; 
    // Same IPs, swapped ports, def a hash collision
    key2.sip = 10;
    key2.dip = 200;
    key2.sport = 4000;
    key2.dport = 3000; 

    toth_insert(tracker, &key1, strdup("foo1"));
    toth_insert(tracker, &key2, strdup("foo2"));

    assert_lookup_eq(tracker, key1, "foo1");
    assert_lookup_eq(tracker, key2, "foo2");

    toth_remove(tracker, &key2);
    assert_lookup_eq(tracker, key1, "foo1");
    assert_lookup_eq(tracker, key2, NULL);

    // Fuzz
    int num = conf.starting_rows*2;
    toth_key_t keys[num];
    memset(&keys, 0, sizeof(keys));

    toth_key_t key;
    // Bzero'ing to clean up pad bytes and prevent valgrind from complaining
    bzero(&key, sizeof(key)); 

    for(int i=0; i<num; i++) {
        keys[i].sip = i;
    }

    for(int i=0; i < num; i++) {
        char buf[8];
        sprintf(buf, "%d", i);
        assert(toth_insert(tracker, &keys[i], strdup(buf)) == TOTH_OK);
    }

    for(int i=0; i < num; i++) {
        char buf[8];
        sprintf(buf, "%d", i);
        assert_lookup_eq(tracker, keys[i], buf);
    }

    // Clear every third 
    for(int i=0; i < num; i++) {
        if(!(num % 3)) {
            toth_remove(tracker, &keys[i]);
            assert_lookup_eq(tracker, keys[i], NULL);
        }
    }

    // Re-check
    for(int i=0; i < num; i++) {
        char buf[8];
        sprintf(buf, "%d", i);
        if(!(num % 3))
            assert_lookup_eq(tracker, keys[i], NULL);
        else
            assert_lookup_eq(tracker, keys[i], buf);
    }

    // force timeouts
    //tracker->timeout = 0;
    //tot_do_timeouts(tracker);

    toth_free(tracker);
}

struct key_cmp {
    bool operator()(const toth_key_t &k1, const toth_key_t &k2) const {
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

        return memcmp((void*)&k1, (void*)&k2, sizeof(toth_key_t)) < 0;
    }
};

#define NUM_ITS 8192

void bench() {
    printf("%s\n", __func__);

    toth_config_t conf;
    toth_config_init(&conf);
    conf.starting_rows = 6000101;

    toth_t *tracker = toth_config_new(&conf, nop_free_cb);
    toth_key_t keys[NUM_ITS];
    memset(&keys, 0, sizeof(keys));

    toth_key_t key;
    // Bzero'ing to clean up pad bytes and prevent valgrind from complaining
    bzero(&key, sizeof(key)); 

    for(int i=0; i<NUM_ITS; i++) {
        key.dip = i;
        key.sip = rand();
        key.sport = (uint16_t)rand();
        key.dport = (uint16_t)rand();
        keys[i] = key;
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t now = 1000000 * tv.tv_sec + tv.tv_usec;

    for(int i=0; i<NUM_ITS; i++) {
        toth_insert(tracker, &keys[i], (char*)"foo");
    }

    assert(tracker->collisions < 10);

    for(int i=0; i<NUM_ITS*100; i++) {
        toth_data_t *d = toth_acquire(tracker, &keys[i % NUM_ITS]);
        assert(d);
        toth_release(tracker, d);
    }

    for(int i=0; i<NUM_ITS; i++) 
        toth_remove(tracker, &keys[i]);

    gettimeofday(&tv, NULL);
    uint64_t fin = 1000000 * tv.tv_sec + tv.tv_usec;
    printf("%d inserts, deletes, %d lookups: %f ms, %d collisions for %d rows\n", 
        NUM_ITS, NUM_ITS*100, float((fin - now))/1000, 
        tracker->collisions, tracker->num_rows);

    toth_free(tracker);

    /////////////////////////
    // The STL map comparison
    // XXX No timeouts! It obviously has a performance advantage
    std::map<toth_key_t, char *, key_cmp> tree;
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
    printf("STL map (*no timeout handling*): %f ms\n", float((fin - now))/1000);
}

void resize() {
    printf("%s (not implemented)\n", __func__);

    toth_config_t conf;
    toth_config_init(&conf);
    conf.starting_rows = 100003;
    conf.timeout = 1;

#if 0
    toth_t *tracker = toth_config_new(&conf, nop_free_cb);

    int nkeys = conf.starting_rows / 4;
    toth_key_t keys[nkeys];
    memset(&keys, 0, sizeof(keys));

    toth_key_t key;
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
        toth_insert(tracker, &keys[i], (char*)"foo");

    sleep(4);
    assert(tracker->active->num_rows == 200003);
    sleep(4);
    assert(tracker->active->num_rows <= 100003);

    toth_free(tracker);
#endif
}

std::vector<toth_key_t> keys;

toth_key_t gen_rand_key() {
    toth_key_t key;
    bzero(&key, sizeof(key));  // for valgrind
    key.sport = (uint16_t)rand();
    key.dport = (uint16_t)rand();
    key.sip = rand();
    key.dip = rand();
    return key;
}

toth_key_t get_rand_key() {
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

#define INIT_NUM_ROWS 600101
#define NUM_KEYS 1024*512
#define TEST_LENGTH 60*5

void stress() {
    puts("Starting long-running stress test");

    toth_config_t conf;
    toth_config_init(&conf);
    conf.starting_rows = INIT_NUM_ROWS;
    conf.timeout = 4;

    toth_t *tracker = toth_config_new(&conf, free_cb);

    for(int i=0; i<NUM_KEYS; i++) {
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
        toth_key_t key;

        time_t now = time(NULL);
        if(now - last_out > 2) {
            last_out = now;

            toth_stats_t stats;
            toth_get_stats(tracker, &stats);
            // print stats
            printf("\n%lus, iteration %llu. Simulating %d sessions\n",
                    time(NULL) - start, iteration, sessions_max);
            printf("- inserted:       %llu\n", stats.inserted);
            printf("- collisions:     %llu\n", stats.collisions);
            printf("- table size:     %llu\n", stats.num_rows);
            printf("- failed inserts: %llu\n", failed_insert);
            printf("- %% used:         %.1f\n", (float)stats.inserted / stats.num_rows * 100);
            printf("- Lookup time avg: %llu ns\n", lookup_total_time/lookup_count);
            if(!insert_count)
                puts("- No successful inserts");
            else
                printf("- Insert time avg: %llu ns\n", insert_total_time/insert_count);

            failed_insert = 0;
            lookup_total_time = 0;
            lookup_count = 1,
            insert_total_time = 0;
            insert_count  = 1;

            toth_randomize_refreshes(tracker, 5);
        }

        if(now - last_state_change > 30) {
            sessions_max = rand() % keys.size();
            if(sessions_max < NUM_KEYS)
                sessions_max = NUM_KEYS;
            last_state_change = now;
        }

        if(now - start > TEST_LENGTH)
            break;

        // New session
        if(!(rand() % 10) || !insert_count) {
            key = get_rand_key();
            void *d = strdup("data");

            clock_gettime(CLOCK_MONOTONIC, &tstart);
            if(toth_insert(tracker, &key, d) != TOTH_OK) {
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
            toth_release(tracker, toth_acquire(tracker, &key));
            lookup_total_time += nanos_total(&tstart);
            lookup_count++;
            // assert_eq(toth_lookup(tracker, &key), "data");
        }

        // Clear
        if(!(rand() % 20)) {
            key = get_rand_key();
            toth_remove(tracker, &key);
        }

        // Replace a key. The old session will timeout
        if(!(rand() % 20)) {
            keys[rand() % sessions_max] = gen_rand_key();
        }

        iteration++;
    }

    toth_free(tracker);
}

int main(int argc, char **argv) {
    // Make rand repeatable
    srand(1);

    if(argc > 1 && !strcmp(argv[1], "-s")) {
        stress();
        return 0;
    }

    basic();
    collisions();
    resize();
    timeouts();
    bench();

    // TODO: check hash distrib?
    return 0;
}
