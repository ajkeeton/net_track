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
#include <sys/socket.h>
#include "../toth/toth.h"

extern "C" {
toth_data_t *_insert_coll(
        toth_data_t *parent, toth_key_t *key, void *data);
uint64_t time_ns();
int key_eq(toth_key_t *k1, toth_key_t *k2) ;
void tot_do_timeouts(toth_t *tbl);
}

void free_cb(void *p) {
    free(p);
}

void nop_free_cb(void *p) {}

uint32_t allocated = 0;
void count_frees_cb(void *p) {
    allocated--;
    free(p);
}

char *strdup_count(const char *s) {
    allocated++;
    return strdup(s);
}

void assert_eq(void *p, const char *s) {
    assert(!strcmp((char *)p, s));
}

void assert_lookup_eq(toth_t *t,  toth_key_t &key, const char *s) {
    void *d = toth_lookup(t, &key); 
    
    if(!s) {
        assert(!d);
        return;
    }

    assert_eq(d, s);
}

void gen_rand_key(toth_key_t *key) {
    bzero(key, sizeof(*key));

    key->family = rand() & 2 ? AF_INET : AF_INET6;

    key->sport = (uint16_t)rand();
    key->dport = (uint16_t)rand();

    if(key->family == AF_INET6) {
        key->dip.v6[0] = rand();
        key->sip.v6[0] = rand();
        key->dip.v6[1] = rand();
        key->sip.v6[1] = rand();
    }
    else {
        key->dip.v4 = rand();
        key->sip.v4 = rand();
    }
}

void basic(bool use_ipv6 = false) {
    printf("%s, use ipv6: %d\n", __func__, use_ipv6);

    toth_config_t conf;
    toth_config_init(&conf);
    conf.max_inserts = 10;
    conf.hash_full_pct = 50;
    uint64_t sip[2], dip[2];

    int family = AF_INET;
    if(use_ipv6) {
        family = AF_INET6;
    }

    toth_t *tracker = toth_config_new(&conf, free_cb);

    toth_key_t key, key2;
    // Bzero'ing to clean up pad bytes. Needed to prevent valgrind from complaining
    bzero(&key, sizeof(key)); 
    bzero(&key2, sizeof(key2)); 

    key.sip.v4 = 10;
    key.dip.v4 = 200;
    key.sport = 3000;
    key.dport = 5000;
    key.vlan = 5;
    key.family = family;

    // Add three (changing source IP)
    toth_keyed_insert(tracker, &key, strdup("foo"));
    key.sip.v4 = 20;
    toth_keyed_insert(tracker, &key, strdup("bar"));
    key.sip.v4 = 30;
    toth_keyed_insert(tracker, &key, strdup("baz"));

    // Lookup each
    key.sip.v4 = 10;
    assert_lookup_eq(tracker, key, "foo");

    key.sip.v4 = 20;
    assert_lookup_eq(tracker, key, "bar");
    
    key.sip.v4 = 30;
    assert_lookup_eq(tracker, key, "baz");
    key.sip.v4 = 20;

    // Overwrite    
    toth_keyed_insert(tracker, &key, strdup("foobazzybar"));
    assert_lookup_eq(tracker, key, "foobazzybar");

    key.sip.v4 = 30;
    assert_lookup_eq(tracker, key, "baz");

    // Swap source and IP, should get same session data
    key2.dip.v4 = key.sip.v4;
    key2.sip.v4 = key.dip.v4;
    key2.dport = key.sport;
    key2.sport = key.dport;
    key2.vlan = key.vlan;
    key2.family = family;

    assert_lookup_eq(tracker, key2, "baz");

    key.sip.v4 = 20;
    toth_remove(tracker, &key);

    key.sip.v4 = 10;
    // Clear after release ... no boom
    toth_remove(tracker, &key);
    // Can't acquire again
    assert(!toth_lookup(tracker, &key));

    key.sip.v4 = 20;
    toth_remove(tracker, &key);
    assert(!toth_lookup(tracker, &key));
    key.sip.v4 = 30;
    toth_remove(tracker, &key);
    assert(!toth_lookup(tracker, &key));

    toth_free(tracker);
}

void timeouts() {
    printf("%s\n", __func__);

    toth_config_t conf;
    toth_config_init(&conf);
    conf.timeout = 1;
    conf.timeout_tables = 2;
    allocated = 0;

    toth_t *tracker = toth_config_new(&conf, count_frees_cb);

    tracker->conf.timeout = 100000;

    toth_key_t key;
    // Bzero'ing to clean up pad bytes and prevent valgrind from complaining
    bzero(&key, sizeof(key)); 
    key.family = AF_INET;

    ////////////////////////////////////////////////////
    // Add three, but cross the refresh + timeout period

    key.sip.v4 = 1;
    toth_keyed_insert(tracker, &key, strdup_count("1"));
    usleep(150000);
    // the next insert triggers the timeout code ... but it's an empty table since we just started
    key.sip.v4 = 2;
    toth_keyed_insert(tracker, &key, strdup_count("2"));

    // Timeout 1
    usleep(150000);
    key.sip.v4 = 3;
    toth_keyed_insert(tracker, &key, strdup_count("3"));

    assert(tracker->inserted == 2);
    key.sip.v4 = 1;
    assert_lookup_eq(tracker, key, NULL);
    key.sip.v4 = 2;
    assert_lookup_eq(tracker, key, "2");
    key.sip.v4 = 3;
    assert_lookup_eq(tracker, key, "3");

    // Make sure lookups keep entries alive
    usleep(150000);
    
    // forcing timeout code to run without insert
    // active table is moved forward
    tot_do_timeouts(tracker);
    // lookup moves this key to new table
    key.sip.v4 = 2;
    assert_lookup_eq(tracker, key, "2");
    usleep(150000);

    // Force timeouts without an insert
    tot_do_timeouts(tracker);
    assert(tracker->inserted == 1);
    key.sip.v4 = 1;
    assert_lookup_eq(tracker, key, NULL);
    key.sip.v4 = 2;
    assert_lookup_eq(tracker, key, "2");
    key.sip.v4 = 3;
    assert_lookup_eq(tracker, key, NULL);
    usleep(150000);

    // active table moved forward, "2" in old table
    tot_do_timeouts(tracker);
    usleep(150000);
    // "2" timed out
    tot_do_timeouts(tracker);

    key.sip.v4 = 1;
    assert_lookup_eq(tracker, key, NULL);
    key.sip.v4 = 2;
    assert_lookup_eq(tracker, key, NULL);
    assert(tracker->inserted == 0);
    assert(allocated == 0);

    toth_free(tracker);
}

void collisions() {
    printf("%s\n", __func__);

    toth_config_t conf;
    toth_config_init(&conf);
    conf.max_inserts = 50;
    conf.max_col_per_row = 100;
    conf.hash_full_pct = 100; // hack to allow lots of collisions

    toth_t *tracker = toth_config_new(&conf, free_cb);

    toth_key_t key1, key2;
    bzero(&key1, sizeof(key1)); 
    bzero(&key2, sizeof(key2)); 

    key1.family = key2.family = AF_INET;
    key1.sip.v4 = 10;
    key1.dip.v4 = 200;
    key1.sport = 3000;
    key1.dport = 4000; 
    // Same IPs, swapped ports, def a hash collision
    key2.sip.v4 = 10;
    key2.dip.v4 = 200;
    key2.sport = 4000;
    key2.dport = 3000; 

    toth_keyed_insert(tracker, &key1, strdup("foo1"));
    toth_keyed_insert(tracker, &key2, strdup("foo2"));

    assert_lookup_eq(tracker, key1, "foo1");
    assert_lookup_eq(tracker, key2, "foo2");

    toth_remove(tracker, &key2);
    assert_lookup_eq(tracker, key1, "foo1");
    assert_lookup_eq(tracker, key2, NULL);

    // Fuzz
    int num = tracker->conf.max_inserts-2;
    // Override max
    tracker->conf.max_inserts = 10000;
    toth_key_t keys[num];
    memset(&keys, 0, sizeof(keys));

    for(int i=0; i<num; i++) {
        keys[i].family = AF_INET;
        keys[i].sip.v4 = i;
    }

    for(int i=0; i < num; i++) {
        char buf[8];
        sprintf(buf, "%d", i);
        assert(toth_keyed_insert(tracker, &keys[i], strdup(buf)) == TOTH_OK);
    }

    for(int i=0; i < num; i++) {
        char buf[8];
        sprintf(buf, "%d", i);
        assert_lookup_eq(tracker, keys[i], buf);
    }

    // Clear every third 
    for(int i=0; i < num; i += 3) {
        toth_remove(tracker, &keys[i]);
        assert_lookup_eq(tracker, keys[i], NULL);
    }

    // Re-check
    for(int i=0; i < num; i++) {
        char buf[8];
        sprintf(buf, "%d", i);
        if(!(i % 3))
            assert_lookup_eq(tracker, keys[i], NULL);
        else
            assert_lookup_eq(tracker, keys[i], buf);
    }

    toth_free(tracker);
}

struct key_cmp {
    bool operator()(const toth_key_t &k1, const toth_key_t &k2) const {
        if(key_eq(&const_cast<toth_key_t&>(k1), &const_cast<toth_key_t&>(k2)))
            return 0;
            
        return memcmp((void*)&k1, (void*)&k2, sizeof(toth_key_t)) < 0;
    }
};

#define NUM_ITS 8192

void bench() {
    printf("%s\n", __func__);

    toth_config_t conf;
    toth_config_init(&conf);
    conf.max_inserts = 6000101 * .06;

    toth_t *tracker = toth_config_new(&conf, nop_free_cb);
    toth_key_t keys[NUM_ITS];
    memset(&keys, 0, sizeof(keys));

    for(int i=0; i<NUM_ITS; i++) {
        gen_rand_key(&keys[i]);
    }

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t now = 1000000 * tv.tv_sec + tv.tv_usec;

    for(int i=0; i<NUM_ITS; i++) {
        toth_keyed_insert(tracker, &keys[i], (char*)"foo");
    }

    assert(tracker->collisions < 10);

    for(int i=0; i<NUM_ITS*100; i++) {
        char *d = (char*)toth_lookup(tracker, &keys[i % NUM_ITS]);
        assert_eq(d, "foo");
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
    printf("STL map *with no timeout handling*: %f ms\n", float((fin - now))/1000);
}

void resize() {
    printf("%s (not implemented)\n", __func__);

    toth_config_t conf;
    toth_config_init(&conf);
    conf.max_inserts = 100003 * .06;
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
        key.dip.v4 = rand();
        key.sip.v4 = rand();
        key.sport = (uint16_t)rand();
        key.dport = (uint16_t)rand();
        key.family = AF_INET;
        keys[i] = key;
    }

    assert(tracker->active->num_rows == 100003);
    for(int i=0; i<nkeys; i++) 
        toth_keyed_insert(tracker, &keys[i], (char*)"foo");

    sleep(4);
    assert(tracker->active->num_rows == 200003);
    sleep(4);
    assert(tracker->active->num_rows <= 100003);

    toth_free(tracker);
#endif
}

void key_cmp() {
    printf("%s\n", __func__);

    toth_key_t key1, key2;
    bzero(&key1, sizeof(key1));
    bzero(&key2, sizeof(key2));

    key1.family = key2.family = AF_INET6;
    key1.sip.v6[0] = 1;
    key1.sip.v6[1] = 2;
    key1.dip.v6[0] = 3;
    key1.dip.v6[1] = 4;
    key1.sport = 1;
    key1.dport = 2;

    key2.dip.v6[0] = key1.sip.v6[0];
    key2.dip.v6[1] = key1.sip.v6[1];
    key2.sip.v6[0] = key1.dip.v6[0];
    key2.sip.v6[1] = key1.dip.v6[1];
    key2.sport = key1.dport;
    key2.dport = key1.sport;

    assert(key_eq(&key1, &key2));

    key2.dip.v6[1] = 20;

    assert(!key_eq(&key1, &key2));

    key2.dip.v6[1] = key1.sip.v6[1];    
    assert(key_eq(&key1, &key2));

    key2.sport = 1000;
    assert(!key_eq(&key1, &key2));

    key2.sport = key1.dport;
    key2.vlan = 1;
    assert(!key_eq(&key1, &key2));
    key1.vlan = 1;
    assert(key_eq(&key1, &key2));
}

std::vector<toth_key_t> keys;

toth_key_t *get_rand_key() {
    return &(keys[rand() % keys.size()]);
}

#define NUM_KEYS 1024*256
toth_key_t *get_next_key() {
    static int i = 0;
    if(i+1 >= keys.size())
        i = 0;
    return &keys[i++];
}

#define INIT_NUM_ROWS 300043
#define TEST_LENGTH 20 // 60*5

void stress() {
    puts("Starting long-running stress test");

    toth_config_t conf;
    toth_config_init(&conf);
    conf.max_inserts = INIT_NUM_ROWS * .06;
    conf.hash_full_pct = 4.5;
    conf.timeout = 2;

    toth_t *tracker = toth_config_new(&conf, count_frees_cb);
    keys.resize(NUM_KEYS);
    for(int i=0; i<NUM_KEYS; i++) {
        gen_rand_key(&keys[i]);
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
             iteration = 0,
             tstart = 0;

    assert(!allocated);
    while(1) {
        time_t now = time(NULL);
        if(now - last_out > 2) {
            last_out = now;

            toth_stats_t stats;
            toth_get_stats(tracker, &stats);
            // print stats
            printf("\n%lus, iteration %llu. Simulating %d sessions\n",
                    time(NULL) - start, iteration, sessions_max);
            printf("- inserts tried:  %llu\n", insert_count + failed_insert);
            printf("- active:         %llu\n", stats.inserted);
            printf("- allocated:      %llu\n", allocated);
            printf("- lookups:        %llu\n", lookup_count);
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

            puts("Randomizing timeout (5%)");
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
            void *d = strdup_count("data");

            tstart = time_ns();
            if(toth_keyed_insert(tracker, get_next_key(), d) != TOTH_OK) {
                failed_insert++;
                count_frees_cb(d);
            }
            else {
                insert_total_time += time_ns() - tstart;
                insert_count++;
            }
        }

        // Lookup
        if(!(rand() % 2)) {
            tstart = time_ns();
            toth_lookup(tracker, get_rand_key());
            lookup_total_time += time_ns() - tstart;
            lookup_count++;
            // assert_eq(toth_lookup(tracker, &key), "data");
        }

        // Clear
        if(!(rand() % 20)) {
            toth_remove(tracker, get_rand_key());
        }

        // Replace a key. Hack to force an old session to timeout
        if(!(rand() % 10))
            gen_rand_key(&keys[rand() % keys.size()]);

        iteration++;
    }

    assert(allocated);

    // Force everything to time out
    tracker->conf.timeout = 0;
    for(int i=0; i<tracker->conf.timeout_tables; i++)
        tot_do_timeouts(tracker);

    assert(!allocated);
    assert(!tracker->inserted);
    
    toth_free(tracker);
}

extern "C" {
void _to_unlink(toth_to_tbl_t *tot, uint32_t idx);
int32_t _to_append(toth_to_tbl_t *tbl, toth_data_t *d);
toth_data_t *toth_new_row();
}

void to_append_unlink() {
    toth_t *tbl = toth_new(nop_free_cb);

    toth_to_tbl_t *tot0 = tbl->tos[0];
    toth_to_tbl_t *tot1 = tbl->tos[1];

    toth_key_t key;
    bzero(&key, sizeof(key));
    key.family == AF_INET;
    key.sport = 1;

    toth_data_t *d0 = toth_new_row();
    d0->user = d0;
    d0->key = &key;
    d0->to_idx = _to_append(tot0, d0);
    d0->to_tbl = 0;

    toth_data_t *d1 = toth_new_row();
    d1->user = d1;
    d1->key = &key;
    d1->to_idx = _to_append(tot0, d1);
    d1->to_tbl = 0;

    toth_data_t *d2 = toth_new_row();
    d2->user = d2;
    d2->key = &key;
    d2->to_idx = _to_append(tot0, d2);
    d2->to_tbl = 0;

    assert(tot0->head == d0->to_idx);
    assert(tot0->tos[0].next == d1->to_idx);
    assert(tot0->tail == d2->to_idx);

    // Unlink head
    _to_unlink(tot0, d0->to_idx);
    assert(tot0->head == d1->to_idx);
    assert(tot0->tail == d2->to_idx);

    // Move it to other table
    d0->to_tbl = 1;
    d0->to_idx = _to_append(tot1, d0);
    assert(tot1->head == d0->to_idx);
    assert(tot1->tail == d0->to_idx);

    // Unlink tail
    _to_unlink(tot0, d2->to_idx);
    assert(tot0->tail == d1->to_idx);
    // Unlink head
    _to_unlink(tot0, d1->to_idx);
    assert(tot0->tail == -1);
    assert(tot0->head == -1);

    // Remove d0 from the other table
    _to_unlink(tot1, d0->to_idx);

    // Put all 3 in a table
    d2->to_idx = _to_append(tot0, d2);
    assert(tot0->head == d2->to_idx);
    assert(tot0->tail == d2->to_idx);
    d1->to_idx = _to_append(tot0, d1);
    assert(tot0->tail == d1->to_idx);
    assert(tot0->tos[d1->to_idx].prev == d2->to_idx);
    d0->to_idx = _to_append(tot0, d0);
    d0->to_tbl = 0;

    assert(tot0->head == d2->to_idx);
    assert(tot0->tail == d0->to_idx);
    assert(tot0->tos[tot0->head].next == d1->to_idx); // confirm d1 is middle node
    assert(tot0->tos[d1->to_idx].next == d0->to_idx); // d1 next points to tail
    assert(tot0->tos[d1->to_idx].prev == d2->to_idx); // d1 prev points to head

    // Remove the d1, the middle node
    _to_unlink(tot0, d1->to_idx);
    assert(tot0->tos[tot0->head].next == d0->to_idx);
    assert(tot0->tos[tot0->tail].prev == d2->to_idx);

    // Cleanup;
    _to_unlink(tot0, d0->to_idx);
    _to_unlink(tot0, d2->to_idx);
    free(d0); free(d1); free(d2);
    toth_free(tbl);
}

int main(int argc, char **argv) {
    // Make rand() repeatable
    srand(1);

    if(argc > 1 && !strcmp(argv[1], "-s")) {
        stress();
        return 0;
    }

    to_append_unlink();
    basic();
    basic(true); // ipv6

    collisions();
    resize();
    key_cmp();
    timeouts();
    bench();

    // TODO: check hash distrib?
    return 0;
}
