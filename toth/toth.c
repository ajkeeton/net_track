/*
 * @author  Adam Keeton <ajkeeton@gmail.com>
 * Copyright (C) 2009-2020 Adam Keeton
 * TCP session tracker, with timeouts
*/

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h> // for AF_INET

#define DEBUG_ASSERT
#ifdef DEBUG_ASSERT
#include <assert.h>
#endif

#include "toth.h"
#include "primes.h"
#include "to.h"
#include "log.h"

// Initialize a config to the defaults
void toth_config_init(toth_config_t *config) {    
    config->timeout = TOTH_DEFAULT_TIMEOUT;
    config->hash_full_pct = TOTH_DEFAULT_HASH_FULL_PCT;

    // Control scaling
    // If the number of inserts > number rows * scale_up_pct
    // Scale up
    config->scale_up_pct = TOTH_DEFAULT_HASH_FULL_PCT * 0.75;
    // If the number of inserts < number rows * scale_down_pct
    // Scale down
    config->scale_down_pct = TOTH_DEFAULT_HASH_FULL_PCT * 0.1;

    int size = prime_at_idx(prime_total()/3); 
    config->max_inserts = size * config->hash_full_pct / 100;

    config->timeout_tables = TOTH_DEFAULT_TIMEOUT_TABLES;

    config->max_col_per_row = TOTH_MAX_COL_PER_ROW;
}

toth_data_t *toth_new_row() {
    return (toth_data_t*)calloc(sizeof(toth_data_t), 1);
};

toth_t *toth_new(void (*free_cb)(void *)) {
    toth_config_t config;
    toth_config_init(&config);
    return toth_config_new(&config, free_cb);
}

toth_t *_toth_new_tbl(uint64_t nrows) {    
    toth_t *tbl = (toth_t*)malloc(sizeof(toth_t));
    if(!tbl)
        return NULL;

    tbl->num_rows = nrows;
    tbl->rows = (toth_data_t**)malloc(sizeof(toth_data_t*) * tbl->num_rows);

    if(!tbl->rows) {
        free(tbl);
        return NULL;
    }

    for(int i=0; i<tbl->num_rows; i++) {
        tbl->rows[i] = toth_new_row();
        if(!tbl->rows[i]) {
            // A row failed to alloc. Delete all up to this point
            for(int j=0; j<i; j++) {
                free(tbl->rows[j]);
            }
            free(tbl);
            return NULL;
        }
    }

    return tbl;
}

toth_t *toth_config_new(toth_config_t *config, void (*free_cb)(void *)) {
    // Ensure sane values
    if(config->timeout == 0)
        config->timeout = TOTH_DEFAULT_TIMEOUT;
    if(config->timeout_tables < 2)
        config->timeout_tables = 2;
    if(config->hash_full_pct < 0 || config->hash_full_pct > 100)
        config->hash_full_pct = TOTH_DEFAULT_HASH_FULL_PCT;

    int size = prime_nearest(config->max_inserts / config->hash_full_pct * 100.0);

    toth_t *t = _toth_new_tbl(size);

    if(!t)
        return NULL;

    memcpy(&t->conf, config, sizeof(*config));

    // Internally we use a sliding window of timeouts with nanosecond resolution
    t->conf.timeout = config->timeout * 1000000000 / (t->conf.timeout_tables - 1);

    t->free_cb = free_cb;
    t->inserted = t->collisions = 0;

    tot_new(t);

    return t;
}

toth_t *toth_new_tbl(uint64_t max, void (*free_cb)(void *)) {
    toth_config_t conf;
    toth_config_init(&conf);
    conf.max_inserts = max;
    return toth_config_new(&conf, free_cb);
}

void toth_free(toth_t *tbl) {
    if(!tbl) 
        return;

    // NOTE: The timeout code clears all the user data and will cleanup collisions
    tot_free(tbl);

    for(int i=0; i<tbl->num_rows; i++) {
        #ifdef DEBUG_ASSERT
        assert(!tbl->rows[i]->key);
        #endif
        free(tbl->rows[i]);
    }

    free(tbl->rows);
    free(tbl);
}

// TODO, convenience func
void toth_key_init4(toth_key_t *key, uint32_t sip, uint16_t sport, 
                    uint32_t dip, uint16_t dport, uint8_t vlan) {
}

// TODO, convenience func
void toth_key_init6(toth_key_t *key, uint32_t sip[4], uint16_t sport, 
                    uint32_t dip[4], uint16_t dport, uint8_t vlan) {
}

// Copy keys
// Family is considered so we don't have to do a full memcpy
toth_key_t *toth_key_alloc_copy(toth_data_t *row, toth_key_t *src) {
    // If there's already a key, just overwrite it
    if(row->key) {
        memcpy(row->key, src, sizeof(*src));
        return row->key;
    }
    
    toth_key_t *dst = (toth_key_t *)malloc(sizeof(toth_key_t));
    if(!dst)
        return NULL;

    if(src->family == AF_INET) {
        dst->sip.v6[0] = src->sip.v6[0];
        dst->dip.v6[0] = src->dip.v6[0];
        dst->sip.v6[1] = 0;
        dst->dip.v6[1] = 0;  
    }
    else {
        dst->sip.v6[0] = src->sip.v6[0];
        dst->dip.v6[0] = src->dip.v6[0];
        dst->sip.v6[1] = src->sip.v6[1];
        dst->dip.v6[1] = src->dip.v6[1];    
    }
    dst->sport = src->sport;
    dst->dport = src->dport;
    dst->vlan = src->vlan;
    dst->family = src->family;

    row->key = dst;
    return row->key;
}

void toth_key_free(toth_t *tbl, toth_data_t *row) {
    free(row->key);
    row->key = NULL;
}

#if 0
void toth_key_set(toth_data_t *row, toth_key_t *key) {
    if(row->key) {
        free(row->key);
        active_keys--;
    }
    row->key = key;
}
#endif

int key_eq(toth_key_t *k1, toth_key_t *k2) {
    if(k1->family == AF_INET) {
        return
            (
                ((k1->sip.v4 == k2->sip.v4) &&
                 (k1->sport == k2->sport) &&
                 (k1->dip.v4 == k2->dip.v4) &&
                 (k1->dport == k2->dport))
                 ||
                ((k1->sip.v4 == k2->dip.v4) &&
                 (k1->sport == k2->dport) &&
                 (k1->dip.v4 == k2->sip.v4) &&
                 (k1->dport == k2->sport))
            ) &&
            k1->vlan == k2->vlan &&
            k1->family == k2->family;
    }

    // IPv6
    return
        (
            ((k1->sip.v6[0] == k2->sip.v6[0]) &&
            (k1->sip.v6[1] == k2->sip.v6[1]) &&
            (k1->sport == k2->sport) &&
            (k1->dip.v6[0] == k2->dip.v6[0]) &&
            (k1->dip.v6[1] == k2->dip.v6[1]) &&
            (k1->dport == k2->dport)) ||

            ((k1->sip.v6[0] == k2->dip.v6[0]) &&
            (k1->sip.v6[1] == k2->dip.v6[1]) &&
            (k1->sport == k2->dport) &&
            (k1->dip.v6[0] == k2->sip.v6[0]) &&
            (k1->dip.v6[1] == k2->sip.v6[1]) &&
            (k1->dport == k2->sport))
        ) &&
        k1->vlan == k2->vlan &&
        k1->family == k2->family;

#if 0
    uint64_t *p1 = (uint64_t*)k1;
    uint64_t *p2 = (uint64_t*)k2;

    return 
        ((p1[0] == p2[0] && p1[1] == p2[1]) ||
        (p1[0] == p2[1] && p1[1] == p2[0])) &&
        k1->vlan == k2->vlan;
#endif
}

// Hash func: XOR32
// Reference: https://www.researchgate.net/publication/281571413_COMPARISON_OF_HASH_STRATEGIES_FOR_FLOW-BASED_LOAD_BALANCING
//static inline uint64_t hash_func(uint64_t mask, toth_key_t *key) {
uint64_t hash_func(uint64_t mask, toth_key_t *key) {
    uint64_t h = (uint64_t)(key->sport * key->dport);
    
    if(key->family == AF_INET)
        h ^= (uint64_t)(key->sip.v4 ^ key->dip.v4);
    else           
        h ^= (uint64_t)(key->sip.v6[0] ^ key->dip.v6[0] ^ key->sip.v6[1] ^ key->dip.v6[1]);

    h *= 1 + key->vlan;

#if 0
    uint64_t h = (uint64_t)(key->sip ^ key->dip) ^
                  (uint64_t)(key->sport * key->dport);
    h *= 1 + key->vlan;
#endif
#if 0
    // XXX Gave similar distribution performance to the above
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, key, sizeof(*key));
    unsigned char digest[16];
    MD5_Final(digest, &c);
    
    uint64_t h = *(uint64_t*)digest;
#endif
    return h % mask;
}

toth_data_t *_lookup(   
        toth_t *tbl, toth_key_t *key, bool alloc_on_collision) {
    uint64_t idx = hash_func(tbl->num_rows, key);
    toth_data_t *row = tbl->rows[idx];

    if(!row->user)
        return row;
    
    if(key_eq(key, row->key)) {
        return row;
    }

    // Collision
    toth_data_t *cur = row->next,
                *prev = row;
    for(int i=1; i < tbl->conf.max_col_per_row + 1; i++) {
        if(!cur) {
            if(!alloc_on_collision)
                return NULL;

            cur = toth_new_row();
            if(!cur)
                // XXX Bad news!
                return NULL;

            tbl->collisions++;
            prev->next = cur;
            cur->prev = prev;
            
            return cur;
        }
        else if(key_eq(key, cur->key)) {
            return cur;
        }

        prev = cur;
        cur = cur->next;
    }

    // No room left for collisions :/
    return NULL;
}

toth_stat_t toth_keyed_insert(toth_t *tbl, toth_key_t *key, void *data) {
    return toth_insert(tbl,
        &key->sip.v4, &key->dip.v4, 
        key->sport, key->dport, 
        key->vlan, key->family,
        data);
}

toth_stat_t toth_insert(toth_t *tbl, 
    uint32_t *sip, uint32_t *dip, 
    uint16_t sport, uint16_t dport, 
    uint8_t vlan, uint8_t family, 
    void *data) {

    if(!data)
        return TOTH_EXCEPTION;
    
    tot_do_timeouts(tbl);

    if(tbl->inserted >= tbl->conf.max_inserts || tot_full(tbl))
        return TOTH_FULL;

    toth_key_t key;
    if(family == AF_INET) {
        key.sip.v6[0] = *sip;
        key.dip.v6[0] = *dip;
        key.sip.v6[1] = 0;
        key.dip.v6[1] = 0;
    }
    else {
        key.sip.v6[0] = ((uint64_t*)sip)[0];
        key.dip.v6[0] = ((uint64_t*)dip)[0];
        key.sip.v6[1] = ((uint64_t*)sip)[1];
        key.dip.v6[1] = ((uint64_t*)dip)[1];
    }
    key.sport = sport;
    key.dport = dport;
    key.vlan = vlan;
    key.family = family;

    toth_data_t *row = _lookup(tbl, &key, true);
    if(!row)
        // NOTE This does not give clear indication if the problem was 
        // collisions
        return TOTH_FULL;
    
    // Handle overwrite
    if(row->user && (row->user != data)) {
        tbl->free_cb(row->user);
        if(!key_eq(row->key, &key)) {
            memcpy(row->key, &key, sizeof(key));
        }

        row->user = data;

        if(tot_refresh(tbl, row) != TOTH_OK) {
            // This should never happen!
            // If it does, we'll silently fail and the session will
            // get timed out sooner than expected
        }
        return TOTH_OK;
    }

    if(!toth_key_alloc_copy(row, &key))
        return TOTH_EXCEPTION;

    tot_insert(tbl, row);

    tbl->inserted++;
    row->user = data;
    
    DEBUG("Inserting %p into table %d\n", data, tbl->to_active);
    return TOTH_OK;
}

void *toth_lookup(toth_t *tbl, toth_key_t *key) {
    toth_data_t *row = _lookup(tbl, key, false);

    if(!row || !row->user)
        return NULL;
    
    tot_refresh(tbl, row);
    return row->user;
}

void toth_remove(toth_t *t, toth_key_t *key) {
    toth_data_t *row = _lookup(t, key, false);
    
    if(!row || !row->user) 
        return;

    tot_remove(t, row);
}

bool toth_full(toth_t *t) {
    return t->inserted >= t->conf.max_inserts;
}

void toth_get_stats(toth_t *t, toth_stats_t *stats) {
    stats->num_rows = t->num_rows;
    stats->inserted = t->inserted;
    stats->collisions = t->collisions;
    stats->max_inserts = t->conf.max_inserts;
}

void toth_do_timeouts(toth_t *t) {
    tot_do_timeouts(t);
}

void toth_do_resize(toth_t *t) {
    float usage = t->inserted / t->num_rows * 100;
    // Current size should already be one of our primes, but just in case 
    // user overrode expected behavior....
    int csize = prime_nearest(t->num_rows);
    int nsize = csize;

    // Size up?
    if(usage > t->conf.scale_up_pct) {
        nsize = prime_larger(csize);
    } 
    // Downsize?
    else if(usage < t->conf.scale_down_pct) {
        nsize = prime_smaller(csize);
    }

    if(nsize == csize)
        return;

// TODO: test cases
#if 0
    toth_config_t conf;
    memcpy(&conf, &t->conf, sizeof(conf));

    conf.max_inserts = nsize / conf.hash_full_pct * 100.0;

    toth_t *nt = toth_config_new(&conf, t->free_cb);

    if(!nt) // Uh oh...
        return;

    tot_copy(nt, t);
    tot_free(t);

    for(int i=0; i<t->num_rows; i++) {
        free(t->rows[i]);
    }

    free(t->rows);

    memcpy(&t->conf, &conf, sizeof(conf));
    t->num_rows = nt->num_rows;
    t->rows = nt->rows;
#endif
}

void toth_randomize_refreshes(toth_t *t, float pct) {
    if(pct > 100 || pct <= 0)
        return;

    int32_t offset = pct / 100.0 * t->conf.timeout;

    t->conf.timeout += rand() % offset - offset / 2;
}

void toth_foreach(toth_t *tbl, void (*cb)(toth_key_t *, void *, void *), void *ctx) {
    for(int i=0; i < tbl->conf.timeout_tables; i++)
        to_foreach(tbl->tos[i], cb, ctx);
}
