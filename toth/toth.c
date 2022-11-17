/*
 * @author  Adam Keeton <ajkeeton@gmail.com>
 * Copyright (C) 2009-2020 Adam Keeton
 * TCP session tracker, with timeouts. Uses a "blue-green" mechanism for 
 * timeouts and automatic hash resizing
*/

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include "toth.h"
#include "primes.h"
#include "to.h"

void toth_config_init(toth_config_t *config) {
    int len = prime_total();

    config->starting_rows = prime_at_idx(len/3); 
    config->timeout = TOTH_DEFAULT_TIMEOUT;
    config->hash_full_pct = TOTH_DEFAULT_HASH_FULL_PCT;

    // Control scaling
    // If the number of inserts > number rows * scale_up_pct
    // Scale up
    config->scale_up_pct = TOTH_DEFAULT_HASH_FULL_PCT * 0.75;
    // If the number of inserts < number rows * scale_down_pct
    // Scale down
    config->scale_down_pct = TOTH_DEFAULT_HASH_FULL_PCT * 0.1;

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

toth_t *toth_new_tbl(uint64_t rows, uint64_t max_inserts, void (*free_cb)(void *)) {
    toth_t *tbl = (toth_t*)malloc(sizeof(toth_t));
    if(!tbl)
        return NULL;

    tbl->num_rows = rows;
    tbl->rows = (toth_data_t**)malloc(sizeof(toth_data_t*) * tbl->num_rows);

    if(!tbl->rows) {
        free(tbl);
        return NULL;
    }

    for(int i=0; i<tbl->num_rows; i++) {
        tbl->rows[i] = toth_new_row();
        if(!tbl->rows[i]) {
            // A row failed to alloc. Delete all up to this point
            for(int j=0; j<i; j++)
                free(tbl->rows[j]);
            free(tbl);
            return NULL;
        }
    }

    tbl->free_cb = free_cb;
    tbl->inserted = tbl->collisions = 0;
    tbl->max_inserts = max_inserts;
    tbl->conf.timeout = ((uint64_t)TOTH_DEFAULT_TIMEOUT) * 100000000;
    tbl->conf.timeout_tables = TOTH_DEFAULT_TIMEOUT_TABLES;

    tot_new(tbl);

    return tbl;
}

toth_t *toth_config_new(toth_config_t *config, void (*free_cb)(void *)) {
    toth_t *t = toth_new_tbl(
        config->starting_rows, 
        config->starting_rows * config->hash_full_pct/100.0, 
        free_cb);

    if(!t)
        return NULL;

    if(t->conf.timeout_tables < 2)
        t->conf.timeout_tables = 2;

    t->conf.timeout = config->timeout * 1000000000 / (t->conf.timeout_tables - 1);

    if(t->conf.timeout_tables != config->timeout_tables) {
        // just re-init to correct size
        tot_free(t);
        t->conf.timeout_tables = config->timeout_tables;
        tot_new(t);
    }

    t->conf.max_col_per_row = config->max_col_per_row;
    return t;
}

void toth_free(toth_t *tbl) {
    if(!tbl) 
        return;

    // NOTE: The timeout code clears all the user data and will cleanup collisions
    tot_free(tbl);

    for(int i=0; i<tbl->num_rows; i++) {
        free(tbl->rows[i]);
    }

    free(tbl->rows);
    free(tbl);
}

static inline int key_eq(toth_key_t *k1, toth_key_t *k2) {
    uint64_t *p1 = (uint64_t*)k1;
    uint64_t *p2 = (uint64_t*)k2;

    return 
        ((p1[0] == p2[0] && p1[1] == p2[1]) ||
        (p1[0] == p2[1] && p1[1] == p2[0])) &&
        k1->vlan == k2->vlan;
}

// Hash func: XOR32
// Reference: https://www.researchgate.net/publication/281571413_COMPARISON_OF_HASH_STRATEGIES_FOR_FLOW-BASED_LOAD_BALANCING
//static inline uint64_t hash_func(uint64_t mask, toth_key_t *key) {
uint64_t hash_func(uint64_t mask, toth_key_t *key) {
#if 1
    uint64_t h = (uint64_t)(key->sip ^ key->dip) ^
                  (uint64_t)(key->sport * key->dport);
    h *= 1 + key->vlan;
#else
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
    
    if(key_eq(key, &row->key)) {
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
        else if(key_eq(key, &cur->key)) {
            return cur;
        }

        prev = cur;
        cur = cur->next;
    }

    // No room left for collisions :/
    return NULL;
}

// NOTE: Insert will overwrite any existing user data using the same key
toth_data_t *_toth_insert(toth_t *tbl, toth_key_t *key, void *data, toth_stat_t *stat) {
    // null data is not allowed
    // the user data pointer is used to check if a row is used
    if(!data || !key) {
        *stat = TOTH_EXCEPTION;
        return NULL;
    }

    // XXX Handle this case better ...
    // - should allow overwrites
    // - use to influence the size of the next hash table
    if(tbl->inserted > tbl->max_inserts) {
        *stat = TOTH_FULL;
        return NULL;
    }

    tot_do_timeouts(tbl);

    toth_data_t *row = _lookup(tbl, key, true);

    if(!row) {
        *stat = TOTH_FULL;
        return NULL;
    }

    // Check if overwrite
    if(row->user && row->user != data) {
        tbl->free_cb(row->user);
        row->user = data;
        tot_refresh(tbl, row);
        return row;
    }
    
    if(tot_insert(tbl, row) != TOTH_OK) {
        if(row->prev) { 
            // this was a collision. we failed to insert into the TO table. .. free up. 
            // XXX this condition should never happen
            row->prev->next = row->next;
            row->next->prev = row->prev;
            free(row);
            tbl->collisions--;
        }

        *stat = TOTH_FULL;
        return NULL;
    }

    memcpy(&row->key, key, sizeof(row->key));
    tbl->inserted++;
    row->user = data;
    
    // printf("Inserting %s into table %d\n", (char*)data, tbl->to_active);
    return row;
}

toth_stat_t toth_insert(toth_t *tbl, toth_key_t *key, void *data) {
    toth_stat_t stat = TOTH_OK;
    _toth_insert(tbl, key, data, &stat);
    return stat;
}

// TODO change to:
// toth_stat_t toth_insert_acquire(toth_t *tbl, toth_key_t *key, void *data, toth_data_t **ret) {
// and make _toth_insert return approp toth_stat_t instead
toth_data_t *toth_insert_acquire(toth_t *tbl, toth_key_t *key, void *data) {
    toth_stat_t stat = TOTH_OK;
    return _toth_insert(tbl, key, data, &stat);
}

toth_data_t *toth_acquire(toth_t *tbl, toth_key_t *key) {
    toth_data_t *row = _lookup(tbl, key, false);

    if(!row || !row->user)
        return NULL;
    
    tot_refresh(tbl, row);
    return row;
}

// NOP - left for API compatibility
void toth_release(toth_t *t, toth_data_t *row) { }

void toth_remove(toth_t *t, toth_key_t *key) {
    toth_data_t *row = _lookup(t, key, false);
    
    if(!row || !row->user) 
        return;

    tot_remove(t, row);
}

void toth_get_stats(toth_t *t, toth_stats_t *stats) {
    stats->num_rows = t->num_rows;
    stats->inserted = t->inserted;
    stats->collisions = t->collisions;
    stats->max_inserts = t->max_inserts;
}

void toth_do_timeouts(toth_t *t) {
    tot_do_timeouts(t);
}

void toth_do_resize(toth_t *t) {
    // Need tests
    #if 0
    float usage = t->inserted / t->num_rows * 100;
    int csize = prime_nearest_idx(t->num_rows);
    int nsize = csize;

    // Size up?
    if(usage > t->conf.scale_up_pct) {
        nsize = prime_larger_idx(csize);
    } 
    // Downsize?
    else if(usage < t->conf.scale_down_pct) {
        nsize = prime_smaller_idx(csize);
    }

    if(nsize == csize)
        return;

    toth_config_t conf;
    memcpy(&conf, &t->conf, sizeof(conf));
    conf.starting_rows = nsize;

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
    t->max_inserts = nt->max_inserts;
    t->rows = nt->rows;
    #endif
}

void toth_randomize_refreshes(toth_t *t, float pct) {
    if(pct > 100 || pct <= 0)
        return;

    int32_t offset = pct / 100.0 * t->conf.timeout;

    t->conf.timeout += rand() % offset - offset / 2;
}