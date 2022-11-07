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

uint64_t time_ns() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000000000 + now.tv_nsec;
}

void toth_config_init(toth_config_t *config) {
    int len = prime_total();

    config->starting_rows = prime_at_idx(len/3); 
    config->min_rows = prime_at_idx(0);
    config->max_rows = prime_at_idx(len);
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
    tbl->timeout = ((uint64_t)TOTH_DEFAULT_TIMEOUT) * 100000000;

    tbl->to_num_tables = TOTH_DEFAULT_TIMEOUT_TABLES;
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

    t->timeout = config->timeout * 1000000000;
    t->timeout_swap = t->timeout / t->to_num_tables;
    
    if(t->to_num_tables != config->timeout_tables) {
        // just re-init to correct size
        tot_free(t);
        t->to_num_tables = config->timeout_tables;
        tot_new(t);
    }

    t->max_col_per_row = config->max_col_per_row;
    return t;
}

void toth_free(toth_t *tbl) {
    if(!tbl) 
        return;

    // NOTE: The timeout code clears all the user data
    tot_free(tbl);

    for(int i=0; i<tbl->num_rows; i++) {
        free(tbl->rows[i]);
        //toth_data_t *row = tbl->rows[i],
        //            *next = tbl->rows[i]->next,
        //            *nn = NULL;
        //while(next) {
        //    nn = next->next;
        //    free(next);
        //    next = nn;
        //}
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
        toth_t *tbl, toth_key_t *key, uint32_t *idx, uint8_t *col_idx, 
        bool alloc_on_collision) {
    *idx = hash_func(tbl->num_rows, key);
    toth_data_t *row = tbl->rows[*idx];
    *col_idx = 0;

    if(!row->user)
        return row;
    
    if(key_eq(key, &row->key)) {
        return row;
    }

    // Collision
    toth_data_t *cur = row->next,
                *prev = row;
    for(int i=1; i < tbl->max_col_per_row; i++) {
        if(!cur) {
            *col_idx = i;
            
            if(alloc_on_collision) {
                cur = toth_new_row();
                if(!cur)
                    // XXX Bad news!
                    return NULL;

                tbl->collisions++;
                prev->next = cur;
                cur->prev = prev;
            }

            return cur;
        }
        else if(key_eq(key, &cur->key)) {
            *col_idx = i;
            return cur;
        }

        prev = cur;
        cur = cur->next;
    }

    // No room left for collisions :/
    return NULL;
}

// NOTE: Insert will overwrite any existing user data using the same key
toth_data_t *_toth_insert(toth_t *tbl, toth_key_t *key, void *data) {
    // null data is not allowed
    // the user data pointer is used to check if a row is used
    if(!data)
        return NULL;

    // XXX Handle this case better ...
    // - should allow overwrites
    // - use to influence the size of the next hash table
    if(tbl->inserted > tbl->max_inserts)
        return NULL;

    tot_do_timeouts(tbl);

    uint32_t idx;
    uint8_t col_idx;

    toth_data_t *row = _lookup(tbl, key, &idx, &col_idx, true);

    if(!row) {
        return NULL;
    }

    // Check if overwrite
    if(row->user && row->user != data) {
        tbl->free_cb(row->user);
        row->user = data;
        tot_refresh(tbl, row);
        return row;
    }
    else {
        tbl->inserted++;
        row->user = data;
    }

    if(tot_insert(tbl, row) != TOTH_OK) {
        if(row->prev) { 
            // this was a collision. we failed to insert into the TO table. .. free up. 
            // XXX this condition should never happen
            row->prev->next = row->next;
            free(row);
            tbl->collisions--;
        }
        return NULL;
    }

    memcpy(&row->key, key, sizeof(row->key));

    // printf("Inserting %s into table %d\n", (char*)data, tbl->to_active);
    return row;
}

toth_stat_t toth_insert(toth_t *tbl, toth_key_t *key, void *data) {
    // Require data
    if(!data)
        return TOTH_EXCEPTION;

    if(!_toth_insert(tbl, key, data))
        return TOTH_EXCEPTION;

    return TOTH_OK;
}

// TODO change to:
// toth_stat_t toth_insert_acquire(toth_t *tbl, toth_key_t *key, void *data, toth_data_t **ret) {
// and make _toth_insert return approp toth_stat_t instead
toth_data_t *toth_insert_acquire(toth_t *tbl, toth_key_t *key, void *data) {
    // Required
    if(!data)
        return NULL;

    return _toth_insert(tbl, key, data);
}

toth_data_t *toth_acquire(toth_t *tbl, toth_key_t *key) {
    uint8_t col_idx = 0;
    uint32_t data_idx = 0;
    toth_data_t *row = _lookup(tbl, key, &data_idx, &col_idx, false);

    if(!row || !row->user)
        return NULL;
    
    tot_refresh(tbl, row);
    return row;
}

// NOP - left for API compatibility
void toth_release(toth_t *tbl, toth_data_t *row) { }

void toth_remove(toth_t *tbl, toth_key_t *key) {
    uint8_t col_idx = 0;
    uint32_t data_idx = 0;

    toth_data_t *row = _lookup(tbl, key, &data_idx, &col_idx, false);
    
    if(!row || !row->user) 
        return;

    tot_remove(tbl, row);
}

void toth_get_stats(toth_t *tbl, toth_stats_t *stats) {
    stats->num_rows = tbl->num_rows;
    stats->inserted = tbl->inserted;
    stats->collisions = tbl->collisions;
    stats->max_inserts = tbl->max_inserts;
}

void toth_do_timeouts(toth_t *tbl) {
    tot_do_timeouts(tbl);
}

void toth_do_resize(toth_t *tbl) {
#warning resize not implemented
}

void toth_randomize_refreshes(toth_t *tracker, float pct) {
#warning todo 
}