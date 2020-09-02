/*
 * @author  Adam Keeton <ajkeeton@gmail.com>
 * Copyright (C) 2009-2020 Adam Keeton
 * TCP session tracker, with timeouts. Uses a "blue-green" mechanism for 
 * timeouts and automatic hash resizing
*/

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include "bgh.h"
#include "primes.h"

void bgh_config_init(bgh_config_t *config) {
    int len = prime_total();

    config->starting_rows = prime_at_idx(len/3); 
    config->min_rows = prime_at_idx(0);
    config->max_rows = prime_at_idx(len);
    config->timeout = BGH_DEFAULT_TIMEOUT;
    config->refresh_period = BGH_DEFAULT_REFRESH_PERIOD;
    config->hash_full_pct = BGH_DEFAULT_HASH_FULL_PCT;

    // Control scaling
    // If the number of inserts > number rows * scale_up_pct
    // Scale up
    config->scale_up_pct = BGH_DEFAULT_HASH_FULL_PCT * 0.75;
    // If the number of inserts < number rows * scale_down_pct
    // Scale down
    config->scale_down_pct = BGH_DEFAULT_HASH_FULL_PCT * 0.1;
}

void bgh_randomize_refreshes(bgh_t *b, float pct) {
    int32_t offset = pct / 100.0 * b->config.refresh_period;

    if(pct <= 0)
        return;

    if(!offset)
        offset = 3; // This will randomize us +/- 1

    b->config.refresh_period += rand() % offset - offset / 2;
    if(b->config.refresh_period <= 0) {
        b->config.refresh_period = 1;
    }
}

bgh_data_t *bgh_new_row() {
    bgh_data_t *row = (bgh_data_t*)calloc(sizeof(bgh_data_t), 1);
    if(!row)
        return NULL;

    return row;
};

bgh_t *bgh_new(void (*free_cb)(void *)) {
    bgh_config_t config;
    bgh_config_init(&config);

    return bgh_config_new(&config, free_cb);
}

void bgh_free_table(bgh_tbl_t *tbl) {
    for(int i=0; i<tbl->num_rows; i++) {
        bgh_data_t *r = tbl->rows[i];
        if(r->user) {
            if(r->ref_count < 1) {
                tbl->free_cb(r->user);
                free(r);
            }
            else {
                // Will free the row when it's released
                // Hopefully the user hasn't lost the pointer...
                r->no_parent_tbl = true;
            }
        }
        else
            free(r);
    }

    free(tbl->rows);
    free(tbl);
}

bgh_tbl_t *bgh_new_tbl(uint64_t rows, uint64_t max_inserts, void (*free_cb)(void *)) {
    bgh_tbl_t *tbl = (bgh_tbl_t*)malloc(sizeof(bgh_tbl_t));
    if(!tbl)
        return NULL;

    tbl->num_rows = rows;
    tbl->rows = (bgh_data_t**)malloc(sizeof(bgh_data_t) * tbl->num_rows);

    if(!tbl->rows) {
        free(tbl);
        return NULL;
    }

    for(int i=0; i<tbl->num_rows; i++) {
        tbl->rows[i] = bgh_new_row();
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
    return tbl;
}

uint64_t _update_size(bgh_config_t *config, int *idx, bgh_tbl_t *tbl) {
    // TODO: incorporate a timeout

    // printf("Sizing: %lu > %f ? Max inserts: %lu\n", 
    //       tbl->inserted, tbl->num_rows * config->scale_up_pct/100.0, tbl->max_inserts);

    uint64_t next = 0;
    if(config->scale_up_pct > 0 && (tbl->inserted > tbl->num_rows * config->scale_up_pct/100.0)) {
        next = prime_larger_idx(*idx);
        if(next > config->max_rows)
            return config->max_rows;
        (*idx)++;
        return next;
    }

    if(tbl->inserted < tbl->num_rows * config->scale_down_pct/100.0) {
        next = prime_smaller_idx(*idx);
        if(next < config->min_rows)
            return config->min_rows;
        (*idx)--;
        return next;
    }

    return tbl->num_rows;
}

static inline void _clear_table(bgh_tbl_t *tbl) {
    for(int i=0; i<tbl->num_rows; i++) {
        bgh_data_t *r = tbl->rows[i];

        if(!r->user || r->ref_count > 0) 
            continue;

        // If ref count > 0, don't delete, just leave in table
        tbl->free_cb(r->user);

        r->user = NULL;
        r->deleted = false;
        tbl->inserted--;
    }

    tbl->collisions = 0;
}

static void *refresh_thread(void *ctx) {
    bgh_t *ssns = (bgh_t*)ctx;
    time_t last = 0;

    last = time(NULL);

    int pindex = prime_nearest_idx(ssns->config.starting_rows);

    while(ssns->running) {
        time_t now = time(NULL);

        // See if we should begin building a new table yet
        if(now - last < ssns->config.refresh_period) {
            usleep(50000); // 50 ms
            continue;
        }

        last = now;
        
        // Calc new hash size
        uint64_t nrows = _update_size(&ssns->config, &pindex, ssns->active);

        if(ssns->standby && nrows == ssns->standby->num_rows)
            // Just re-use this table
            _clear_table(ssns->standby);
        else {
            if(ssns->standby) bgh_free_table(ssns->standby);

            uint64_t max_inserts = nrows * ssns->config.hash_full_pct/100.0;
            // Create new hash
            ssns->standby = bgh_new_tbl(nrows, max_inserts, ssns->active->free_cb);
        }

        if(!ssns->standby) {
            // XXX Need way to handle/report this case gracefully
            // For now, just do-over
            continue;
        }

        ssns->refreshing = true;

        // When we're refreshing, all new sessions go into the new table
        // Lookups are tried on both, if the first lookup fails. When a 
        // lookup succeeds on the active (and about to be replaced) table, 
        // the data is removed from that table and inserted in the standby table
        sleep(ssns->config.timeout);

        bgh_tbl_t *old = ssns->active;

        // Swap to the new table
        pthread_mutex_lock(&ssns->lock);
        ssns->active = ssns->standby;
        ssns->refreshing = false;
        pthread_mutex_unlock(&ssns->lock);

        ssns->standby = old;
    }

    return NULL;
}

bgh_t *bgh_config_new(bgh_config_t *config, void (*free_cb)(void *)) {
    bgh_t *table = (bgh_t*)malloc(sizeof(bgh_t));
    if(!table)
        return NULL;

    table->config = *config;

    table->active = bgh_new_tbl(
        config->starting_rows, 
        config->starting_rows * config->hash_full_pct/100.0, 
        free_cb);

    table->standby = NULL;

    if(config->refresh_period > 0)
        table->running = true;
    else
        table->running = false;

    table->refreshing = false;
    pthread_mutex_init(&table->lock, NULL);

    pthread_create(&table->refresh, NULL, refresh_thread, table);

    return table;
}

void bgh_free(bgh_t *tbl) {
    if(!tbl) return;

    tbl->running = false;
    pthread_join(tbl->refresh, NULL);
    pthread_mutex_destroy(&tbl->lock);

    bgh_free_table(tbl->active);
    if(tbl->standby)
        bgh_free_table(tbl->standby);
    free(tbl);
}

static inline int key_eq(bgh_key_t *k1, bgh_key_t *k2) {
    uint64_t *p1 = (uint64_t*)k1;
    uint64_t *p2 = (uint64_t*)k2;

    return 
        ((p1[0] == p2[0] && p1[1] == p2[1]) ||
        (p1[0] == p2[1] && p1[1] == p2[0])) &&
        k1->vlan == k2->vlan;
}

// Hash func: XOR32
// Reference: https://www.researchgate.net/publication/281571413_COMPARISON_OF_HASH_STRATEGIES_FOR_FLOW-BASED_LOAD_BALANCING
//static inline uint64_t hash_func(uint64_t mask, bgh_key_t *key) {
uint64_t hash_func(uint64_t mask, bgh_key_t *key) {
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

int64_t _lookup_idx(bgh_tbl_t *table, bgh_key_t *key) {
    int64_t idx = hash_func(table->num_rows, key);
    bgh_data_t *row = table->rows[idx];

    // If nothing is/was stored here, just return it anyway.
    // We'll check later
    // The check for "deleted" is to deal with the case where there was 
    // previously a collision
    if((!row->user && !row->deleted) || key_eq(key, &row->key))
        return idx;

    // There was a collision. Use linear probing
    //  NOTE: 
    //  - while draining or on _clear, we set data to null
    //  - if there had been a collision, we still need to be able to reach the
    //    collided node
    //  - "deleted" is used to handle that case

    uint64_t collisions = 0;
    uint64_t start = idx++;
    while(idx != start) {
        collisions++;

        //printf("%llu vs %llu\n", 
        //        hash_func(table->num_rows, &table->rows[start]->key),
        //        hash_func(table->num_rows, key));

        if(idx >= table->num_rows)
            idx = 0;

        bgh_data_t *row = table->rows[idx];

        if(key_eq(key, &row->key)) {
            // Intentionally ignoring the collision count here. Otherwise, we 
            // wind up counting extra collisions every time we look up this row
            return idx;
        }

        if(!row->user && !row->deleted) {
            table->collisions += collisions;
            return idx;
        }

        idx++;
    }

    return -1;
}

bgh_data_t *_lookup_row(bgh_tbl_t *table, bgh_key_t *key) {
    int64_t idx = hash_func(table->num_rows, key);
    bgh_data_t *row = table->rows[idx];

    if(key_eq(key, &row->key))
        return row;

    // If nothing is/was stored here, just return it anyway.
    // We'll check later
    // The check for 'deleted' is to handle the case where
    // a collided row was moved
    if(!row->user && !row->deleted)
        return row;

    uint64_t start = idx++;
    while(idx != start) {
        if(idx >= table->num_rows)
            idx = 0;

        bgh_data_t *row = table->rows[idx];

        if(key_eq(key, &row->key)) {
            // Intentionally ignoring the collision count here. Otherwise, we 
            // wind up counting extra collisions every time we look up this row
            return row;
        }

        if(!row->user && !row->deleted) {
            return row;
        }

        idx++;
    }

    return NULL;
}

bgh_data_t *_bgh_insert_table(bgh_tbl_t *tbl, bgh_key_t *key, void *data) { 
    // XXX Handle this case better ...
    // - should allow overwrites
    // - use to influence the size of the next hash table
    if(tbl->inserted > tbl->max_inserts)
        return NULL;

    int64_t idx = _lookup_idx(tbl, key);

    if(idx < 0)
        return NULL;

    bgh_data_t *nrow = tbl->rows[idx];

    if(!nrow->user)
        tbl->inserted++;
    else if(nrow->ref_count < 1)
        tbl->free_cb(nrow->user);
    
    // else... Ref count is non zero.
    // Something is using it. Treating it as user error

    nrow->ref_count = 0;
    nrow->deleted = false;
    memcpy(&nrow->key, key, sizeof(nrow->key));
    nrow->user = data;

    return nrow;
}

// NOTE: Insert will overwrite any existing user data using the same key
bgh_data_t *bgh_insert(bgh_t *tbl, bgh_key_t *key, void *data) {
    // null data is not allowed
    // the user data pointer is used to check if a row is used
    if(!data)
        return NULL;

    pthread_mutex_lock(&tbl->lock);
    if(tbl->refreshing) {
        // First check if it's in the active table. If so, move it to standby
        int idx = _lookup_idx(tbl->active, key);
        if(idx > -1) {
            bgh_data_t *row = tbl->active->rows[idx];

            // If the pointer differs, delete if ref count is < 2
            // a ref_count of 1 is allowed since that just means we currently
            // have one in use.. which makes sense
            //
            // NOTE: this calls the delete callback... user better be done with
            // the old one
            if(row->user && row->user != data && row->ref_count < 2) {
                tbl->active->free_cb(row->user);
                tbl->active->rows[idx]->user = NULL;
            }
            else
                // User tried to overwrite old data with something new, but
                // multiple things held the old data (in terms of ref count)
                // This is invalid. To prevent crashes, just insert the new
                // data into the standby table.

                // Any future lookups during the refresh that go to the active 
                // table first will return the old data. It will then overwrite
                // the new data in the standby table
                {}
        }
        bgh_data_t *ret = _bgh_insert_table(tbl->standby, key, data);
        pthread_mutex_unlock(&tbl->lock);
        return ret;
    }
    pthread_mutex_unlock(&tbl->lock);
    return _bgh_insert_table(tbl->active, key, data);
}

bgh_data_t *bgh_insert_acquire(bgh_t *tbl, bgh_key_t *key, void *data) {
    bgh_data_t *ret = bgh_insert(tbl, key, data);
    if(!ret)
        return NULL;
    ret->ref_count++;
    return ret;
}

static inline bgh_data_t *_move_tables(
        bgh_tbl_t *active, bgh_tbl_t *standby, bgh_key_t *key, bgh_data_t *row) {            
    bgh_data_t *nrow = _bgh_insert_table(standby, key, row->user);
    if(!nrow) {
        // We failed to insert it into the new table
        return NULL; // this makes sure it still gets deleted correctly later
    }

    active->inserted--;
    row->ref_count = 0;
    row->user = NULL;
    row->deleted = true; // this is necessary to handle the case where there 
                         // was a previous collision with this row

    return nrow;
}

bgh_data_t *_draining_lookup_active(
        bgh_tbl_t *active, bgh_tbl_t *standby, bgh_key_t *key) {
    bgh_data_t *row = _lookup_row(active, key);
    if(!row || !row->user)
        return _lookup_row(standby, key);

    // Row was found in the active table. Move to standby
    return _move_tables(active, standby, key, row);
}

bgh_data_t *_draining_prefer_standby(
        bgh_tbl_t *active, bgh_tbl_t *standby, bgh_key_t *key) {
    bgh_data_t *row = _lookup_row(standby, key);
    if(row && row->user) 
         return row;

    row = _lookup_row(active, key);
    if(!row || !row->user)
        return NULL;

    return _move_tables(active, standby, key, row);
}

bgh_data_t *bgh_acquire(bgh_t *ssns, bgh_key_t *key) {
    bgh_data_t *row = NULL;

    pthread_mutex_lock(&ssns->lock);
    if(ssns->refreshing) {
        if(ssns->active->inserted > ssns->standby->inserted) {
            row = _draining_lookup_active(ssns->active, ssns->standby, key);
        }
        else {
            row = _draining_prefer_standby(ssns->active, ssns->standby, key);
        }

        pthread_mutex_unlock(&ssns->lock);

        if(row && row->user) {
            row->ref_count++;
            return row;
        }
        
        return NULL;
    } 
    pthread_mutex_unlock(&ssns->lock);
        
    row = _lookup_row(ssns->active, key);
    if(row && row->user) {
        row->ref_count++;
        return row;
    }

    return NULL;
}

void bgh_release(bgh_t *tbl, bgh_data_t *row) {
    if(!row)
        return;
        
    row->ref_count--;
}

void bgh_delete_from_table(bgh_tbl_t *tbl, bgh_key_t *key) {
    bgh_data_t *row = _lookup_row(tbl, key);
    if(!row || !row->user) 
        return;

    // XXX Deletes ignore ref_count
    // Uh oh...
    //if(row->ref_count >= 2)
    //    return;

    tbl->free_cb(row->user);

    tbl->inserted--;
    row->user = NULL;
    row->deleted = true;
}

// XXX Clear ignores ref_count
void bgh_clear(bgh_t *tbl, bgh_key_t *key) {
    pthread_mutex_lock(&tbl->lock);
    if(tbl->refreshing) {
        // XXX Revisit: Not optimal to just do both this way, but this is an edge case
        bgh_delete_from_table(tbl->active, key);
        bgh_delete_from_table(tbl->standby, key);
        pthread_mutex_unlock(&tbl->lock);
        return;
    }
    pthread_mutex_unlock(&tbl->lock);
    bgh_delete_from_table(tbl->active, key);
}

void bgh_get_stats(bgh_t *tbl, bgh_stats_t *stats) {
    pthread_mutex_lock(&tbl->lock);
    stats->in_refresh = tbl->refreshing;
    stats->num_rows = tbl->active->num_rows;
    stats->inserted = tbl->active->inserted;
    stats->collisions = tbl->active->collisions;
    stats->max_inserts = tbl->active->max_inserts;
    pthread_mutex_unlock(&tbl->lock);
}
