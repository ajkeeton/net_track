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
#include "llto.h"
#include "primes.h"

void llto_config_init(llto_config_t *config) {
    int len = prime_total();

    config->starting_rows = prime_at_idx(len/3); 
    config->min_rows = prime_at_idx(0);
    config->max_rows = prime_at_idx(len);
    config->timeout = LLTO_DEFAULT_TIMEOUT;
    config->hash_full_pct = LLTO_DEFAULT_HASH_FULL_PCT;

    // Control scaling
    // If the number of inserts > number rows * scale_up_pct
    // Scale up
    config->scale_up_pct = LLTO_DEFAULT_HASH_FULL_PCT * 0.75;
    // If the number of inserts < number rows * scale_down_pct
    // Scale down
    config->scale_down_pct = LLTO_DEFAULT_HASH_FULL_PCT * 0.1;
}

struct llto_to_t *llto_to_new() {
    return (struct llto_to_t*)calloc(sizeof(struct llto_to_t), 1);
}

struct llto_data_t *llto_new_row() {
    return (struct llto_data_t*)calloc(sizeof(struct llto_data_t), 1);
};

void _free_entire_row(llto_t *tbl, struct llto_data_t *row) { 
    if(row->next) {
        // Clean up collisions
        struct llto_data_t *d = row->next,
                           *n = NULL;
        do {
            if(d->user)
                tbl->free_cb(d->user);
            n = d->next;
            free(d);
            d = n;
        } while(n);
    }

    if(row->user)
        tbl->free_cb(row->user);

    free(row);
}

llto_t *llto_new(void (*free_cb)(void *)) {
    llto_config_t config;
    llto_config_init(&config);

    return llto_config_new(&config, free_cb);
}

void llto_free(llto_t *tbl) {
    if(!tbl) return;

    struct llto_to_t *cur = tbl->to_head,
              *next = NULL;

    while(cur) {
        next = cur->next;
        free(cur);
        cur = next;
    }

    for(int i=0; i<tbl->num_rows; i++) {
        _free_entire_row(tbl, tbl->rows[i]);
    }

    free(tbl->rows);
    free(tbl);
}

llto_t *llto_config_new(llto_config_t *config, void (*free_cb)(void *)) {
    llto_t *tbl = (llto_t*)calloc(sizeof(llto_t), 1);
    if(!tbl)
        return NULL;

    tbl->num_rows = config->starting_rows;
    tbl->rows = (struct llto_data_t**)malloc(sizeof(struct llto_data_t*) * tbl->num_rows);

    if(!tbl->rows) {
        free(tbl);
        return NULL;
    }

    for(int i=0; i<tbl->num_rows; i++) {
        tbl->rows[i] = llto_new_row();
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
    tbl->max_inserts = config->starting_rows * config->hash_full_pct/100.0;
    tbl->timeout = config->timeout * 1000000000;
    tbl->to_head = tbl->to_tail = NULL;

    return tbl;
}

static inline int key_eq(llto_key_t *k1, llto_key_t *k2) {
    uint64_t *p1 = (uint64_t*)k1;
    uint64_t *p2 = (uint64_t*)k2;

    return 
        ((p1[0] == p2[0] && p1[1] == p2[1]) ||
        (p1[0] == p2[1] && p1[1] == p2[0])) &&
        k1->vlan == k2->vlan;
}

// Hash func: XOR32
// Reference: https://www.researchgate.net/publication/281571413_COMPARISON_OF_HASH_STRATEGIES_FOR_FLOW-BASED_LOAD_BALANCING
//static inline uint64_t hash_func(uint64_t mask, llto_key_t *key) {
uint64_t hash_func(uint64_t mask, llto_key_t *key) {
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

struct llto_data_t *_lookup_row(llto_t *table, llto_key_t *key) {
    uint64_t idx = hash_func(table->num_rows, key);
    struct llto_data_t *row = table->rows[idx];

    if(key_eq(key, &row->key))
        return row;

    // Collision?
    for(struct llto_data_t *d = row->next; d; d=d->next) {
        if(key_eq(key, &d->key))
        // XXX Should technically move this node to the front now
            return d;
    }

    return NULL;
}

uint64_t time_ns() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000000000 + now.tv_nsec;
}

struct llto_to_t *_to_new(llto_t *tbl, struct llto_data_t *row) {
    struct llto_to_t *to = (struct llto_to_t*)calloc(sizeof(struct llto_to_t), 1);
    to->row = row;
    to->next = tbl->to_head;
    
    if(tbl->to_head)
        tbl->to_head->prev = to;
    else
        // There was no head, therefore no tail
        tbl->to_tail = to;

    tbl->to_head = to;
    to->t = time_ns();

    return to;
}

void _to_front(llto_t *tbl, struct llto_to_t *to) {
    to->t = time_ns();

    if(to == tbl->to_head)
        return;

    struct llto_to_t *n = to->next,
                     *p = to->prev;

    if(p) 
        p->next = n;
    if(n)
        n->prev = p;

    // Back that tail up
    if(to == tbl->to_tail)
        tbl->to_tail = p;

    to->next = tbl->to_head;
    tbl->to_head->prev = to;
    tbl->to_head = to;
    to->prev = NULL;
}

void _free_single(llto_t *tbl, struct llto_data_t *row) { 
    // row->user should have been validated by caller
    tbl->free_cb(row->user);
        
    row->user = NULL;
    row->ref_count = 0;
    tbl->inserted--;
    
    if(row->prev) {
        // This row was a collision
        // Fix list
        struct llto_data_t *p = row->prev,
                           *n = row->next;
        p->next = n;
        if(n)
            n->prev = p;
        free(row);
    } 
    else if(row->next) {
        uint64_t idx = hash_func(tbl->num_rows, &row->key);
        tbl->rows[idx] = row->next;
        row->next->prev = NULL;
        free(row);
    }
}

void _timeout(llto_t *tbl) {
    uint64_t now = time_ns();
    struct llto_to_t *cur = tbl->to_tail;
    struct llto_to_t *tmp = NULL;

    #if 0
    puts("List:");
    struct llto_to_t *c = tbl->to_head;
    while(c) {
        printf("node: %llu - %llu = %llu.... %s\n", 
            now,  c->t, now -  c->t, (char*) c->row->user);   
        c = c->next;
    }
    puts("--------------");
    #endif

    while(cur) {
        //printf("Checking: %llu - %llu = %llu.... %s\n", 
        //    now, cur->t, now - cur->t, (char*)cur->row->user);
        if(now - cur->t < tbl->timeout)
            return;
        
        // Should technically never happen...
        if(!cur->row->user || (cur->row->ref_count >= 1)) 
            return;

        //printf("Timing out: %llu - %llu = %llu.... %p: %s\n", 
        //    now, cur->t, now - cur->t, cur->row, (char*)cur->row->user);
        
        tmp = cur;
        cur = cur->prev;

        _free_single(tbl, tmp->row);
        free(tmp);

        if(tbl->to_head == tmp)
            tbl->to_head = NULL;

        tbl->to_tail = cur;
        if(cur)
            cur->next = NULL;
    }
}

void llto_clear(llto_t *tbl, llto_key_t *key) {
    struct llto_data_t *row = _lookup_row(tbl, key);

    if(!row || !row->user) {
        return;
    }

    struct llto_to_t *to = row->to,
            *p = row->to->prev,
            *n = row->to->next;

    if(p)
        p->next = n;
    if(n)
        n->prev = p;

    if(to == tbl->to_head)
        tbl->to_head = to->next;
    if(to == tbl->to_tail)
        tbl->to_tail = to->prev;

    _free_single(tbl, row);
    free(to);
}

struct llto_data_t *_handle_coll(
        struct llto_data_t *parent, llto_key_t *key, void *data) {
    struct llto_data_t *n = NULL;
    
    // First, check if it exists
    for(struct llto_data_t *d = parent->next; d; d=d->next) {
        if(key_eq(key, &d->key)) {
            n = d;
            break;
        }
    }

    if(!n) {
        n = llto_new_row();
        if(!n) {
            return NULL;
        }
    }

    // Make new head of collision list

    if(parent->next) {
        if(parent->next != n) {
            n->next = parent->next;
        }

        parent->next->prev = n;
    }

    // NOTE: parent->prev should always be null

    parent->next = n;
    n->prev = parent;
    return n;
}

// NOTE: Insert will overwrite any existing user data using the same key
// Ref count is not incremented
struct llto_data_t *_llto_insert(llto_t *tbl, llto_key_t *key, void *data) {
    _timeout(tbl);

    // XXX Handle this case better ...
    // - should allow overwrites
    // - use to influence the size of the next hash table
    if(tbl->inserted > tbl->max_inserts)
        return NULL;

    uint64_t idx = hash_func(tbl->num_rows, key);
    struct llto_data_t *row = tbl->rows[idx];

    if(row->user) {
        // Handle collisions
        if(!key_eq(key, &row->key)) {
            row = _handle_coll(row, key, data);
            if(!row)
                return NULL;
        }
    }

    // Check if we need to overwrite old data
    if(row->user) {
        tbl->free_cb(row->user);
        _to_front(tbl, row->to);
    }
    else {
        tbl->inserted++;
        row->to = _to_new(tbl, row);
    }

    memcpy(&row->key, key, sizeof(row->key));
    row->user = data;

    return row;
}

llto_stat_t llto_insert(llto_t *tbl, llto_key_t *key, void *data) {
    // Require data
    if(!data)
        return LLTO_EXCEPTION;

    if(!_llto_insert(tbl, key, data))
        return LLTO_EXCEPTION;

    return LLTO_OK;
}

struct llto_data_t *llto_insert_acquire(llto_t *tbl, llto_key_t *key, void *data) {
    // Required
    if(!data)
        return NULL;

    struct llto_data_t *ret = _llto_insert(tbl, key, data);
    if(!ret)
        return NULL;

    ret->ref_count++;
    return ret;
}

struct llto_data_t *llto_acquire(llto_t *tbl, llto_key_t *key) {
    struct llto_data_t *row = _lookup_row(tbl, key);

    if(!row || !row->user)
        return NULL;

    row->ref_count++;
    _to_front(tbl, row->to);
    return row;
}

void llto_release(llto_t *tbl, struct llto_data_t *row) {
    if(!row)
        return;

    if(row->ref_count > 0)
        row->ref_count--;
}

void llto_get_stats(llto_t *tbl, llto_stats_t *stats) {
    stats->num_rows = tbl->num_rows;
    stats->inserted = tbl->inserted;
    stats->collisions = tbl->collisions;
    stats->max_inserts = tbl->max_inserts;
}

// Not applicable to llto, but keeping consistent with bgh api
void llto_randomize_refreshes(llto_t *tracker, float pct) {}
