#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "to.h"

void toth_key_free(toth_t *tbl, toth_data_t *row);
uint64_t hash_func(uint64_t mask, toth_key_t *key);

uint64_t time_ns() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return now.tv_sec * 1000000000 + now.tv_nsec;
}

void _toth_data_clear(toth_t *tbl, toth_data_t *row) {   
    tbl->free_cb(row->user);
    tbl->inserted--;
    toth_data_t *p = row->prev,
                *n = row->next;

    if(p) {
        // Collision. Need to fix pointers
        p->next = n;
        if(n)
            n->prev = p;
        toth_key_free(tbl, row);
        free(row);
        tbl->collisions--;
    }
    else if(n) {
        // No prev. We're the head
        // Promote next
        uint64_t idx = hash_func(tbl->num_rows, row->key);
        tbl->rows[idx] = n;
        n->prev = NULL;
        toth_key_free(tbl, row);
        free(row);
        tbl->collisions--;
    }
    else {
        row->user = NULL;
        toth_key_free(tbl, row);
    }
}

toth_to_tbl_t *_to_new_tbl(uint32_t size) {
    toth_to_tbl_t *n = (toth_to_tbl_t*)calloc(sizeof(toth_to_tbl_t), 1);
    if(!n)
        return NULL;

    n->num_rows = size;
    n->tos = (toth_to_node_t*)calloc(sizeof(toth_to_node_t), size);

    if(!n->tos) {
        free(n);
        return NULL;
    }

    n->head = n->tail = -1;
    return n;
}

void _to_unlink(toth_to_tbl_t *tot, uint32_t idx) {
    toth_to_node_t *to = &tot->tos[idx];

    if(to->next >= 0) {
        toth_to_node_t *next = &tot->tos[to->next];
        next->prev = to->prev;
    }

    if(to->prev >= 0) {
        toth_to_node_t *prev = &tot->tos[to->prev];
        prev->next = to->next;
    }

    if(tot->head == idx) {
        tot->head = to->next;
    }
    if(tot->tail == idx) {
        tot->tail = to->prev;
    }

    to->next = to->prev = -1;
    
    // NOTE! 
    // Intentionally not decrementing "inserted".
    // We don't currently keep track of holes. They accumlate until timeout
    // "inserted" is used as an index for appending nodes.
    // A future feature would be to keep track of those holes and fill them as
    // needed.
}

void _validate_list(toth_to_tbl_t *tot) {
    int32_t i = tot->head;

    int n = 0;
    // uint64_t start = tbl->inserted;
    while(i >= 0) {
        toth_to_node_t *to = &tot->tos[i];
        i = to->next;
        n++;
    }

    if(n != tot->inserted)
        abort();
}

void debug_tbl(toth_to_tbl_t *tot) {
    int32_t i = tot->head;
    toth_to_node_t *to = NULL;
    int n = 0;
    printf("TOT %p: head: %d\ttail:%d\n", tot, tot->head, tot->tail);

    while(i >= 0) {
        to = &tot->tos[i];    
        printf("next: %d\tprev: %d\tdata: %p\n", to->next, to->prev, to->data);
        i = to->next;
        n++;
    }

    if(tot->head < 0)
        return;

    int nn = 0;
    // Walk backwards and confirm count is the same
    i = tot->tail;
    while(i >= 0) {
        to = &tot->tos[i];
        i = to->prev;
        nn++;
    }

    assert(n == nn);
    printf("Num nodes: %d\n", n);
}

int32_t _to_append(toth_to_tbl_t *tbl, toth_data_t *d) {
    //puts("Appending");
    //debug_tbl(tbl);

    toth_to_node_t *nn = &tbl->tos[tbl->inserted];    
    nn->prev = tbl->tail;

    if(tbl->head == -1) {
        tbl->head = tbl->inserted;
    }
    else {
        toth_to_node_t *old_tail = &tbl->tos[tbl->tail];
        old_tail->next = tbl->inserted;
    }

    tbl->tail = tbl->inserted;
    tbl->inserted++;

    nn->next = -1;
    nn->data = d;

    //puts("Done appending");
    //debug_tbl(tbl);
    //puts("-------------");
    return tbl->tail;
}

toth_to_tbl_t *_toth_get_oldest_table(toth_t *tbl) {
    return tbl->to_active+1 < tbl->conf.timeout_tables ? 
        tbl->tos[tbl->to_active+1] : tbl->tos[0];
}

toth_to_tbl_t *_tot_get_active(toth_t *tbl) {
    return tbl->tos[tbl->to_active];
}

toth_stat_t tot_insert(toth_t *tbl, toth_data_t *row) {
    toth_to_tbl_t *tot = _tot_get_active(tbl);
    if(tot->inserted >= tot->num_rows)
        return TOTH_MEM_EXCEPTION;

    row->to_idx = _to_append(tot, row);
    row->to_tbl = tbl->to_active;
    return TOTH_OK;
}

void tot_remove(toth_t *tbl, toth_data_t *d) {
    //printf("- Clearing node %p / %s using table %d\n", d, (char*)d->user, d->to_tbl);
    _to_unlink(tbl->tos[d->to_tbl], d->to_idx);
    _toth_data_clear(tbl, d);
 }

// Move timeout to the active table
void _to_move(toth_to_tbl_t *to, toth_to_tbl_t *from, uint8_t tidx, toth_data_t *row) {
    _to_unlink(from, row->to_idx);
    row->to_idx = _to_append(to, row);
    row->to_tbl = tidx;
}

toth_stat_t tot_refresh(toth_t *tbl, toth_data_t *row) {
    if(row->to_tbl == tbl->to_active)
        return TOTH_OK;

    toth_to_tbl_t *tot = _tot_get_active(tbl);
    // Make sure destination table has room   
    if(tot->inserted >= tot->num_rows)
        return TOTH_MEM_EXCEPTION;

    _to_move(tot, tbl->tos[row->to_tbl], tbl->to_active, row);

    // printf("Moved %s from %d to %d (%p)\n", (char*)row->user, row->to_tbl, tbl->to_active, current);
    return TOTH_OK;
}

void _to_clear_table(toth_t *tbl, toth_to_tbl_t *tot) {
    int32_t i = tot->head;

    // uint64_t start = tbl->inserted;
    while(i >= 0) {
        toth_to_node_t *to = &tot->tos[i];    
        toth_data_t *d = to->data;

        toth_key_free(tbl, d);
        tbl->free_cb(d->user);

        if(d->prev) {
            if(d->next)
                d->next->prev = d->prev;
            d->prev->next = d->next;
            // this was a collision. free here
            free(d);
            tbl->collisions--;
        }
        else {
            d->user = NULL;
        }
        
        tbl->inserted--;
        i = to->next;
        to->prev = -1;
        to->next = -1;
    }

    // printf("Timedout %lu\n", start - tbl->inserted);
    tot->head = tot->tail = -1;
    tot->inserted = 0;
}

toth_data_t *_lookup(   
        toth_t *tbl, toth_key_t *key, bool alloc_on_collision);

bool _toth_insert_from_copy(toth_t *tbl, toth_data_t *d) {
    toth_data_t *row = _lookup(tbl, d->key, true);

    // Should never happen... 
    if(!row)
        return false;

    row->key = d->key;
    d->key = NULL;
    row->user = d->user;
    d->user = NULL;

    row->to_tbl = d->to_tbl;
    row->to_idx = _to_append(tbl->tos[d->to_tbl], row);

    return true;
}

// Copy from ftbl to dtbl
// NOTE: If dtbl is smaller there is risk that not all nodes will be copied 
void tot_copy(toth_t *dtbl, toth_t *ftbl) {
    toth_to_tbl_t *to = dtbl->tos[dtbl->to_active];

    // Process any timeouts first
    tot_do_timeouts(ftbl);

    for(int i=0; i < ftbl->conf.timeout_tables; i++) {
        toth_to_tbl_t *from = ftbl->tos[i];

        int32_t j = from->head;

        while(j >= 0) {
            // Shouldn't happen but just in case...
            if(to->inserted >= to->num_rows)
                return;

            toth_to_node_t *ton = &from->tos[j];
            toth_data_t *d = ton->data;
    
            if(!_toth_insert_from_copy(dtbl, d))
                break;

            _to_unlink(from, d->to_idx);
        }

        from->head = -1;
    }
}

// Purge oldest table if enough time has passed
void tot_do_timeouts(toth_t *tbl) {
    uint64_t t = time_ns();

    if((t - tbl->to_last) < tbl->conf.timeout) {
        // puts("too early to time out");
        return;
    }

    tbl->to_last = t;

    tbl->to_active = tbl->to_active+1 < tbl->conf.timeout_tables ? tbl->to_active+1 : 0;

    // printf("Timing out tbl %p (%d)\n", to_tbl, tbl->to_active);
    _to_clear_table(tbl, _tot_get_active(tbl));
}

void to_foreach(toth_to_tbl_t *tot, void (*cb)(toth_key_t *, void *, void *), void *ctx) {
    int32_t i = tot->head;
    toth_to_node_t *to = NULL;

    while(i >= 0) {
        to = &tot->tos[i];    
        cb(to->data->key, to->data->user, ctx);
        i = to->next;
    }
}

void tot_new(toth_t *tbl) {
    tbl->to_active = 0;
    tbl->tos = (toth_to_tbl_t **)calloc(sizeof(toth_to_tbl_t *), tbl->conf.timeout_tables);
    if(!tbl->tos) {
        // XXX
        abort();
    }

    for(int i=0; i < tbl->conf.timeout_tables; i++) {
        tbl->tos[i] = _to_new_tbl(tbl->conf.max_inserts);
        if(!tbl->tos[i])
            // XXX
            abort();
    }

    tbl->to_last = time_ns();
}

void tot_free(toth_t *tbl) {
    for(int i=0; i<tbl->conf.timeout_tables; i++) {
        toth_to_tbl_t *tot = tbl->tos[i];
        _to_clear_table(tbl, tot);
        free(tot->tos);
        free(tot);    
    }

    free(tbl->tos);
}
