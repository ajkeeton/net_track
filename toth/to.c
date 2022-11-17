#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "to.h"

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
        free(row);
        tbl->collisions--;
    }
    else if(n) {
        // No prev. We're the head
        // Promote next
        uint64_t idx = hash_func(tbl->num_rows, &row->key);
        tbl->rows[idx] = n;
        n->prev = NULL;
        tbl->collisions--;
        free(row);
    }
    else 
        row->user = NULL;
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

    // XXX 
    // Intentionally not decrementing "inserts".
    // We don't currently keep track of holes.
    // They will accumulate until we timeout.
    // This is a side effect of the design.
    // A future feature would be to keep track of those holes and fill them as
    // needed.
    // XXX
}

int32_t _to_append(toth_to_tbl_t *tbl, toth_data_t *d) {
    toth_to_node_t *nn = &tbl->tos[tbl->inserts];    
    nn->prev = tbl->tail;

    // First node
    if(tbl->head == -1) {
        tbl->head = 0;
    }
    else {
        toth_to_node_t *old_tail = &tbl->tos[tbl->tail];
        old_tail->next = tbl->inserts;
    }

    tbl->tail = tbl->inserts;
    tbl->inserts++;

    nn->next = -1;
    nn->data = d;

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
    if(tot->inserts + 1 >= tot->num_rows)
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
    if(tot->inserts + 1 >= tot->num_rows)
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
    tot->inserts = 0;
}

void tot_copy(toth_t *dtbl, toth_t *ftbl) {
    toth_to_tbl_t *to = dtbl->tos[dtbl->to_active];

    // Cleanup first
    tot_do_timeouts(ftbl);

    for(int i=0; i < ftbl->conf.timeout_tables; i++) {
        toth_to_tbl_t *from = ftbl->tos[i];
        int32_t i = from->head;

        while(i >= 0) {
            // Shouldn't happen but just in case...
            if(to->inserts+1 >= to->num_rows)
                return;

            toth_to_node_t *ton = &from->tos[i];    
            toth_data_t *d = ton->data;
    
            _to_unlink(from, d->to_idx);
            if(toth_insert(dtbl, &d->key, d->user) != TOTH_OK)
                return;

            d->user = NULL;
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

void tot_new(toth_t *tbl) {
    tbl->to_active = 0;
    tbl->tos = (toth_to_tbl_t **)calloc(sizeof(toth_to_tbl_t *), tbl->conf.timeout_tables);
    if(!tbl->tos) {
        // XXX
        abort();
    }

    for(int i=0; i < tbl->conf.timeout_tables; i++) {
        tbl->tos[i] = _to_new_tbl(tbl->max_inserts);
        if(!tbl->tos[i])
            // XXX
            abort();
    }

    tbl->to_last = time_ns();
}

void tot_free(toth_t *tbl) {
    for(int i=0; i<tbl->conf.timeout_tables; i++) {
        toth_to_tbl_t *tot = tbl->tos[i];

        //printf("\nFreeing table %d\n", to_idx);

        _to_clear_table(tbl, tot);
        free(tot->tos);
        free(tot);    
    }

    free(tbl->tos);
}
