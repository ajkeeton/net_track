#pragma once
/*
 * @author  Adam Keeton <ajkeeton@gmail.com>
 * Copyright (C) 2009-2020 Adam Keeton
 * TCP session tracker, with timeouts. Uses a "blue-green" mechanism for 
 * timeouts and automatic hash resizing. Resizing and timeouts are handled in 
 * their own thread
*/

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#define TOTH_DEFAULT_TIMEOUT 60 // seconds
#define TOTH_DEFAULT_TIMEOUT_TABLES 3
#define TOTH_MAX_COL_PER_ROW 3 // NOTE: Must be smaller than a uint8_t (255)
// When num_rows * hash_full_pct < number inserted, hash is considered 
// full and we won't insert.
#define TOTH_DEFAULT_HASH_FULL_PCT 6.0 // 6 percent

typedef enum _toth_stat_t {
    TOTH_OK,
    TOTH_FULL,
    TOTH_ALLOC_FAILED,
    TOTH_MEM_EXCEPTION,
    TOTH_EXCEPTION
} toth_stat_t;

typedef struct _toth_stats_t {
    uint64_t inserted, 
             collisions,
             max_inserts,
             num_rows;
} toth_stats_t;

typedef struct _toth_config_t {
    uint64_t starting_rows,
             min_rows,
             max_rows,
             timeout;
    float hash_full_pct,
          scale_up_pct,
          scale_down_pct;

    uint8_t timeout_tables, 
            max_col_per_row;
} toth_config_t;

typedef struct _toth_key_t {
    // Ports are intentionally kept as uint32_ts as an optimization in the key
    // comparison function
    uint32_t sip;
    uint32_t sport;

    uint32_t dip;
    uint32_t dport;

    uint8_t vlan;
} toth_key_t;

typedef struct _toth_data_t {
    toth_key_t key;
    void *user;

    // For collisions
    struct _toth_data_t *next, *prev; 

    uint8_t to_tbl;
    uint32_t to_idx;
} toth_data_t;

typedef struct _toth_to_node_t {
    // Index into the data table
    toth_data_t *data;

    // If there was a collision this will be set to the collided node
    // toth_data_t *col;

    int32_t next,
            prev;
} toth_to_node_t;

typedef struct _toth_to_tbl_t {
    uint32_t num_rows,
             inserts;
    int32_t head,
            tail;
    toth_to_node_t *tos;
} toth_to_tbl_t;

typedef struct _toth_t {
    toth_config_t config;

    // The callback to clean up user data
    void (*free_cb)(void *);

    // Running stats for this table
    // "collisions" is considered when resizing the next hash
    uint64_t inserted, 
             collisions,
             max_inserts,
             timeout,
             timeout_swap,
             num_rows,
             to_last_swap,
             to_last,
             max_col_per_row;

    // The hash table for user data
    toth_data_t **rows;

    // The timeout tables
    uint32_t to_num_tables;
    uint32_t to_active;
    toth_to_tbl_t **tos;
} toth_t;

#ifdef __cplusplus
extern "C" {
#endif

// Allocate new session tracker using default config
toth_t *toth_new(void (*free_cb)(void *));

// Allocate new session tracker using user config
toth_t *toth_config_new(toth_config_t *config, void (*free_cb)(void *));

// Initialize a configuration with the default values
void toth_config_init(toth_config_t *config);

// Free session tracker
void toth_free(toth_t *tracker);

// Lookup entry. Points to user data, if any. Increments reference count
toth_data_t *toth_acquire(toth_t *tracker, toth_key_t *key);

// Release row, decrementing reference count
void toth_release(toth_t *tracker, toth_data_t *data);

// Insert entry
toth_stat_t toth_insert(toth_t *tracker, toth_key_t *key, void *data);

// Insert entry but return row with ref_count = 1
toth_data_t *toth_insert_acquire(toth_t *tracker, toth_key_t *key, void *data);

// Delete entry and free user data if any
void toth_remove(toth_t *tracker, toth_key_t *key);

// Populate given stats structure
void toth_get_stats(toth_t *tracker, toth_stats_t *stats);

void toth_do_timeouts(toth_t *tracker);

void toth_do_resize(toth_t *tracker);

// Apply a random offset to the refresh and refresh timeout 
// This prevents timing attacks and helps performance when BGH is used in a 
// large number of parallel threads
//
// Argument is a percentage applied to the current settings.
// Can be called repeatedly to re-randomize the the settings
void toth_randomize_refreshes(toth_t *tracker, float pct);

#ifdef __cplusplus
}
#endif
