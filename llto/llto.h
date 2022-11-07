#pragma once
/*
 * @author  Adam Keeton <ajkeeton@gmail.com>
 * Copyright (C) 2009-2020 Adam Keeton
 * TCP session tracker, with timeouts. Uses a linked-list LRU for timeouts
*/

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#define LLTO_DEFAULT_TIMEOUT 60 // seconds
#define LLTO_DEFAULT_REFRESH_PERIOD 120 // seconds
// When num_rows * hash_full_pct < number inserted, hash is considered 
// full and we won't insert.
#define LLTO_DEFAULT_HASH_FULL_PCT 6.0 // 6 percent

typedef enum _llto_stat_t {
    LLTO_OK,
    LLTO_FULL,
    LLTO_ALLOC_FAILED,
    LLTO_MEM_EXCEPTION,
    LLTO_IN_USE,
    LLTO_EXCEPTION
} llto_stat_t;

typedef struct _llto_config_t {
    uint64_t starting_rows,
             min_rows,
             max_rows,
             timeout;
    float hash_full_pct,
          scale_up_pct,
          scale_down_pct;
} llto_config_t;

typedef struct _llto_key_t {
    // Ports are intentionally kept as uint32_ts as an optimization in the key
    // comparison function
    uint32_t sip;
    uint32_t sport;

    uint32_t dip;
    uint32_t dport;

    uint8_t vlan;
} llto_key_t;

struct llto_to_t;

struct llto_data_t {
    void *user;
    llto_key_t key;
    struct llto_to_t *to;
    int ref_count;

    // For collisions
    struct llto_data_t *prev, *next;
};

typedef struct _llto_stats_t {
    uint64_t inserted, 
             collisions,
             max_inserts,
             num_rows;
} llto_stats_t;
 
struct llto_to_t {
    struct llto_data_t *row;
    struct llto_to_t *next, 
              *prev;
    uint64_t t;
};

typedef struct _llto_t {
    //llto_config_t config;

  // The callback to clean up user data
    void (*free_cb)(void *);

    // Running stats for this table
    // "collisions" considered when resizing the next hash
    uint64_t inserted, 
             collisions,
             max_inserts,
             num_rows,
             timeout;

    struct llto_data_t **rows;
    struct llto_to_t *to_head,
              *to_tail;
} llto_t;

#ifdef __cplusplus
extern "C" {
#endif

// Allocate new session tracker using default config
llto_t *llto_new(void (*free_cb)(void *));

// Allocate new session tracker using user config
llto_t *llto_config_new(llto_config_t *config, void (*free_cb)(void *));

// Initialize a configuration with the default values
void llto_config_init(llto_config_t *config);

// Free session tracker
void llto_free(llto_t *tracker);

// Lookup entry. Points to user data, if any. Increments reference count
struct llto_data_t *llto_acquire(llto_t *tracker, llto_key_t *key);

// Release row, decrementing reference count
void llto_release(llto_t *tracker, struct llto_data_t *data);

// Insert entry
llto_stat_t llto_insert(llto_t *tracker, llto_key_t *key, void *data);

// Insert entry and return row with ref_count = 1
struct llto_data_t *llto_insert_acquire(llto_t *tracker, llto_key_t *key, void *data);

// Delete entry and free user data if any
void llto_clear(llto_t *tracker, llto_key_t *key);

// Populate given stats structure
void llto_get_stats(llto_t *tracker, llto_stats_t *stats);

// Apply a random offset to the refresh and refresh timeout 
// This prevents timing attacks and helps performance when LLTO is used in a 
// large number of parallel threads
//
// Argument is a percentage applied to the current settings.
// Can be called repeatedly to re-randomize the the settings
void llto_randomize_refreshes(llto_t *tracker, float pct);

#ifdef __cplusplus
}
#endif

