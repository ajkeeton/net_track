#pragma once
/*
 * @author  Adam Keeton <ajkeeton@gmail.com>
 * Copyright (C) 2009-2020 Adam Keeton
 * TCP session tbl, with timeouts. Uses a "blue-green" mechanism for 
 * timeouts and automatic hash resizing. Resizing and timeouts are handled in 
 * their own thread
*/

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

// Number of timeout tables to use
// Higher numbers reduce the size of each batch but traffic spikes while under
// load may cause a table to fill resulting in failed inserts
#define TOTH_DEFAULT_TIMEOUT_TABLES 3

// Default timeout in seconds
// This is divided by the number of tables to get a sliding window effect
#define TOTH_DEFAULT_TIMEOUT 60

// Max number of collisions allowed for a given row
// Once reached the insert will fail
#define TOTH_MAX_COL_PER_ROW 3 

// When num_rows * hash_full_pct < number inserted, hash is considered 
// full and we won't insert.
#define TOTH_DEFAULT_HASH_FULL_PCT 5.0 // 5 percent

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
    uint64_t max_inserts,
             timeout;
    float hash_full_pct,
          scale_up_pct,
          scale_down_pct;
    uint8_t timeout_tables,  // # of timeout tables (sliding window slices)
            max_col_per_row; // Max collisions per row
} toth_config_t;

typedef struct _toth_ip_t {
    union {
        uint32_t v4;
        uint64_t v6[2];
    };
} toth_ips_t;

typedef struct _toth_key_t {
    toth_ips_t sip, 
               dip;

    uint16_t sport,
             dport;

    uint8_t vlan,
            family;
} toth_key_t;

typedef struct _toth_data_t {
    toth_key_t *key;
    void *user;

    // For collisions
    struct _toth_data_t *next, *prev; 

    uint8_t to_tbl;
    uint32_t to_idx;
} toth_data_t;

typedef struct _toth_to_node_t {
    // Index into the data table
    toth_data_t *data;

    int32_t next,
            prev;
} toth_to_node_t;

typedef struct _toth_to_tbl_t {
    uint32_t num_rows,
             inserted;
    int32_t head,
            tail;
    toth_to_node_t *tos;
} toth_to_tbl_t;

typedef struct _toth_t {
    toth_config_t conf;

    // The callback to clean up user data
    void (*free_cb)(void *);

    // Running stats for this table
    // "collisions" is considered when resizing the next hash
    uint64_t inserted, 
             collisions,
             num_rows,
             to_last;

    // The hash table for user data
    toth_data_t **rows;

    // A pool of keys so we can skip the dynamic alloc/frees
    // toth_keys_t *keys;

    // The timeout tables
    uint32_t to_active;
    toth_to_tbl_t **tos;
} toth_t;

#ifdef __cplusplus
extern "C" {
#endif

// Allocate new session tbl using default config
toth_t *toth_new(void (*free_cb)(void *));

// Allocate new session tbl using 'max' as the max number of inserts
// All other values will be defaults
toth_t *toth_new_tbl(uint64_t max, void (*free_cb)(void *));

// Allocate new session tbl using user config
toth_t *toth_config_new(toth_config_t *config, void (*free_cb)(void *));

// Initialize a configuration with the default values
void toth_config_init(toth_config_t *config);

// Free session tbl
void toth_free(toth_t *tbl);

// Lookup entry. Points to user data, if any
void *toth_lookup(toth_t *tbl, toth_key_t *key);

// Lookup, but don't adjust timeouts
void *toth_lookup_no_refresh(toth_t *tbl, toth_key_t *key);

// Insert entry
// Will allocate a new key interally and copy 'key' to it
toth_stat_t toth_keyed_insert(toth_t *tbl, toth_key_t *key, void *data);

toth_stat_t toth_insert(toth_t *tbl, 
    uint32_t *sip, uint32_t *dip, 
    uint16_t sport, uint16_t dport, 
    uint8_t vlan, uint8_t family, 
    void *data);

// Delete entry and free user data if any
// NOTE: some internal data won't be cleaned up until the timeout
void toth_remove(toth_t *tbl, toth_key_t *key);

// Returns true if we've run out of room
bool toth_full(toth_t *tbl);

// Populate given stats structure
void toth_get_stats(toth_t *tbl, toth_stats_t *stats);

// Force timeout code to execute rather than waiting for the next insert
void toth_do_timeouts(toth_t *tbl);

// Force a resize table to resize. New size is determined by current hash usage 
void toth_do_resize(toth_t *tbl);

// Calls callback for each node in table
// Callback is passed a pointer to the key, the data, and a user-provided context
void toth_foreach(toth_t *tbl, void (*cb)(toth_key_t *, void *, void *), void *ctx);

// TODO, convenience
#if 0
// Convenience functions to initialize a key
void toth_key_init4(toth_key_t *key, uint32_t sip, uint16_t sport, 
                    uint32_t dip, uint16_t dport, uint8_t vlan);
void toth_key_init6(toth_key_t *key, uint32_t sip[4], uint16_t sport, 
                    uint32_t dip[4], uint16_t dport, uint8_t vlan);
#endif

// Copy keys
// IP family is considered so we don't have to do a full memcpy
void toth_key_copy(toth_key_t *dst, toth_key_t *src);

// Apply a random offset to the refresh and refresh timeout 
// This prevents timing attacks and helps performance when several instances
// are used in parallel
//
// Argument is a percentage applied to the current settings
void toth_randomize_refreshes(toth_t *tbl, float pct);

#ifdef __cplusplus
}
#endif
