#pragma once

#include "toth.h"

void tot_new(toth_t *tbl);
void tot_free(toth_t *tbl);
void tot_remove(toth_t *tbl, toth_data_t *row);
toth_stat_t tot_refresh(toth_t *tbl, toth_data_t *row);
toth_stat_t tot_insert(toth_t *tbl, toth_data_t *row);
void tot_do_timeouts(toth_t *tbl);