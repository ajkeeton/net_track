#pragma once
#include <stdint.h>

int prime_total();
uint64_t prime_at_idx(int idx);
uint64_t prime_nearest(uint64_t val);
uint64_t prime_larger(uint64_t val);
uint64_t prime_smaller(uint64_t val);

int prime_nearest_idx(uint64_t val);
uint64_t prime_larger_idx(int idx);
uint64_t prime_smaller_idx(int idx);
