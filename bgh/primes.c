#include "primes.h"

// Handy:
// http://compoasso.free.fr/primelistweb/page/prime/liste_online_en.php

static uint64_t primes[] = {
    25013,	
    50047,
	100003,
	200003,
	300043,
	400067,
	500107,
	600101,
	700027,
	800029,
	900091,
	1000117,
	2000081,
	3000017,
	4000081,
	5000153,
	5500003,
	6000101,
	7000003,
	8000071,
	9000143,
	10000141,
	11000081,
	12000097,
	13000133,
	14000071,
	15000017,
    16000057,
    17000023,
    18000041,
    19000013,
    20000003
};

int _prime_nearest_idx(uint64_t val, int idx, int lower, int upper) {
    if(idx == 0 || idx == prime_total()-1 || val == primes[idx])
        return idx;

    if(val > primes[idx])  {
        // Handles case where we weren't exactly a prime already
        if(val <= primes[idx+1]) 
            return idx+1;

        return _prime_nearest_idx(val, 
           (upper + idx) / 2,
           idx,
           upper);
    }

    if(val > primes[idx-1])
        // Handles case where we weren't exactly a prime already
        return idx;

    return _prime_nearest_idx(val, (lower + idx) / 2, lower, idx);
}

int prime_nearest_idx(uint64_t val) {
    return _prime_nearest_idx(val, prime_total()/2, 0, prime_total());
}

uint64_t prime_at_idx(int idx) {
    if(idx < 0)
        return primes[0];
    if(idx >= prime_total())
        return primes[prime_total()-1];
    return primes[idx];
}

int prime_total() {
    return sizeof(primes) / sizeof(primes[0]);
}

uint64_t prime_larger_idx(int idx) {
    return idx < prime_total()-1 ?  primes[idx+1] : primes[prime_total() - 1];
}

uint64_t prime_smaller_idx(int idx) {
    return idx > 0 ? primes[idx-1] : primes[0];
}

