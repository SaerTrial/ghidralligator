/*
 * Ghidralligator - MMIO Fuzzing Engine
 *
 * Implements Fuzzware-style MMIO fuzzing: peripheral reads consume bytes
 * from the fuzzer input stream instead of returning fixed/zero values.
 *
 * Licensed under the Apache License, Version 2.0
 */

#ifndef MMIO_H
#define MMIO_H

#include <cstdint>
#include <vector>

using namespace std;

typedef struct {
    uint64_t start;
    uint64_t end;
} mmio_range_t;

typedef struct {
    // Fuzzer input stream
    uint8_t *data;
    uint32_t size;
    uint32_t cursor;

    // MMIO address ranges (from config)
    vector<mmio_range_t> ranges;
} MMIOState;

// Global MMIO state (nullptr when MMIO fuzzing disabled)
inline MMIOState *G_MMIO = nullptr;

// Initialize MMIO state (clear ranges, zero cursor)
void mmio_init(MMIOState *s);

// Reset between test cases: set new input data and reset cursor
void mmio_reset(MMIOState *s, uint8_t *data, uint32_t size);

// Check if address falls in a configured MMIO range
bool mmio_is_mmio_addr(MMIOState *s, uint64_t addr);

// Read: consume bytes from fuzzer input stream
// Returns true on success, false if input exhausted (caller should halt)
bool mmio_fuzz_read(MMIOState *s, uint64_t addr, int size, uint64_t *val_out);

// Write: silently dropped (peripheral writes are no-ops in emulation)
void mmio_fuzz_write(MMIOState *s, uint64_t addr, uint64_t val, int size);

#endif
