/*
 * Ghidralligator - MMIO Fuzzing Engine
 *
 * Implements Fuzzware-style MMIO fuzzing: peripheral reads consume bytes
 * from the fuzzer input stream instead of returning fixed/zero values.
 *
 * Licensed under the Apache License, Version 2.0
 */

#include <cstdio>
#include <cstring>
#include "mmio.h"
#include "globals.h"

void mmio_init(MMIOState *s) {
    s->data = nullptr;
    s->size = 0;
    s->cursor = 0;
    s->ranges.clear();
}

void mmio_reset(MMIOState *s, uint8_t *data, uint32_t size) {
    s->data = data;
    s->size = size;
    s->cursor = 0;
}

bool mmio_is_mmio_addr(MMIOState *s, uint64_t addr) {
    for (const auto &r : s->ranges) {
        if (addr >= r.start && addr <= r.end) {
            return true;
        }
    }
    return false;
}

bool mmio_fuzz_read(MMIOState *s, uint64_t addr, int size, uint64_t *val_out) {
    *val_out = 0;

    if (s->data == nullptr || s->cursor + size > s->size) {
        log_debug("[MMIO] Input exhausted at 0x%lx (cursor=%u, need=%d, have=%u)\n",
                  addr, s->cursor, size, s->size);
        return false;
    }

    memcpy(val_out, &s->data[s->cursor], size);
    s->cursor += size;

    log_debug("[MMIO] Read 0x%lx size=%d -> 0x%lx (cursor=%u/%u)\n",
              addr, size, *val_out, s->cursor, s->size);

    return true;
}

void mmio_fuzz_write(MMIOState *s, uint64_t addr, uint64_t val, int size) {
    log_debug("[MMIO] Write 0x%lx size=%d val=0x%lx (dropped)\n", addr, size, val);
}
