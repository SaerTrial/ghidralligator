/*
 * Ghidralligator - ARM Cortex-M NVIC Interrupt Controller
 *
 * Implements the Nested Vectored Interrupt Controller (NVIC) for
 * Cortex-M emulation, modeled after QEMU's armv7m_nvic.c and the
 * ARM Architecture Reference Manual.
 *
 * Licensed under the Apache License, Version 2.0
 */

#include <cstdio>
#include <cstring>
#include "globals.h"
#include "nvic.h"
#include "utils.h"
#include "memory.h"

using namespace ghidra;

// Stack frame offsets for Cortex-M exception entry
// The hardware pushes: R0, R1, R2, R3, R12, LR, ReturnAddr, xPSR
#define FRAME_R0_OFFSET     0x00
#define FRAME_R1_OFFSET     0x04
#define FRAME_R2_OFFSET     0x08
#define FRAME_R3_OFFSET     0x0C
#define FRAME_R12_OFFSET    0x10
#define FRAME_LR_OFFSET     0x14
#define FRAME_PC_OFFSET     0x18
#define FRAME_XPSR_OFFSET   0x1C
#define FRAME_SIZE          0x20  // 32 bytes

// Forward declarations
static void nvic_recompute_state(NVICState *s);
static int nvic_gprio_mask(NVICState *s);
static uint32_t nvic_read_irq_enable(NVICState *s, uint32_t offset);
static uint32_t nvic_read_irq_pending(NVICState *s, uint32_t offset);
static uint32_t nvic_read_irq_active(NVICState *s, uint32_t offset);
static uint32_t nvic_read_irq_priority(NVICState *s, uint32_t offset);
static void nvic_write_irq_enable_set(NVICState *s, uint32_t offset, uint32_t val);
static void nvic_write_irq_enable_clear(NVICState *s, uint32_t offset, uint32_t val);
static void nvic_write_irq_pending_set(NVICState *s, uint32_t offset, uint32_t val);
static void nvic_write_irq_pending_clear(NVICState *s, uint32_t offset, uint32_t val);
static void nvic_write_irq_priority(NVICState *s, uint32_t offset, uint32_t val);

// ============================================================================
// Initialization
// ============================================================================

void nvic_init(NVICState *s, int num_irq, int num_prio_bits) {
    memset(s, 0, sizeof(NVICState));
    s->num_irq = num_irq;
    s->num_prio_bits = num_prio_bits;
    // Priority mask: only top num_prio_bits are implemented
    // E.g., 4 bits -> mask = 0xF0
    s->prio_mask = (uint8_t)(((1 << num_prio_bits) - 1) << (8 - num_prio_bits));
    s->irq_interval = 0;  // disabled by default
    nvic_reset(s);
}

void nvic_reset(NVICState *s) {
    int num_irq = s->num_irq;
    int num_prio_bits = s->num_prio_bits;
    uint8_t prio_mask = s->prio_mask;
    uint32_t irq_interval = s->irq_interval;
    uint32_t vtor = s->vtor;

    // Clear all vector state
    for (int i = 0; i < NVIC_MAX_VECTORS; i++) {
        s->vectors[i].prio = 0;
        s->vectors[i].enabled = 0;
        s->vectors[i].pending = 0;
        s->vectors[i].active = 0;
        s->vectors[i].level = 0;
    }

    // Fixed-priority exceptions
    s->vectors[EXC_RESET].prio = -3;
    s->vectors[EXC_RESET].enabled = 1;
    s->vectors[EXC_NMI].prio = -2;
    s->vectors[EXC_NMI].enabled = 1;
    s->vectors[EXC_HARDFAULT].prio = -1;
    s->vectors[EXC_HARDFAULT].enabled = 1;

    // System exceptions (configurable priority, disabled by default)
    // MemManage, BusFault, UsageFault need to be enabled via SHCSR
    s->vectors[EXC_SVCALL].enabled = 1;
    s->vectors[EXC_PENDSV].enabled = 1;
    s->vectors[EXC_SYSTICK].enabled = 1;

    // SCB registers
    s->vtor = vtor;  // Preserved across reset (set from config or firmware)
    s->aircr = 0;
    s->scr = 0;
    s->ccr = 0;
    s->shcsr = 0;
    s->cfsr = 0;
    s->hfsr = 0;
    s->prigroup = 0;

    // Restore configuration (preserved across reset)
    s->num_irq = num_irq;
    s->num_prio_bits = num_prio_bits;
    s->prio_mask = prio_mask;
    s->irq_interval = irq_interval;

    // Re-apply pre-enabled IRQs from config
    for (int i = 0; i < s->num_pre_enabled; i++) {
        int exc = s->pre_enabled_irqs[i];
        s->vectors[exc].enabled = 1;
    }

    nvic_recompute_state(s);
}

// ============================================================================
// Priority resolution (core NVIC algorithm)
// ============================================================================

static int nvic_gprio_mask(NVICState *s) {
    // Group priority mask based on PRIGROUP
    // PRIGROUP=0: group=[7:1], sub=[0]    -> mask=0xFE
    // PRIGROUP=7: group=none,  sub=[7:0]  -> mask=0x00
    return ~0U << (s->prigroup + 1);
}

static void nvic_recompute_state(NVICState *s) {
    int pend_prio = NVIC_NOEXC_PRIO;
    int active_prio = NVIC_NOEXC_PRIO;
    int pend_irq = 0;
    int total = EXC_EXTERNAL_BASE + s->num_irq;
    int gprio_mask = nvic_gprio_mask(s);

    for (int i = 1; i < total; i++) {
        VecInfo *vec = &s->vectors[i];

        if (vec->enabled && vec->pending) {
            int prio = vec->prio;
            if (prio > 0) {
                prio &= gprio_mask;
            }
            if (prio < pend_prio) {
                pend_prio = prio;
                pend_irq = i;
            }
        }
        if (vec->active) {
            int prio = vec->prio;
            if (prio > 0) {
                prio &= gprio_mask;
            }
            if (prio < active_prio) {
                active_prio = prio;
            }
        }
    }

    s->vectpending = pend_irq;
    s->vectpending_prio = pend_prio;
    s->exception_prio = active_prio;
}

// ============================================================================
// Interrupt management
// ============================================================================

void nvic_set_pending(NVICState *s, int irq) {
    int exception = irq + EXC_EXTERNAL_BASE;
    if (exception >= EXC_EXTERNAL_BASE + s->num_irq) {
        log_info("[NVIC] nvic_set_pending: IRQ %d out of range\n", irq);
        return;
    }
    s->vectors[exception].pending = 1;
    nvic_recompute_state(s);
}

// Set pending by exception number (for system exceptions like SysTick)
void nvic_set_pending_exception(NVICState *s, int exception) {
    if (exception < 1 || exception >= NVIC_MAX_VECTORS) {
        log_info("[NVIC] nvic_set_pending_exception: exception %d out of range\n", exception);
        return;
    }
    s->vectors[exception].pending = 1;
    nvic_recompute_state(s);
}

bool nvic_has_pending(NVICState *s) {
    // A pending exception can preempt if its group priority is strictly
    // less than the current execution priority
    return (s->vectpending != 0 && s->vectpending_prio < s->exception_prio);
}

int nvic_acknowledge(NVICState *s) {
    int pending = s->vectpending;
    if (pending == 0) {
        return 0;
    }

    VecInfo *vec = &s->vectors[pending];
    vec->active = 1;
    vec->pending = 0;

    log_info("[NVIC] Acknowledge exception %d (prio=%d)\n", pending, vec->prio);

    nvic_recompute_state(s);
    return pending;
}

void nvic_complete(NVICState *s, int exception) {
    if (exception <= 0 || exception >= NVIC_MAX_VECTORS) {
        return;
    }
    s->vectors[exception].active = 0;
    log_info("[NVIC] Complete exception %d\n", exception);
    nvic_recompute_state(s);
}

// Find next enabled IRQ in round-robin order for BB-count interrupt injection
int nvic_next_enabled_irq(NVICState *s, int *rr_idx) {
    int n = s->num_irq;
    if (n <= 0) return -1;

    for (int i = 0; i < n; i++) {
        int idx = (*rr_idx + i) % n;
        int exc = EXC_EXTERNAL_BASE + idx;
        if (s->vectors[exc].enabled) {
            *rr_idx = (idx + 1) % n;
            return exc;
        }
    }

    // No enabled IRQs — also try SysTick
    if (s->vectors[EXC_SYSTICK].enabled) {
        return EXC_SYSTICK;
    }

    return -1;
}

// ============================================================================
// MMIO Register Read Helpers
// ============================================================================

// Read NVIC_ISER or NVIC_ICER (both return current enable state)
static uint32_t nvic_read_irq_enable(NVICState *s, uint32_t offset) {
    // offset is relative to NVIC_ISER_BASE (0x100), each register covers 32 IRQs
    int reg_idx = offset / 4;
    int base_irq = reg_idx * 32;
    uint32_t val = 0;

    for (int i = 0; i < 32; i++) {
        int exc = base_irq + i + EXC_EXTERNAL_BASE;
        if (exc < EXC_EXTERNAL_BASE + s->num_irq) {
            if (s->vectors[exc].enabled) {
                val |= (1U << i);
            }
        }
    }
    return val;
}

static uint32_t nvic_read_irq_pending(NVICState *s, uint32_t offset) {
    int reg_idx = offset / 4;
    int base_irq = reg_idx * 32;
    uint32_t val = 0;

    for (int i = 0; i < 32; i++) {
        int exc = base_irq + i + EXC_EXTERNAL_BASE;
        if (exc < EXC_EXTERNAL_BASE + s->num_irq) {
            if (s->vectors[exc].pending) {
                val |= (1U << i);
            }
        }
    }
    return val;
}

static uint32_t nvic_read_irq_active(NVICState *s, uint32_t offset) {
    int reg_idx = offset / 4;
    int base_irq = reg_idx * 32;
    uint32_t val = 0;

    for (int i = 0; i < 32; i++) {
        int exc = base_irq + i + EXC_EXTERNAL_BASE;
        if (exc < EXC_EXTERNAL_BASE + s->num_irq) {
            if (s->vectors[exc].active) {
                val |= (1U << i);
            }
        }
    }
    return val;
}

static uint32_t nvic_read_irq_priority(NVICState *s, uint32_t offset) {
    // Each 32-bit register contains priorities for 4 IRQs (8 bits each)
    int base_irq = offset;  // offset is byte offset from IPR base
    uint32_t val = 0;

    for (int i = 0; i < 4; i++) {
        int exc = base_irq + i + EXC_EXTERNAL_BASE;
        if (exc < EXC_EXTERNAL_BASE + s->num_irq) {
            uint8_t prio = (uint8_t)(s->vectors[exc].prio & s->prio_mask);
            val |= ((uint32_t)prio << (i * 8));
        }
    }
    return val;
}

// ============================================================================
// MMIO Register Write Helpers
// ============================================================================

static void nvic_write_irq_enable_set(NVICState *s, uint32_t offset, uint32_t val) {
    int reg_idx = offset / 4;
    int base_irq = reg_idx * 32;

    for (int i = 0; i < 32; i++) {
        if (val & (1U << i)) {
            int exc = base_irq + i + EXC_EXTERNAL_BASE;
            if (exc < EXC_EXTERNAL_BASE + s->num_irq) {
                s->vectors[exc].enabled = 1;
                log_debug("[NVIC] Enable IRQ %d (exception %d)\n", base_irq + i, exc);
            }
        }
    }
    nvic_recompute_state(s);
}

static void nvic_write_irq_enable_clear(NVICState *s, uint32_t offset, uint32_t val) {
    int reg_idx = offset / 4;
    int base_irq = reg_idx * 32;

    for (int i = 0; i < 32; i++) {
        if (val & (1U << i)) {
            int exc = base_irq + i + EXC_EXTERNAL_BASE;
            if (exc < EXC_EXTERNAL_BASE + s->num_irq) {
                s->vectors[exc].enabled = 0;
                log_debug("[NVIC] Disable IRQ %d (exception %d)\n", base_irq + i, exc);
            }
        }
    }
    nvic_recompute_state(s);
}

static void nvic_write_irq_pending_set(NVICState *s, uint32_t offset, uint32_t val) {
    int reg_idx = offset / 4;
    int base_irq = reg_idx * 32;

    for (int i = 0; i < 32; i++) {
        if (val & (1U << i)) {
            int exc = base_irq + i + EXC_EXTERNAL_BASE;
            if (exc < EXC_EXTERNAL_BASE + s->num_irq) {
                s->vectors[exc].pending = 1;
                log_debug("[NVIC] Set pending IRQ %d (exception %d)\n", base_irq + i, exc);
            }
        }
    }
    nvic_recompute_state(s);
}

static void nvic_write_irq_pending_clear(NVICState *s, uint32_t offset, uint32_t val) {
    int reg_idx = offset / 4;
    int base_irq = reg_idx * 32;

    for (int i = 0; i < 32; i++) {
        if (val & (1U << i)) {
            int exc = base_irq + i + EXC_EXTERNAL_BASE;
            if (exc < EXC_EXTERNAL_BASE + s->num_irq) {
                s->vectors[exc].pending = 0;
                log_debug("[NVIC] Clear pending IRQ %d (exception %d)\n", base_irq + i, exc);
            }
        }
    }
    nvic_recompute_state(s);
}

static void nvic_write_irq_priority(NVICState *s, uint32_t offset, uint32_t val) {
    int base_irq = offset;  // byte offset from IPR base

    for (int i = 0; i < 4; i++) {
        int exc = base_irq + i + EXC_EXTERNAL_BASE;
        if (exc < EXC_EXTERNAL_BASE + s->num_irq) {
            uint8_t prio = (uint8_t)((val >> (i * 8)) & 0xFF);
            prio &= s->prio_mask;  // Only implemented bits
            s->vectors[exc].prio = prio;
            log_debug("[NVIC] Set priority IRQ %d = 0x%02x\n", base_irq + i, prio);
        }
    }
    nvic_recompute_state(s);
}

// Read system handler priority (SHPR1/2/3)
static uint32_t nvic_read_shpr(NVICState *s, uint32_t offset) {
    // SHPR1 at offset 0xD18 covers exceptions 4-7
    // SHPR2 at offset 0xD1C covers exceptions 8-11
    // SHPR3 at offset 0xD20 covers exceptions 12-15
    int base_exc;
    if (offset == SCB_SHPR1) base_exc = 4;
    else if (offset == SCB_SHPR2) base_exc = 8;
    else base_exc = 12;

    uint32_t val = 0;
    for (int i = 0; i < 4; i++) {
        int exc = base_exc + i;
        if (exc < EXC_EXTERNAL_BASE) {
            uint8_t prio = (uint8_t)(s->vectors[exc].prio & s->prio_mask);
            val |= ((uint32_t)prio << (i * 8));
        }
    }
    return val;
}

// Write system handler priority (SHPR1/2/3)
static void nvic_write_shpr(NVICState *s, uint32_t offset, uint32_t val) {
    int base_exc;
    if (offset == SCB_SHPR1) base_exc = 4;
    else if (offset == SCB_SHPR2) base_exc = 8;
    else base_exc = 12;

    for (int i = 0; i < 4; i++) {
        int exc = base_exc + i;
        // Skip fixed-priority exceptions and reserved slots
        if (exc >= EXC_EXTERNAL_BASE) continue;
        if (exc == EXC_RESET || exc == EXC_NMI || exc == EXC_HARDFAULT) continue;
        if (exc >= 7 && exc <= 10) continue;  // Reserved
        if (exc == 13) continue;  // Reserved

        uint8_t prio = (uint8_t)((val >> (i * 8)) & 0xFF);
        prio &= s->prio_mask;
        s->vectors[exc].prio = prio;
        log_debug("[NVIC] Set system handler %d priority = 0x%02x\n", exc, prio);
    }
    nvic_recompute_state(s);
}

// ============================================================================
// MMIO Register Read
// ============================================================================

uint32_t nvic_read(NVICState *s, uint32_t addr, int size) {
    uint32_t offset = addr - SCS_BASE;
    uint32_t val = 0;

    // NVIC_ISER / NVIC_ICER (both read as current enable state)
    if (offset >= NVIC_ISER_BASE && offset <= NVIC_ISER_END) {
        val = nvic_read_irq_enable(s, offset - NVIC_ISER_BASE);
    } else if (offset >= NVIC_ICER_BASE && offset <= NVIC_ICER_END) {
        val = nvic_read_irq_enable(s, offset - NVIC_ICER_BASE);
    }
    // NVIC_ISPR / NVIC_ICPR (both read as current pending state)
    else if (offset >= NVIC_ISPR_BASE && offset <= NVIC_ISPR_END) {
        val = nvic_read_irq_pending(s, offset - NVIC_ISPR_BASE);
    } else if (offset >= NVIC_ICPR_BASE && offset <= NVIC_ICPR_END) {
        val = nvic_read_irq_pending(s, offset - NVIC_ICPR_BASE);
    }
    // NVIC_IABR (read-only)
    else if (offset >= NVIC_IABR_BASE && offset <= NVIC_IABR_END) {
        val = nvic_read_irq_active(s, offset - NVIC_IABR_BASE);
    }
    // NVIC_IPR (priority registers)
    else if (offset >= NVIC_IPR_BASE && offset <= NVIC_IPR_END) {
        val = nvic_read_irq_priority(s, offset - NVIC_IPR_BASE);
    }
    // SCB registers
    else if (offset == SCB_ICTR) {
        // INTLINESNUM: number of 32-IRQ groups minus 1
        val = (s->num_irq + 31) / 32 - 1;
    } else if (offset == SCB_ICSR) {
        // Build ICSR from current state
        // VECTACTIVE [8:0]: current active exception
        for (int i = 1; i < EXC_EXTERNAL_BASE + s->num_irq; i++) {
            if (s->vectors[i].active) {
                val |= (i & 0x1FF);
                break;
            }
        }
        // RETTOBASE [11]: 1 if only one exception active
        int active_count = 0;
        for (int i = 1; i < EXC_EXTERNAL_BASE + s->num_irq; i++) {
            if (s->vectors[i].active) active_count++;
        }
        if (active_count <= 1) val |= (1 << 11);
        // VECTPENDING [20:12]
        val |= ((s->vectpending & 0x1FF) << 12);
        // PENDSTSET [26]
        if (s->vectors[EXC_SYSTICK].pending) val |= (1 << 26);
        // PENDSVSET [28]
        if (s->vectors[EXC_PENDSV].pending) val |= (1 << 28);
        // NMIPENDSET [31]
        if (s->vectors[EXC_NMI].pending) val |= (1U << 31);
    } else if (offset == SCB_VTOR) {
        val = s->vtor;
    } else if (offset == SCB_AIRCR) {
        val = AIRCR_VECTKEY_READ | ((s->prigroup & 0x7) << 8);
    } else if (offset == SCB_SCR) {
        val = s->scr;
    } else if (offset == SCB_CCR) {
        val = s->ccr;
    } else if (offset == SCB_SHPR1 || offset == SCB_SHPR2 || offset == SCB_SHPR3) {
        val = nvic_read_shpr(s, offset);
    } else if (offset == SCB_SHCSR) {
        val = s->shcsr;
        // Add active/pending bits from vector state
        if (s->vectors[EXC_MEMMANAGE].active) val |= (1 << 0);
        if (s->vectors[EXC_BUSFAULT].active) val |= (1 << 1);
        if (s->vectors[EXC_USAGEFAULT].active) val |= (1 << 3);
        if (s->vectors[EXC_SVCALL].active) val |= (1 << 7);
        if (s->vectors[EXC_DEBUGMON].active) val |= (1 << 8);
        if (s->vectors[EXC_PENDSV].active) val |= (1 << 10);
        if (s->vectors[EXC_SYSTICK].active) val |= (1 << 11);
        if (s->vectors[EXC_USAGEFAULT].pending) val |= (1 << 12);
        if (s->vectors[EXC_MEMMANAGE].pending) val |= (1 << 13);
        if (s->vectors[EXC_BUSFAULT].pending) val |= (1 << 14);
        if (s->vectors[EXC_SVCALL].pending) val |= (1 << 15);
    } else if (offset == SCB_CFSR) {
        val = s->cfsr;
    } else if (offset == SCB_HFSR) {
        val = s->hfsr;
    } else {
        log_debug("[NVIC] Unhandled read at 0x%08x (offset 0x%03x)\n", addr, offset);
        val = 0;
    }

    log_debug("[NVIC] Read  0x%08x => 0x%08x (size=%d)\n", addr, val, size);
    return val;
}

// ============================================================================
// MMIO Register Write
// ============================================================================

void nvic_write(NVICState *s, uint32_t addr, uint32_t val, int size) {
    uint32_t offset = addr - SCS_BASE;

    log_debug("[NVIC] Write 0x%08x <= 0x%08x (size=%d)\n", addr, val, size);

    // NVIC_ISER (set enable)
    if (offset >= NVIC_ISER_BASE && offset <= NVIC_ISER_END) {
        nvic_write_irq_enable_set(s, offset - NVIC_ISER_BASE, val);
    }
    // NVIC_ICER (clear enable)
    else if (offset >= NVIC_ICER_BASE && offset <= NVIC_ICER_END) {
        nvic_write_irq_enable_clear(s, offset - NVIC_ICER_BASE, val);
    }
    // NVIC_ISPR (set pending)
    else if (offset >= NVIC_ISPR_BASE && offset <= NVIC_ISPR_END) {
        nvic_write_irq_pending_set(s, offset - NVIC_ISPR_BASE, val);
    }
    // NVIC_ICPR (clear pending)
    else if (offset >= NVIC_ICPR_BASE && offset <= NVIC_ICPR_END) {
        nvic_write_irq_pending_clear(s, offset - NVIC_ICPR_BASE, val);
    }
    // NVIC_IABR (read-only, writes ignored)
    else if (offset >= NVIC_IABR_BASE && offset <= NVIC_IABR_END) {
        log_debug("[NVIC] Write to read-only IABR ignored\n");
    }
    // NVIC_IPR (priority)
    else if (offset >= NVIC_IPR_BASE && offset <= NVIC_IPR_END) {
        nvic_write_irq_priority(s, offset - NVIC_IPR_BASE, val);
    }
    // SCB registers
    else if (offset == SCB_ICSR) {
        // Write-1-to-set/clear bits
        if (val & (1 << 25)) s->vectors[EXC_SYSTICK].pending = 0;  // PENDSTCLR
        if (val & (1 << 26)) s->vectors[EXC_SYSTICK].pending = 1;  // PENDSTSET
        if (val & (1 << 27)) s->vectors[EXC_PENDSV].pending = 0;   // PENDSVCLR
        if (val & (1 << 28)) s->vectors[EXC_PENDSV].pending = 1;   // PENDSVSET
        if (val & (1U << 31)) s->vectors[EXC_NMI].pending = 1;     // NMIPENDSET
        nvic_recompute_state(s);
    } else if (offset == SCB_VTOR) {
        // VTOR must be aligned to the vector table size (at least 128 bytes)
        s->vtor = val & 0xFFFFFF80;
        log_info("[NVIC] VTOR set to 0x%08x\n", s->vtor);
    } else if (offset == SCB_AIRCR) {
        // Check VECTKEY
        if ((val & AIRCR_VECTKEY_MASK) != AIRCR_VECTKEY_WRITE) {
            log_info("[NVIC] AIRCR write with invalid VECTKEY (0x%04x), ignored\n",
                     (val >> 16) & 0xFFFF);
            return;
        }
        s->prigroup = (val >> 8) & 0x7;
        log_info("[NVIC] PRIGROUP set to %d\n", s->prigroup);
        // SYSRESETREQ
        if (val & (1 << 2)) {
            log_info("[NVIC] System reset requested\n");
        }
        nvic_recompute_state(s);
    } else if (offset == SCB_SCR) {
        s->scr = val & 0x1F;
    } else if (offset == SCB_CCR) {
        s->ccr = val;
    } else if (offset == SCB_SHPR1 || offset == SCB_SHPR2 || offset == SCB_SHPR3) {
        nvic_write_shpr(s, offset, val);
    } else if (offset == SCB_SHCSR) {
        // Enable bits for MemManage, BusFault, UsageFault
        uint32_t enable_mask = (1 << 16) | (1 << 17) | (1 << 18);
        s->shcsr = val & enable_mask;
        s->vectors[EXC_MEMMANAGE].enabled = (val >> 16) & 1;
        s->vectors[EXC_BUSFAULT].enabled = (val >> 17) & 1;
        s->vectors[EXC_USAGEFAULT].enabled = (val >> 18) & 1;
        nvic_recompute_state(s);
    } else if (offset == SCB_CFSR) {
        // Write-1-to-clear
        s->cfsr &= ~val;
    } else if (offset == SCB_HFSR) {
        // Write-1-to-clear
        s->hfsr &= ~val;
    } else if (offset == NVIC_STIR) {
        // Software Trigger Interrupt Register
        int irq = val & 0x1FF;
        if (irq < s->num_irq) {
            log_info("[NVIC] Software trigger IRQ %d\n", irq);
            nvic_set_pending(s, irq);
        }
    } else {
        log_debug("[NVIC] Unhandled write at 0x%08x (offset 0x%03x) = 0x%08x\n",
                  addr, offset, val);
    }
}

// ============================================================================
// EXC_RETURN detection
// ============================================================================

bool nvic_is_exc_return(uint64_t addr) {
    // EXC_RETURN values have bits [31:5] all set to 1
    // Valid patterns: 0xFFFFFFxx where bits [4:0] encode return info
    return (addr & 0xFFFFFF00) == 0xFFFFFF00;
}

// ============================================================================
// Exception Entry
// ============================================================================

void nvic_exception_entry(NVICState *s, MemoryState *mem, Emulate *emu, int exception) {
    AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");

    // Read current register state
    uint32_t r0   = (uint32_t)mem->getValue("r0");
    uint32_t r1   = (uint32_t)mem->getValue("r1");
    uint32_t r2   = (uint32_t)mem->getValue("r2");
    uint32_t r3   = (uint32_t)mem->getValue("r3");
    uint32_t r12  = (uint32_t)mem->getValue("r12");
    uint32_t lr   = (uint32_t)mem->getValue("lr");
    uint32_t pc   = (uint32_t)emu->getExecuteAddress().getOffset();
    uint32_t xpsr = (uint32_t)mem->getValue("cpsr");
    uint32_t sp   = (uint32_t)mem->getValue("sp");

    // Ensure 8-byte alignment (bit 9 of xPSR records if adjustment was made)
    uint32_t frameptr;
    if (sp & 0x4) {
        frameptr = sp - 4 - FRAME_SIZE;  // Align down
        xpsr |= (1 << 9);  // Record alignment adjustment
    } else {
        frameptr = sp - FRAME_SIZE;
    }

    log_info("[NVIC] Exception entry: exc=%d, SP=0x%08x -> 0x%08x, PC=0x%08x\n",
             exception, sp, frameptr, pc);

    // Push stack frame: {R0, R1, R2, R3, R12, LR, ReturnAddr, xPSR}
    mem->setValue(ram, frameptr + FRAME_R0_OFFSET,   4, r0);
    mem->setValue(ram, frameptr + FRAME_R1_OFFSET,   4, r1);
    mem->setValue(ram, frameptr + FRAME_R2_OFFSET,   4, r2);
    mem->setValue(ram, frameptr + FRAME_R3_OFFSET,   4, r3);
    mem->setValue(ram, frameptr + FRAME_R12_OFFSET,  4, r12);
    mem->setValue(ram, frameptr + FRAME_LR_OFFSET,   4, lr);
    mem->setValue(ram, frameptr + FRAME_PC_OFFSET,   4, pc);
    mem->setValue(ram, frameptr + FRAME_XPSR_OFFSET, 4, xpsr);

    // Update SP
    mem->setValue("sp", frameptr);

    // Set LR to EXC_RETURN
    // For simplicity: always use MSP, return to Thread mode
    // If we were in Handler mode (another exception active), return to Handler
    bool returning_to_handler = false;
    for (int i = 1; i < EXC_EXTERNAL_BASE + s->num_irq; i++) {
        if (i != exception && s->vectors[i].active) {
            returning_to_handler = true;
            break;
        }
    }

    uint32_t exc_return;
    if (returning_to_handler) {
        exc_return = EXC_RETURN_HANDLER_MSP;  // 0xFFFFFFF1
    } else {
        exc_return = EXC_RETURN_THREAD_MSP;   // 0xFFFFFFF9
    }
    mem->setValue("lr", exc_return);

    // Set IPSR (exception number in cpsr/xpsr bits [8:0])
    uint32_t new_xpsr = (uint32_t)mem->getValue("cpsr");
    new_xpsr = (new_xpsr & ~0x1FF) | (exception & 0x1FF);
    mem->setValue("cpsr", new_xpsr);

    // Load handler address from vector table
    uint32_t vector_addr = s->vtor + (exception * 4);
    uint32_t handler = (uint32_t)mem->getValue(ram, vector_addr, 4);

    // Handler address has Thumb bit set (bit 0), clear it for execution
    uint32_t handler_addr = handler & ~1U;

    log_info("[NVIC] Vector[%d] at 0x%08x = 0x%08x, handler at 0x%08x\n",
             exception, vector_addr, handler, handler_addr);

    // Set PC to handler
    emu->setExecuteAddress(Address(ram, handler_addr));
}

// ============================================================================
// Exception Return
// ============================================================================

void nvic_exception_return(NVICState *s, MemoryState *mem, Emulate *emu, uint32_t exc_return) {
    AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");

    // Find which exception is returning (the highest-priority active one)
    int returning_exc = 0;
    for (int i = 1; i < EXC_EXTERNAL_BASE + s->num_irq; i++) {
        if (s->vectors[i].active) {
            returning_exc = i;
            break;
        }
    }

    if (returning_exc == 0) {
        log_info("[NVIC] Exception return with no active exception, EXC_RETURN=0x%08x\n", exc_return);
        // Still try to unstack
    }

    log_info("[NVIC] Exception return: exc=%d, EXC_RETURN=0x%08x\n", returning_exc, exc_return);

    // Read current SP (based on EXC_RETURN bit 2: 0=MSP, 1=PSP)
    // For simplicity, always use sp register
    uint32_t frameptr = (uint32_t)mem->getValue("sp");

    // Pop stack frame
    uint32_t r0   = (uint32_t)mem->getValue(ram, frameptr + FRAME_R0_OFFSET,   4);
    uint32_t r1   = (uint32_t)mem->getValue(ram, frameptr + FRAME_R1_OFFSET,   4);
    uint32_t r2   = (uint32_t)mem->getValue(ram, frameptr + FRAME_R2_OFFSET,   4);
    uint32_t r3   = (uint32_t)mem->getValue(ram, frameptr + FRAME_R3_OFFSET,   4);
    uint32_t r12  = (uint32_t)mem->getValue(ram, frameptr + FRAME_R12_OFFSET,  4);
    uint32_t lr   = (uint32_t)mem->getValue(ram, frameptr + FRAME_LR_OFFSET,   4);
    uint32_t pc   = (uint32_t)mem->getValue(ram, frameptr + FRAME_PC_OFFSET,   4);
    uint32_t xpsr = (uint32_t)mem->getValue(ram, frameptr + FRAME_XPSR_OFFSET, 4);

    // Restore SP (account for 8-byte alignment adjustment)
    uint32_t new_sp = frameptr + FRAME_SIZE;
    if (xpsr & (1 << 9)) {
        new_sp += 4;  // Undo alignment adjustment
    }

    // Restore registers
    mem->setValue("r0", r0);
    mem->setValue("r1", r1);
    mem->setValue("r2", r2);
    mem->setValue("r3", r3);
    mem->setValue("r12", r12);
    mem->setValue("lr", lr);
    mem->setValue("sp", new_sp);
    mem->setValue("cpsr", xpsr);

    // Clear active bit for returning exception
    if (returning_exc > 0) {
        nvic_complete(s, returning_exc);
    }

    // Clear IPSR if returning to Thread mode
    bool return_to_handler = !(exc_return & (1 << 3));
    if (!return_to_handler) {
        // Returning to Thread mode: clear IPSR
        uint32_t cpsr = (uint32_t)mem->getValue("cpsr");
        cpsr &= ~0x1FF;
        mem->setValue("cpsr", cpsr);
    }

    log_info("[NVIC] Return to PC=0x%08x, SP=0x%08x, LR=0x%08x\n", pc, new_sp, lr);

    // Set PC to return address
    emu->setExecuteAddress(Address(ram, pc & ~1U));
}
