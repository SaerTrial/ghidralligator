/*
 * Ghidralligator - ARM Cortex-M NVIC Interrupt Controller
 *
 * Implements the Nested Vectored Interrupt Controller (NVIC) for
 * Cortex-M emulation, modeled after QEMU's armv7m_nvic.c and the
 * ARM Architecture Reference Manual.
 *
 * Licensed under the Apache License, Version 2.0
 */

#ifndef NVIC_H
#define NVIC_H

#include "globals.h"

// SCS (System Control Space) address range
#define SCS_BASE        0xE000E000
#define SCS_END         0xE000EFFF

// NVIC register offsets from SCS_BASE
#define NVIC_ISER_BASE  0x100   // Interrupt Set Enable
#define NVIC_ISER_END   0x13F
#define NVIC_ICER_BASE  0x180   // Interrupt Clear Enable
#define NVIC_ICER_END   0x1BF
#define NVIC_ISPR_BASE  0x200   // Interrupt Set Pending
#define NVIC_ISPR_END   0x23F
#define NVIC_ICPR_BASE  0x280   // Interrupt Clear Pending
#define NVIC_ICPR_END   0x2BF
#define NVIC_IABR_BASE  0x300   // Interrupt Active Bit
#define NVIC_IABR_END   0x33F
#define NVIC_IPR_BASE   0x400   // Interrupt Priority
#define NVIC_IPR_END    0x5EF

// SysTick register offsets from SCS_BASE
#define SYST_CSR        0x010   // SysTick Control and Status
#define SYST_RVR        0x014   // SysTick Reload Value
#define SYST_CVR        0x018   // SysTick Current Value
#define SYST_CALIB      0x01C   // SysTick Calibration

// SCB register offsets from SCS_BASE
#define SCB_ICTR        0x004   // Interrupt Controller Type
#define SCB_ICSR        0xD04   // Interrupt Control and State
#define SCB_VTOR        0xD08   // Vector Table Offset
#define SCB_AIRCR       0xD0C   // Application Interrupt and Reset Control
#define SCB_SCR         0xD10   // System Control
#define SCB_CCR         0xD14   // Configuration and Control
#define SCB_SHPR1       0xD18   // System Handler Priority 1 (exceptions 4-7)
#define SCB_SHPR2       0xD1C   // System Handler Priority 2 (exceptions 8-11)
#define SCB_SHPR3       0xD20   // System Handler Priority 3 (exceptions 12-15)
#define SCB_SHCSR       0xD24   // System Handler Control and State
#define SCB_CFSR        0xD28   // Configurable Fault Status
#define SCB_HFSR        0xD2C   // Hard Fault Status
#define NVIC_STIR       0xF00   // Software Trigger Interrupt

// AIRCR key values
#define AIRCR_VECTKEY_WRITE 0x05FA0000
#define AIRCR_VECTKEY_READ  0xFA050000
#define AIRCR_VECTKEY_MASK  0xFFFF0000

// Exception numbers
#define EXC_RESET       1
#define EXC_NMI         2
#define EXC_HARDFAULT   3
#define EXC_MEMMANAGE   4
#define EXC_BUSFAULT    5
#define EXC_USAGEFAULT  6
#define EXC_SVCALL      11
#define EXC_DEBUGMON    12
#define EXC_PENDSV      14
#define EXC_SYSTICK     15
#define EXC_EXTERNAL_BASE 16

// Maximum vectors: 16 internal + up to 256 external
#define NVIC_MAX_VECTORS 272

// Priority that is lower than any real priority (used as sentinel)
#define NVIC_NOEXC_PRIO 0x100

// EXC_RETURN magic values
#define EXC_RETURN_HANDLER_MSP      0xFFFFFFF1  // Return to Handler mode, MSP
#define EXC_RETURN_THREAD_MSP       0xFFFFFFF9  // Return to Thread mode, MSP
#define EXC_RETURN_THREAD_PSP       0xFFFFFFFD  // Return to Thread mode, PSP

// Per-vector state (following QEMU's VecInfo pattern)
typedef struct {
    int16_t prio;       // Priority value (lower = higher urgency)
    uint8_t enabled;    // 1 if interrupt is enabled
    uint8_t pending;    // 1 if interrupt is pending
    uint8_t active;     // 1 if interrupt is currently being serviced
    uint8_t level;      // Input level (for level-triggered interrupts)
} VecInfo;

// NVIC state
typedef struct {
    VecInfo vectors[NVIC_MAX_VECTORS];

    // SCB registers
    uint32_t vtor;      // Vector Table Offset Register
    uint32_t aircr;     // Application Interrupt and Reset Control
    uint32_t scr;       // System Control Register
    uint32_t ccr;       // Configuration and Control Register
    uint32_t shcsr;     // System Handler Control and State Register
    uint32_t cfsr;      // Configurable Fault Status Register
    uint32_t hfsr;      // Hard Fault Status Register

    // Priority grouping (from AIRCR bits [10:8])
    uint32_t prigroup;

    // Computed state (recomputed after any change)
    int vectpending;        // Exception number of highest-priority pending
    int vectpending_prio;   // Its priority
    int exception_prio;     // Priority of highest-priority active exception

    // Configuration
    int num_irq;            // Total number of external IRQs
    int num_prio_bits;      // Number of implemented priority bits (e.g., 4 for STM32H7)
    uint8_t prio_mask;      // Mask for implemented priority bits

    // SysTick registers
    uint32_t systick_csr;       // Control and Status Register
    uint32_t systick_rvr;       // Reload Value Register
    uint32_t systick_cvr;       // Current Value Register

    // Interrupt injection config (BB-count based, Fuzzware-style)
    uint32_t irq_interval;  // Fire interrupt every N basic blocks (0 = disabled)

    // Pre-enabled IRQs from config (re-applied on each reset)
    int pre_enabled_irqs[NVIC_MAX_VECTORS];
    int num_pre_enabled;
} NVICState;

// Global NVIC instance pointer (NULL when NVIC is not enabled)
inline NVICState *G_NVIC = nullptr;

// Initialization and reset
void nvic_init(NVICState *s, int num_irq, int num_prio_bits);
void nvic_reset(NVICState *s);

// MMIO register access
uint32_t nvic_read(NVICState *s, uint32_t addr, int size);
void nvic_write(NVICState *s, uint32_t addr, uint32_t val, int size);

// Interrupt management
void nvic_set_pending(NVICState *s, int irq);
void nvic_set_pending_exception(NVICState *s, int exception);
bool nvic_has_pending(NVICState *s);
int nvic_acknowledge(NVICState *s);
void nvic_complete(NVICState *s, int exception);

// Round-robin interrupt selection: find next enabled IRQ
// Returns exception number (>=16) or -1 if none enabled
int nvic_next_enabled_irq(NVICState *s, int *rr_idx);

// Exception entry/return
void nvic_exception_entry(NVICState *s, MemoryState *mem, Emulate *emu, int exception);
void nvic_exception_return(NVICState *s, MemoryState *mem, Emulate *emu, uint32_t exc_return);
bool nvic_is_exc_return(uint64_t addr);

// Check if address is in SCS MMIO range
inline bool nvic_is_scs_addr(uint64_t addr) {
    return (addr >= SCS_BASE && addr <= SCS_END);
}

#endif
