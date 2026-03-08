/*
 * Ghidralligator - Cortex-M Hooks
 *
 * Provides hooks for ARM Cortex-M targets, including NVIC initialization
 * and common system instruction handling (WFI, DSB, ISB, DMB, etc.).
 *
 * Licensed under the Apache License, Version 2.0
 */

#include <cstdio>
#include "globals.h"
#include "fuzzers.h"
#include "memory.h"
#include "utils.h"
#include "nvic.h"
#include "mmio.h"

//////////////// Callbacks ///////////////////

// Always-succeed handler for hasExclusiveAccess (STREX success)
// Returns 1 in output and lets the rest of the instruction execute
class cortexm_ExclusiveSuccessCallback : public BreakCallBack {
public:
  virtual bool pcodeCallback(PcodeOpRaw *curop);
};
bool cortexm_ExclusiveSuccessCallback::pcodeCallback(PcodeOpRaw *curop) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  // Set output to 1 (exclusive access granted = STREX will succeed)
  VarnodeData *outvn = curop->getOutput();
  if (outvn != nullptr) {
    mem->setValue(outvn->space, outvn->offset, outvn->size, 1);
  }
  // Return true so executeCallother calls fallthruOp() to continue
  // with the remaining pcode ops in this instruction
  return true;
};

// NOP handler for unimplemented pcode ops
class cortexm_NopCallback : public BreakCallBack {
public:
  virtual bool pcodeCallback(PcodeOpRaw *curop);
};
bool cortexm_NopCallback::pcodeCallback(PcodeOpRaw *curop) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t pc = emulate->getExecuteAddress().getOffset();

  // Determine instruction size (Thumb: 2 or 4 bytes)
  // For Thumb-2 instructions, the first halfword determines size
  uint32_t next_ins = pc + 4;  // Default to 4 for 32-bit Thumb-2

  log_debug("[HOOK] cortexm nop at 0x%x\n", pc);

  emulate->setExecuteAddress(Address(ram, next_ins));
  return true;
};

// Hook malloc for ASAN feature
class cortexm_MallocCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool cortexm_MallocCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t size = mem->getValue("r0");
  uint32_t lr = mem->getValue("lr");
  uint32_t addr_buf = 0;

  log_info("[HOOK] malloc: size: 0x%x\n", size);

  addr_buf = (uint32_t)heap_allocate(size, true, ram, mem);
  mem->setValue("r0", addr_buf);

  emulate->setExecuteAddress(Address(ram, lr & ~1U));
  return true;
};

// Hook free for ASAN feature
class cortexm_FreeCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool cortexm_FreeCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t addr_buf = mem->getValue("r0");
  uint32_t lr = mem->getValue("lr");

  log_info("[HOOK] free: 0x%x\n", addr_buf);

  if (heap_free(addr_buf)) {
      emulate->setExecuteAddress(Address(ram, lr & ~1U));
      return true;
  }

  return false;
};

// Hook HAL_GetTick - return incrementing value so timeout loops terminate
class cortexm_GetTickCallback : public BreakCallBack {
public:
  uint32_t tick_counter = 0;
  virtual bool addressCallback(const Address &addr);
};
bool cortexm_GetTickCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t lr = mem->getValue("lr");

  tick_counter += 100;
  mem->setValue("r0", tick_counter);

  log_debug("[HOOK] HAL_GetTick -> %u\n", tick_counter);
  emulate->setExecuteAddress(Address(ram, lr & ~1U));
  return true;
};

// Hook function to skip (return immediately via LR)
class cortexm_SkipFunctionCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool cortexm_SkipFunctionCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t lr = mem->getValue("lr");

  log_debug("[HOOK] Skip function at 0x%lx\n", addr.getOffset());
  mem->setValue("r0", 0);
  emulate->setExecuteAddress(Address(ram, lr & ~1U));
  return true;
};

// Hook UART init - set up UART handle manually to avoid GPIO-heavy HAL init
class cortexm_UartInitCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool cortexm_UartInitCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t lr = mem->getValue("lr");

  // Set up UART handle at 0x20000048 (handle 0)
  uint32_t handle_addr = 0x20000048;
  mem->setValue(ram, handle_addr, 4, 0x40004800);       // Offset 0x00: Instance = USART3
  mem->setValue(ram, handle_addr + 0x8c, 4, 0x20);      // Offset 0x8c: RxState = HAL_UART_STATE_READY

  log_debug("[HOOK] UART init: handle at 0x%x, instance=0x40004800, RxState=0x20\n", handle_addr);

  mem->setValue("r0", 0);  // return HAL_OK
  emulate->setExecuteAddress(Address(ram, lr & ~1U));
  return true;
};

// Hook printf
class cortexm_PrintfCallback : public BreakCallBack {
public:
  virtual bool addressCallback(const Address &addr);
};
bool cortexm_PrintfCallback::addressCallback(const Address &addr) {
  MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
  AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
  uint32_t lr = mem->getValue("lr");
  uint32_t address_char = mem->getValue("r0");
  char* pChar = NULL;

  if (mem_get_string(mem, address_char, &pChar)) {
      log_info("[HOOK] printf: %s\n", pChar);
      free(pChar);
      pChar = NULL;
  } else {
      log_info("[HOOK] printf: Failed to get string\n");
  }

  emulate->setExecuteAddress(Address(ram, lr & ~1U));
  return true;
};


//////////////////////////////////////////////


// NVIC instance (static, persists across test cases)
static NVICState nvic_state;

// MMIO state (static, persists across test cases)
static MMIOState mmio_state;

// Register this particular fuzzer backend
namespace cortexm {

  // Define where to trigger the insertion routine callback
  uint64_t get_insert_point() {
    return G_LOCAL_CONFIG.start_address;
  }

  // This function is used to describe how to write the test_case into the target program
  void insert_test_case(Emulate* emulate, uint8_t* pTest_case, uint64_t test_case_len, bool* ret_mode) {
    // When MMIO fuzzing is active, test case is consumed via MMIO reads —
    // no need to inject into emulated memory
    if (G_MMIO) {
      // Set up UART handle at 0x20000048 (USART3)
      MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
      AddrSpace *ram = mem->getTranslate()->getSpaceByName("ram");
      uint32_t handle_addr = 0x20000048;
      mem->setValue(ram, handle_addr, 4, 0x40004800);      // Instance = USART3
      mem->setValue(ram, handle_addr + 0x8c, 4, 0x20);     // RxState = READY

      // Set _DAT_200000dc = 0 (UART handle index)
      mem->setValue(ram, 0x200000dc, 4, 0);

      // SP already set by config.json registers, just need frame setup
      // FUN_08003aa8 does push {r7,lr}; sub sp,#0x18
      // SP is 0x20020000, after push it's 0x2001FFF8, after sub it's 0x2001FFE0
      // Start at 0x8003b00 which is inside the function body
      uint32_t sp = 0x20020000 - 8 - 0x18;  // account for push + sub
      mem->setValue("sp", sp);

      *ret_mode = false;
      return;
    }

    MemoryState *mem = static_cast<EmulateMemory *>(emulate)->getMemoryState();
    AddrSpace *spc = mem->getTranslate()->getSpaceByName("ram");

    uint32_t addr_test_case = 0;

    if (test_case_len > 0x1000) {
      emulate->setHalt(true);
      return;
    }

    // Allocate buffer for the test case on the emulated heap
    addr_test_case = heap_allocate(test_case_len, true, spc, mem);
    if (addr_test_case == 0) {
        log_error("insert_test_case: Failed to allocate virtual memory for test_case - sz: 0x%lx\n", test_case_len);
        exit(-1);
    }

    mem_write(addr_test_case, pTest_case, test_case_len, mem);

    // Pass test case info via r0 (pointer) and r1 (length)
    mem->setValue("r0", addr_test_case);
    mem->setValue("r1", test_case_len);

    *ret_mode = false;
    return;
  };


  // Register user defined hooks and NVIC/MMIO initialization
  std::map<uint64_t, BreakCallBack*> register_user_hooks() {
    std::map<uint64_t, BreakCallBack*> hook_map;

    // Initialize NVIC
    // STM32H753 has up to 150 external interrupts and 4 priority bits
    nvic_init(&nvic_state, 150, 4);
    G_NVIC = &nvic_state;
    log_info("[NVIC] Initialized: %d external IRQs, %d priority bits\n",
             nvic_state.num_irq, nvic_state.num_prio_bits);

    // Initialize MMIO fuzzing engine
    // Ranges and irq_interval are populated by parser.cc from config.json
    mmio_init(&mmio_state);
    G_MMIO = &mmio_state;
    log_info("[MMIO] Fuzzing engine initialized\n");

    // Hook HAL_GetTick (0x080024d8) so timeout loops terminate
    cortexm_GetTickCallback* gettick_cb = new cortexm_GetTickCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x080024d8, gettick_cb));

    // Skip GPIO init (FUN_080036b0) - heavy MMIO polling
    cortexm_SkipFunctionCallback* skip_gpio_init = new cortexm_SkipFunctionCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x080036b0, skip_gpio_init));

    // Skip LED toggle (FUN_080037a0) - calls HAL_GPIO_ReadPin in loop
    cortexm_SkipFunctionCallback* skip_led = new cortexm_SkipFunctionCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x080037a0, skip_led));

    // Skip FUN_08003920 - does GPIO reads
    cortexm_SkipFunctionCallback* skip_3920 = new cortexm_SkipFunctionCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x08003920, skip_3920));

    // Skip FUN_08003cd8 - init function
    cortexm_SkipFunctionCallback* skip_3cd8 = new cortexm_SkipFunctionCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x08003cd8, skip_3cd8));

    // Hook UART init (FUN_080037f0) - set up handle without GPIO ops
    cortexm_UartInitCallback* uart_init_cb = new cortexm_UartInitCallback();
    hook_map.insert(pair<uint64_t, BreakCallBack*>(0x080037f0, uart_init_cb));

    log_info("[Loader]  %ld user-defined hooks applied\n", hook_map.size());
    return hook_map;
  };


  // Register opcodes hooks for Cortex-M specific instructions
  std::map<string, BreakCallBack*> register_opcodes_hooks() {
    std::map<string, BreakCallBack*> opcode_hooks;

    // NOP handler for various unimplemented pcode ops
    cortexm_NopCallback* nop_callback = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"HintPreloadData", nop_callback));

    // Additional NOP handlers for common Cortex-M instructions that
    // Sleigh may emit as CALLOTHER pcode ops
    cortexm_NopCallback* nop_cb2 = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"HintPreloadDataForWrite", nop_cb2));

    cortexm_NopCallback* nop_cb3 = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"HintPreloadInstruction", nop_cb3));

    cortexm_NopCallback* nop_cb4 = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"DataMemoryBarrier", nop_cb4));

    cortexm_NopCallback* nop_cb5 = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"DataSynchronizationBarrier", nop_cb5));

    cortexm_NopCallback* nop_cb6 = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"InstructionSynchronizationBarrier", nop_cb6));

    // Interrupt enable/disable ops (cpsie/cpsid) - NOP them
    cortexm_NopCallback* nop_cpsid = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"disableIRQinterrupts", nop_cpsid));

    cortexm_NopCallback* nop_cpsie = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"enableIRQinterrupts", nop_cpsie));

    cortexm_NopCallback* nop_wfi = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"WaitForInterrupt", nop_wfi));

    cortexm_NopCallback* nop_wfe = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"WaitForEvent", nop_wfe));

    cortexm_NopCallback* nop_svc = new cortexm_NopCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"software_interrupt", nop_svc));

    // hasExclusiveAccess - always return success so STREX completes
    cortexm_ExclusiveSuccessCallback* exc_success = new cortexm_ExclusiveSuccessCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"hasExclusiveAccess", exc_success));

    // Exclusive access ops - ExclusiveAccess/ClearExclusiveLocal just continue
    cortexm_ExclusiveSuccessCallback* nop_exc2 = new cortexm_ExclusiveSuccessCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"ClearExclusiveLocal", nop_exc2));

    cortexm_ExclusiveSuccessCallback* nop_exc3 = new cortexm_ExclusiveSuccessCallback();
    opcode_hooks.insert(pair<string, BreakCallBack*>((string)"ExclusiveAccess", nop_exc3));

    log_info("[Loader]  %ld callback(s) for opcodes applied\n", opcode_hooks.size());
    return opcode_hooks;
  };

  // Register the cortexm target
  fuzz_target Fuzz_Target("cortexm", get_insert_point, insert_test_case, register_user_hooks, register_opcodes_hooks);
};
