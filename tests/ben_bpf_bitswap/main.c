#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "embUnit.h"
#include "timex.h"
#include "ztimer.h"

#if BPF_COQ == 0
#include "bpf.h"
#elif BPF_COQ == 1
#include "interpreter.h"
#else
#include "ibpf_util.h"
#endif



const unsigned char bpf_input_bin[] = {
  0x71, 0x13, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xb4, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x6c, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x71, 0x15, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x6c, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x4c, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xa4, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0x71, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x5c, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x5c, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x7c, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x6c, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x4c, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x5c, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x7c, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x6c, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x4c, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x54, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/*make bitswap BPF_LOW=1 BPF_COMPCERT=0
0000000000000000 swap_bits:
;   uint8_t bit1 = ctx->bit1;
       0:	71 13 01 00 00 00 00 00	r3 = *(u8 *)(r1 + 1)
       1:	b4 02 00 00 01 00 00 00	w2 = 1
;   uint8_t mask1 = 1 << bit1;
       2:	b4 04 00 00 01 00 00 00	w4 = 1
       3:	6c 34 00 00 00 00 00 00	w4 <<= w3
;   uint8_t bit2 = ctx->bit2;
       4:	71 15 02 00 00 00 00 00	r5 = *(u8 *)(r1 + 2)
;   uint8_t mask2 = 1 << bit2;
       5:	6c 52 00 00 00 00 00 00	w2 <<= w5
;   uint8_t result = value & ~(mask1 | mask2);
       6:	bc 26 00 00 00 00 00 00	w6 = w2
       7:	4c 46 00 00 00 00 00 00	w6 |= w4
       8:	a4 06 00 00 ff ff ff ff	w6 ^= -1
;   uint8_t value = ctx->value;
       9:	71 11 00 00 00 00 00 00	r1 = *(u8 *)(r1 + 0)
;   uint8_t result = value & ~(mask1 | mask2);
      10:	bc 10 00 00 00 00 00 00	w0 = w1
      11:	5c 60 00 00 00 00 00 00	w0 &= w6
;   result |= ((value & mask1) >> bit1) << bit2;
      12:	5c 14 00 00 00 00 00 00	w4 &= w1
      13:	7c 34 00 00 00 00 00 00	w4 >>= w3
      14:	6c 54 00 00 00 00 00 00	w4 <<= w5
      15:	4c 40 00 00 00 00 00 00	w0 |= w4
;   result |= ((value & mask2) >> bit2) << bit1;
      16:	5c 12 00 00 00 00 00 00	w2 &= w1
      17:	7c 52 00 00 00 00 00 00	w2 >>= w5
      18:	6c 32 00 00 00 00 00 00	w2 <<= w3
      19:	4c 20 00 00 00 00 00 00	w0 |= w2
;   return result;
      20:	54 00 00 00 ff 00 00 00	w0 &= 255
      21:	95 00 00 00 00 00 00 00	exit
*/
        
#if BPF_COQ == 2
static uint16_t *jitted_thumb_list;

ibpf_full_state_t ibpf_state;

__attribute__ ((noinline)) void _magic_function(unsigned int ofs, struct jit_state* st){
  int res = 0;
  __asm volatile (
    "orr %[input_0], #0x1\n\t"
    "mov r12, sp\n\t"
    "sub sp, sp, #48\n\t"
    "str r12, [sp, #0]\n\t"
    "mov pc, %[input_0]\n\t"
    : [result] "=r" (res)
    : [input_1] "r" (st), [input_0] "r" (jitted_thumb_list + ofs)
    : "cc" //The instruction modifies the condition code flags
  );
  return ;
}
#else
/* ibpf defines this within the struct */
static uint8_t _bpf_stack[512];
#endif

struct bpf_input_ctx {
  uint8_t value;
  uint8_t bit1;
  uint8_t bit2;
};

struct bpf_input_ctx ctx = {
  .value = 156,
  .bit1 = 3,
  .bit2 = 6,
};

#if BPF_COQ == 1
static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};
                                        
static struct memory_region mr_ctx = {.start_addr = (uintptr_t) &ctx,
                                        .block_size = sizeof(ctx),
                                        .block_perm = Readable,
                                        .block_ptr = (unsigned char *) (uintptr_t) &ctx};
#endif



int main(void){  
  float duration = 0;
  for (int loop_size = 0; loop_size < 1000; loop_size++) {
  
#if BPF_COQ == 0
  bpf_t bpf = {
    .application = (uint8_t*)&bpf_input_bin,
    .application_len = sizeof(bpf_input_bin),
    .stack = _bpf_stack,
    .stack_size = sizeof(_bpf_stack),
    .flags = BPF_FLAG_PREFLIGHT_DONE,
  };
  bpf_setup(&bpf);
  int64_t res = 0;
  
#elif BPF_COQ == 1
  struct memory_region memory_regions[] = { mr_stack, mr_ctx };
  struct bpf_state st = {
    .state_pc = 0,
    .regsmap = {0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, (uintptr_t)_bpf_stack+512},
    .bpf_flag = vBPF_OK,
    .mrs = memory_regions,
    .mrs_num = ARRAY_SIZE(memory_regions),
    .ins = (unsigned long long *) bpf_input_bin,
    .ins_len = sizeof(bpf_input_bin),
  };
  
#else
  jitted_thumb_list = ibpf_state.jitted_thumb_list;
  ibpf_full_state_init(&ibpf_state, 2);
  ibpf_set_mem_region(&ibpf_state, &ctx, sizeof(ctx), Readable, 1);
  ibpf_set_code(&ibpf_state, bpf_input_bin, sizeof(bpf_input_bin));
  jit_alu32(&ibpf_state.st);
#endif

  uint32_t begin = ztimer_now(ZTIMER_USEC); // unsigned long long -> uint64_t
#if BPF_COQ == 0
  int result = bpf_execute_ctx(&bpf, &ctx, sizeof(ctx), &res);
  
  //printf("Vanilla-rBPF C result = 0x:%x\n", (unsigned int)res);
  
#elif BPF_COQ == 1
  int result = bpf_interpreter(&st, 10000, (uintptr_t) &ctx);
  
  //printf("flag=%d\n", st.bpf_flag);
  //printf("CertrBPF C result = 0x:%x\n", (unsigned int)result); //= 0xd4
  
#else
  int result = ibpf_interpreter(&ibpf_state.st, 10000, (uintptr_t) &ctx);
  
  //printf("flag=%d\n", ibpf_state.st.flag);
  //printf("CertrBPF-JIT C result = 0x:%x\n", (unsigned int)result);
  //_magic_function(0, &ibpf_state.st);
  //printf("CertrBPF-JIT-Pure C result = 0x:%x\n", (unsigned int)(ibpf_state.st.regs_st[0]));
#endif

  uint32_t end = ztimer_now(ZTIMER_USEC);
  duration = (float)(end-begin) + duration;
  }
  printf("execution time:%f\n", duration);
  return 0;
}
