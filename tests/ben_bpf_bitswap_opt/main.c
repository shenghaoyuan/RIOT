#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "embUnit.h"
#include "timex.h"
#include "ztimer.h"

#if BPF_COQ == 0
#include "bpf.h"
#else
#include "interpreter.h"
#endif


const unsigned char bpf_input_bin[] = {
  0x71, 0x13, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xb7, 0x04, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x6f, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x71, 0x15, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x6f, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x4f, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xa7, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0x71, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x5f, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x5f, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x7f, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x6f, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x4f, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x5f, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x7f, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x6f, 0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x4f, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x57, 0x00, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* make bitswap BPF_LOW=0 BPF_COMPCERT=0

0000000000000000 swap_bits:
;   uint8_t bit1 = ctx->bit1;
       0:	71 13 01 00 00 00 00 00	r3 = *(u8 *)(r1 + 1)
       1:	b7 02 00 00 01 00 00 00	r2 = 1
;   uint8_t mask1 = 1 << bit1;
       2:	b7 04 00 00 01 00 00 00	r4 = 1
       3:	6f 34 00 00 00 00 00 00	r4 <<= r3
;   uint8_t bit2 = ctx->bit2;
       4:	71 15 02 00 00 00 00 00	r5 = *(u8 *)(r1 + 2)
;   uint8_t mask2 = 1 << bit2;
       5:	6f 52 00 00 00 00 00 00	r2 <<= r5
;   uint8_t result = value & ~(mask1 | mask2);
       6:	bf 26 00 00 00 00 00 00	r6 = r2
       7:	4f 46 00 00 00 00 00 00	r6 |= r4
       8:	a7 06 00 00 ff ff ff ff	r6 ^= -1
;   uint8_t value = ctx->value;
       9:	71 11 00 00 00 00 00 00	r1 = *(u8 *)(r1 + 0)
;   uint8_t result = value & ~(mask1 | mask2);
      10:	bf 10 00 00 00 00 00 00	r0 = r1
      11:	5f 60 00 00 00 00 00 00	r0 &= r6
;   result |= ((value & mask1) >> bit1) << bit2;
      12:	5f 14 00 00 00 00 00 00	r4 &= r1
      13:	7f 34 00 00 00 00 00 00	r4 >>= r3
      14:	6f 54 00 00 00 00 00 00	r4 <<= r5
      15:	4f 40 00 00 00 00 00 00	r0 |= r4
;   result |= ((value & mask2) >> bit2) << bit1;
      16:	5f 12 00 00 00 00 00 00	r2 &= r1
      17:	7f 52 00 00 00 00 00 00	r2 >>= r5
      18:	6f 32 00 00 00 00 00 00	r2 <<= r3
      19:	4f 20 00 00 00 00 00 00	r0 |= r2
;   return result;
      20:	57 00 00 00 ff 00 00 00	r0 &= 255
      21:	95 00 00 00 00 00 00 00	exit

*/
static uint8_t _bpf_stack[512];

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


#if BPF_COQ == 1 || BPF_COQ == 2
static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};
                                        
static struct memory_region mr_ctx = {.start_addr = (uintptr_t) &ctx,
                                        .block_size = sizeof(ctx),
                                        .block_perm = Readable,
                                        .block_ptr = (unsigned char *) (uintptr_t) &ctx};
#endif

#if BPF_COQ == 2
unsigned int mycache[sizeof(bpf_input_bin)/sizeof(bpf_input_bin[0])]={0};
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
#else

#if BPF_COQ == 2
  for (unsigned int i = 0; i < sizeof(bpf_input_bin)/sizeof(bpf_input_bin[0]); i++) { mycache[i] = 0; }
#endif
  
  struct memory_region memory_regions[] = { mr_stack, mr_ctx };
  struct bpf_state st = {
    .state_pc = 0,
    .regsmap = {0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, (uintptr_t)_bpf_stack+512},
    .bpf_flag = vBPF_OK,
    .mrs = memory_regions,
    .mrs_num = ARRAY_SIZE(memory_regions),
    .ins_len = sizeof(bpf_input_bin),
    .ins = (unsigned long long *) bpf_input_bin,
#if BPF_COQ == 2
    .cache = mycache,
#endif
  };
#endif

  uint32_t begin = ztimer_now(ZTIMER_USEC); // unsigned long long -> uint64_t
#if BPF_COQ == 0
  int result = bpf_execute_ctx(&bpf, &ctx, sizeof(ctx), &res);
  
  //printf("Vanilla-rBPF C result = 0x:%x\n", (unsigned int)res);
  
#elif BPF_COQ == 1 || BPF_COQ == 2
  int result = bpf_interpreter(&st, 10000, (uintptr_t) &ctx);
  
  //printf("flag=%d\n", st.bpf_flag);
  //printf("CertrBPF C result = 0x:%x\n", (unsigned int)result); //= 0xd4
  
#endif
  uint32_t end = ztimer_now(ZTIMER_USEC);
  duration = (float)(end-begin) + duration;
  }
  printf("execution time:%f\n", duration);
  return 0;
}
