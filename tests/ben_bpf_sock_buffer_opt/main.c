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


unsigned char bpf_input_bin[] = {
  0x61, 0x12, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x15, 0x02, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x13, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3d, 0x34, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
  0xb7, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x63, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3d, 0x26, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0f, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x06, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x07, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
  0xad, 0x37, 0xf9, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x15, 0x02, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x01, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
  0x61, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0f, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
  0x07, 0x02, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0xbf, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x55, 0x02, 0xfa, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* make sock_buffer BPF_LOW=0 BPF_COMPCERT=0

0000000000000000 foo:
;     uint32_t len = ctx->len;
       0:	61 12 08 00 00 00 00 00	r2 = *(u32 *)(r1 + 8)
;     for (index = 0U; index < len; index++) {
       1:	15 02 0e 00 00 00 00 00	if r2 == 0 goto +14 <LBB0_4>
       2:	61 13 04 00 00 00 00 00	r3 = *(u32 *)(r1 + 4)
       3:	61 14 00 00 00 00 00 00	r4 = *(u32 *)(r1 + 0)
       4:	3d 34 0b 00 00 00 00 00	if r4 >= r3 goto +11 <LBB0_4>
       5:	b7 05 00 00 01 00 00 00	r5 = 1
       6:	bf 10 00 00 00 00 00 00	r0 = r1
       7:	07 00 00 00 0c 00 00 00	r0 += 12
       8:	b7 06 00 00 01 00 00 00	r6 = 1

0000000000000048 LBB0_3:
;         array[index] = 1U;
       9:	63 50 00 00 00 00 00 00	*(u32 *)(r0 + 0) = r5
;     for (index = 0U; index < len; index++) {
      10:	3d 26 05 00 00 00 00 00	if r6 >= r2 goto +5 <LBB0_4>
      11:	bf 47 00 00 00 00 00 00	r7 = r4
      12:	0f 67 00 00 00 00 00 00	r7 += r6
      13:	07 06 00 00 01 00 00 00	r6 += 1
      14:	07 00 00 00 04 00 00 00	r0 += 4
      15:	ad 37 f9 ff 00 00 00 00	if r7 < r3 goto -7 <LBB0_3>

0000000000000080 LBB0_4:
      16:	b7 00 00 00 00 00 00 00	r0 = 0
;     for (index = 0U; index < len; index++) {
      17:	15 02 08 00 00 00 00 00	if r2 == 0 goto +8 <LBB0_7>
      18:	b7 03 00 00 00 00 00 00	r3 = 0
      19:	07 01 00 00 0c 00 00 00	r1 += 12

00000000000000a0 LBB0_6:
;         cumul += array[index];
      20:	61 10 00 00 00 00 00 00	r0 = *(u32 *)(r1 + 0)
      21:	0f 30 00 00 00 00 00 00	r0 += r3
;     for (index = 0U; index < len; index++) {
      22:	07 01 00 00 04 00 00 00	r1 += 4
      23:	07 02 00 00 ff ff ff ff	r2 += -1
      24:	bf 03 00 00 00 00 00 00	r3 = r0
      25:	55 02 fa ff 00 00 00 00	if r2 != 0 goto -6 <LBB0_6>

00000000000000d0 LBB0_7:
;     return cumul;
      26:	95 00 00 00 00 00 00 00	exit
*/

#define ARRAY_LENGTH 40

struct test_md
{
    uint32_t data_start;
    uint32_t data_end;
    uint32_t len;
    uint32_t array[ARRAY_LENGTH];
};

struct test_md bpf_input_ctx = {.data_start = 100, .data_end = 200, .len = 9, .array={0}};

        
static uint8_t _bpf_stack[512];


#if BPF_COQ == 1 || BPF_COQ == 2
static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};
                              
static struct memory_region mr_ctx = {.start_addr = (uintptr_t)&bpf_input_ctx,
                                        .block_size = sizeof(bpf_input_ctx),
                                        .block_perm = Writable,
                                        .block_ptr = &bpf_input_ctx};
#endif

#if BPF_COQ == 2 
unsigned int mycache[sizeof(bpf_input_bin)/sizeof(bpf_input_bin[0])]={0};
#endif

int main(void){
  
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
  int result = bpf_execute_ctx(&bpf, &bpf_input_ctx, sizeof(bpf_input_ctx), &res);
  
  //printf("Vanilla-rBPF C result = 0x:%x\n", (unsigned int)res);
  
#elif BPF_COQ == 1 || BPF_COQ == 2
  int result = bpf_interpreter(&st, 10000, (uintptr_t) &bpf_input_ctx);
  
  //printf("flag=%d\n", st.bpf_flag);
  //printf("CertrBPF C result = 0x:%x\n", (unsigned int)result);
#endif

  uint32_t end = ztimer_now(ZTIMER_USEC);
  float duration = (float)(end-begin);
  
  printf("execution time:%f\n", duration);
  
  return 0;
}
