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
  0xbf, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x77, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xbf, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0xa5, 0x03, 0x11, 0x00, 0x02, 0x00, 0x00, 0x00,
  0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x15, 0x02, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xb7, 0x02, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
  0xb7, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xbf, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0f, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x77, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x07, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xbf, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x06, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x77, 0x06, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xbf, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x2d, 0x56, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x05, 0x00, 0xf4, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* make fib BPF_LOW=0 BPF_COMPCERT=0

0000000000000000 fib:
;     if (num == 0) {
       0:	bf 12 00 00 00 00 00 00	r2 = r1
       1:	67 02 00 00 20 00 00 00	r2 <<= 32
       2:	77 02 00 00 20 00 00 00	r2 >>= 32
       3:	bf 23 00 00 00 00 00 00	r3 = r2
       4:	07 03 00 00 ff ff ff ff	r3 += -1
       5:	a5 03 11 00 02 00 00 00	if r3 < 2 goto +17 <LBB0_4>
       6:	bf 10 00 00 00 00 00 00	r0 = r1
       7:	15 02 10 00 00 00 00 00	if r2 == 0 goto +16 <LBB0_5>
       8:	b7 00 00 00 01 00 00 00	r0 = 1
       9:	b7 02 00 00 03 00 00 00	r2 = 3
      10:	b7 03 00 00 01 00 00 00	r3 = 1

0000000000000058 LBB0_3:
      11:	bf 04 00 00 00 00 00 00	r4 = r0
;         next = t0 + t1;
      12:	0f 30 00 00 00 00 00 00	r0 += r3
;       for (uint32_t i = 3; i <=num; i++) {
      13:	bf 15 00 00 00 00 00 00	r5 = r1
      14:	67 05 00 00 20 00 00 00	r5 <<= 32
      15:	77 05 00 00 20 00 00 00	r5 >>= 32
      16:	07 02 00 00 01 00 00 00	r2 += 1
      17:	bf 26 00 00 00 00 00 00	r6 = r2
      18:	67 06 00 00 20 00 00 00	r6 <<= 32
      19:	77 06 00 00 20 00 00 00	r6 >>= 32
      20:	bf 43 00 00 00 00 00 00	r3 = r4
      21:	2d 56 02 00 00 00 00 00	if r6 > r5 goto +2 <LBB0_5>
      22:	05 00 f4 ff 00 00 00 00	goto -12 <LBB0_3>

00000000000000b8 LBB0_4:
      23:	b7 00 00 00 01 00 00 00	r0 = 1

00000000000000c0 LBB0_5:
; }
      24:	95 00 00 00 00 00 00 00	exit

*/
        
static uint8_t _bpf_stack[512];

static uint32_t input_x = 10U; //10

#if BPF_COQ == 1 || BPF_COQ == 2
static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};                                      
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

  struct memory_region memory_regions[] = { mr_stack };
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
  int result = bpf_execute(&bpf, (uintptr_t) input_x, 0, &res); //instead of bpf_execute_ctx and we translates input_x as a pointer value!!!
  
  //printf("Vanilla-rBPF C result = 0x:%x\n", (unsigned int)res);
  
#elif BPF_COQ == 1 || BPF_COQ == 2 
  int result = bpf_interpreter(&st, 10000, input_x);
  
  //printf("flag=%d\n", st.bpf_flag);
  //printf("CertrBPF C result = 0x:%x\n", (unsigned int)result); //= 0x37 
#endif


  uint32_t end = ztimer_now(ZTIMER_USEC);
  duration = (float)(end-begin) + duration;
  }
  printf("execution time:%f\n", duration);
  return 0;
}
