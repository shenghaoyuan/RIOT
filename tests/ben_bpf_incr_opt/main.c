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
  0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* make incr BPF_LOW=0 BPF_COMPCERT=0

0000000000000000 incr:
; {
       0:	bf 10 00 00 00 00 00 00	r0 = r1
;   return x+1;
       1:	07 00 00 00 01 00 00 00	r0 += 1
       2:	95 00 00 00 00 00 00 00	exit

*/
        

static uint8_t _bpf_stack[512];

static uint32_t input_x = 156U;

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
  for (int i = 0; i < sizeof(bpf_input_bin)/sizeof(bpf_input_bin[0]); i++) { mycache[i] = 0; }
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
  int result = bpf_execute(&bpf, (uintptr_t) input_x, 0, &res);
  
  //printf("Vanilla-rBPF C result = 0x:%x\n", (unsigned int)res);
  
#elif BPF_COQ == 1 || BPF_COQ == 2
  int result = bpf_interpreter(&st, 10000, input_x);
  
  //printf("flag=%d\n", st.bpf_flag);
  //printf("CertrBPF C result = 0x:%x\n", (unsigned int)result); //= 0x9d = 157
#endif

  uint32_t end = ztimer_now(ZTIMER_USEC);
  duration = (float)(end-begin) + duration;
  }
  printf("execution time:%f\n", duration);
  return 0;
}
