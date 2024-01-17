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


unsigned char bpf_input_bin[] = {
  0xbc, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x14, 0x0a, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x63, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x63, 0x9a, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xb4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x15, 0x01, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x15, 0x01, 0x09, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x15, 0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
  0xb4, 0x03, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
  0x2d, 0x13, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0c, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x05, 0x00, 0xf9, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0xa9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x0a, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* make fib

0000000000000000 fib:
       0:	bc a0 00 00 00 00 00 00	w0 = w10
       1:	14 0a 00 00 10 00 00 00	w10 -= 16
       2:	63 0a 00 00 00 00 00 00	*(u32 *)(r10 + 0) = r0
       3:	63 9a 04 00 00 00 00 00	*(u32 *)(r10 + 4) = r9
       4:	b4 02 00 00 01 00 00 00	w2 = 1
       5:	b4 00 00 00 01 00 00 00	w0 = 1
       6:	16 01 0c 00 00 00 00 00	if w1 == 0 goto +12 <fib+0x98>
       7:	16 01 09 00 01 00 00 00	if w1 == 1 goto +9 <fib+0x88>
       8:	16 01 08 00 02 00 00 00	if w1 == 2 goto +8 <fib+0x88>
       9:	b4 03 00 00 03 00 00 00	w3 = 3
      10:	2e 13 09 00 00 00 00 00	if w3 > w1 goto +9 <fib+0xa0>
      11:	bc 24 00 00 00 00 00 00	w4 = w2
      12:	bc 02 00 00 00 00 00 00	w2 = w0
      13:	bc 40 00 00 00 00 00 00	w0 = w4
      14:	0c 20 00 00 00 00 00 00	w0 += w2
      15:	04 03 00 00 01 00 00 00	w3 += 1
      16:	05 00 f9 ff 00 00 00 00	goto -7 <fib+0x50>
      17:	b4 00 00 00 01 00 00 00	w0 = 1
      18:	05 00 01 00 00 00 00 00	goto +1 <fib+0xa0>
      19:	b4 00 00 00 00 00 00 00	w0 = 0
      20:	61 a9 04 00 00 00 00 00	r9 = *(u32 *)(r10 + 4)
      21:	04 0a 00 00 10 00 00 00	w10 += 16
      22:	95 00 00 00 00 00 00 00	exit
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

static uint32_t input_x = 10U; //10

#if BPF_COQ == 1
static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};
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
  struct memory_region memory_regions[] = { mr_stack };
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
  ibpf_full_state_init(&ibpf_state, 1);
  ibpf_set_code(&ibpf_state, bpf_input_bin, sizeof(bpf_input_bin));
  jit_alu32(&ibpf_state.st);

#endif

  uint32_t begin = ztimer_now(ZTIMER_USEC); // unsigned long long -> uint64_t
#if BPF_COQ == 0
  int result = bpf_execute(&bpf, (uintptr_t) input_x, 0, &res);
  
  //printf("Vanilla-rBPF C result = 0x:%x\n", (unsigned int)res);
  
#elif BPF_COQ == 1
  int result = bpf_interpreter(&st, 10000, input_x);
  
  //printf("flag=%d\n", st.bpf_flag);
  //printf("CertrBPF C result = 0x:%x\n", (unsigned int)result); //= 0x37 
  
#else
  int result = ibpf_interpreter(&ibpf_state.st, 10000, input_x);
  
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
