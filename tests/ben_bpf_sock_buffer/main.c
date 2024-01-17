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
  0x63, 0x6a, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x63, 0x7a, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x03, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
  0x61, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x17, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x16, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3d, 0x65, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0c, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3d, 0x71, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0xbc, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x6c, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0c, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x63, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x05, 0x00, 0xf3, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3d, 0x65, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0xbc, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x6c, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0c, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x05, 0x00, 0xf6, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x61, 0xa6, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0xa7, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0xa9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x0a, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* make sock_buffer

0000000000000000 foo:
       0:	bc a0 00 00 00 00 00 00	w0 = w10
       1:	14 0a 00 00 10 00 00 00	w10 -= 16
       2:	63 0a 00 00 00 00 00 00	*(u32 *)(r10 + 0) = r0
       3:	63 9a 04 00 00 00 00 00	*(u32 *)(r10 + 4) = r9
       4:	63 6a 08 00 00 00 00 00	*(u32 *)(r10 + 8) = r6
       5:	63 7a 0c 00 00 00 00 00	*(u32 *)(r10 + 12) = r7
       6:	bc 13 00 00 00 00 00 00	w3 = w1
       7:	04 03 00 00 0c 00 00 00	w3 += 12
       8:	61 12 00 00 00 00 00 00	r2 = *(u32 *)(r1 + 0)
       9:	61 17 04 00 00 00 00 00	r7 = *(u32 *)(r1 + 4)
      10:	61 16 08 00 00 00 00 00	r6 = *(u32 *)(r1 + 8)
      11:	b4 00 00 00 00 00 00 00	w0 = 0
      12:	b4 05 00 00 00 00 00 00	w5 = 0
      13:	3e 65 0c 00 00 00 00 00	if w5 >= w6 goto +12 <foo+0xd0>
      14:	bc 21 00 00 00 00 00 00	w1 = w2
      15:	0c 51 00 00 00 00 00 00	w1 += w5
      16:	3e 71 09 00 00 00 00 00	if w1 >= w7 goto +9 <foo+0xd0>
      17:	b4 04 00 00 02 00 00 00	w4 = 2
      18:	bc 51 00 00 00 00 00 00	w1 = w5
      19:	6c 41 00 00 00 00 00 00	w1 <<= w4
      20:	bc 34 00 00 00 00 00 00	w4 = w3
      21:	0c 14 00 00 00 00 00 00	w4 += w1
      22:	b4 01 00 00 01 00 00 00	w1 = 1
      23:	63 14 00 00 00 00 00 00	*(u32 *)(r4 + 0) = r1
      24:	04 05 00 00 01 00 00 00	w5 += 1
      25:	05 00 f3 ff 00 00 00 00	goto -13 <foo+0x68>
      26:	b4 05 00 00 00 00 00 00	w5 = 0
      27:	3e 65 09 00 00 00 00 00	if w5 >= w6 goto +9 <foo+0x128>
      28:	b4 04 00 00 02 00 00 00	w4 = 2
      29:	bc 51 00 00 00 00 00 00	w1 = w5
      30:	6c 41 00 00 00 00 00 00	w1 <<= w4
      31:	bc 34 00 00 00 00 00 00	w4 = w3
      32:	0c 14 00 00 00 00 00 00	w4 += w1
      33:	61 41 00 00 00 00 00 00	r1 = *(u32 *)(r4 + 0)
      34:	0c 10 00 00 00 00 00 00	w0 += w1
      35:	04 05 00 00 01 00 00 00	w5 += 1
      36:	05 00 f6 ff 00 00 00 00	goto -10 <foo+0xd8>
      37:	61 a6 08 00 00 00 00 00	r6 = *(u32 *)(r10 + 8)
      38:	61 a7 0c 00 00 00 00 00	r7 = *(u32 *)(r10 + 12)
      39:	61 a9 04 00 00 00 00 00	r9 = *(u32 *)(r10 + 4)
      40:	04 0a 00 00 10 00 00 00	w10 += 16
      41:	95 00 00 00 00 00 00 00	exit
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

#if BPF_COQ == 1
static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};
                              
static struct memory_region mr_ctx = {.start_addr = (uintptr_t)&bpf_input_ctx,
                                        .block_size = sizeof(bpf_input_ctx),
                                        .block_perm = Writable,
                                        .block_ptr = &bpf_input_ctx};
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
  bpf_mem_region_t region;
  bpf_setup(&bpf);
  int64_t res = 0;
  bpf_add_region(&bpf, &region,
                 &bpf_input_ctx, sizeof(bpf_input_ctx), BPF_MEM_REGION_WRITE);

#elif BPF_COQ == 1           
  struct memory_region memory_regions[] = { mr_stack, mr_ctx };
  struct bpf_state st = {
    .state_pc = 0,
    .regsmap = {0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, (uintptr_t)_bpf_stack+512},
    .bpf_flag = vBPF_OK,
    .mrs = memory_regions,
    .mrs_num = ARRAY_SIZE(memory_regions),
    .ins = (unsigned long long *) bpf_input_bin,
    .ins_len = sizeof(bpf_input_bin)/8,
  };
  
#else
  jitted_thumb_list = ibpf_state.jitted_thumb_list;
  ibpf_full_state_init(&ibpf_state, 2);
  ibpf_set_mem_region(&ibpf_state, &bpf_input_ctx, sizeof(bpf_input_ctx), Writable, 1);
  ibpf_set_code(&ibpf_state, bpf_input_bin, sizeof(bpf_input_bin));
  jit_alu32(&ibpf_state.st);
#endif

  uint32_t begin = ztimer_now(ZTIMER_USEC); // unsigned long long -> uint64_t
#if BPF_COQ == 0
  int result = bpf_execute_ctx(&bpf, &bpf_input_ctx, sizeof(bpf_input_ctx), &res);
  
  //printf("Vanilla-rBPF C result = 0x:%x\n", (unsigned int)res);
  
#elif BPF_COQ == 1
  int result = bpf_interpreter(&st, 10000, (uintptr_t) &bpf_input_ctx);
  
  //printf("flag=%d\n", st.bpf_flag);
  //printf("CertrBPF C result = 0x:%x\n", (unsigned int)result); // = 0x9
  
#else
  int result = ibpf_interpreter(&ibpf_state.st, 10000, (uintptr_t) &bpf_input_ctx);
  
  //printf("flag=%d\n", ibpf_state.st.flag);
  //printf("CertrBPF-JIT C result = 0x:%x\n", (unsigned int)result);
  //_magic_function(0, &ibpf_state.st);
  //printf("CertrBPF-JIT-Pure C result = 0x:%x\n", (unsigned int)(ibpf_state.st.regs_st[0]));
#endif

  uint32_t end = ztimer_now(ZTIMER_USEC);
  float duration = (float)(end-begin);
  
  printf("execution time:%f\n", duration);
  
  return 0;
}
