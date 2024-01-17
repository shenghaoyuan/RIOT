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


unsigned char bpf_input_bin[] = /* compiled by CompCertBPF */{
  0xbc, 0xa0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x14, 0x0a, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x63, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x63, 0x9a, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x63, 0x6a, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x15, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0x7d, 0x31, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x1c, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x04, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0x7d, 0x43, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x04, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0xbc, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x6c, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0c, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x46, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xdd, 0x60, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x63, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x63, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x05, 0x00, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x05, 0x00, 0xea, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x61, 0xa6, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0xa9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x0a, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
}; 

/* make bubblesort
0000000000000000 bubblesort:
       0:	bc a0 00 00 00 00 00 00	w0 = w10
       1:	14 0a 00 00 10 00 00 00	w10 -= 16
       2:	63 0a 00 00 00 00 00 00	*(u32 *)(r10 + 0) = r0
       3:	63 9a 04 00 00 00 00 00	*(u32 *)(r10 + 4) = r9
       4:	63 6a 08 00 00 00 00 00	*(u32 *)(r10 + 8) = r6
       5:	61 12 00 00 00 00 00 00	r2 = *(u32 *)(r1 + 0)
       6:	61 15 04 00 00 00 00 00	r5 = *(u32 *)(r1 + 4)
       7:	b4 01 00 00 00 00 00 00	w1 = 0
       8:	bc 23 00 00 00 00 00 00	w3 = w2
       9:	04 03 00 00 ff ff ff ff	w3 += -1
      10:	7e 31 13 00 00 00 00 00	if w1 s>= w3 goto +19 <bubblesort+0xf0>
      11:	b4 03 00 00 00 00 00 00	w3 = 0
      12:	bc 24 00 00 00 00 00 00	w4 = w2
      13:	1c 14 00 00 00 00 00 00	w4 -= w1
      14:	04 04 00 00 ff ff ff ff	w4 += -1
      15:	7e 43 0c 00 00 00 00 00	if w3 s>= w4 goto +12 <bubblesort+0xe0>
      16:	b4 04 00 00 02 00 00 00	w4 = 2
      17:	bc 30 00 00 00 00 00 00	w0 = w3
      18:	6c 40 00 00 00 00 00 00	w0 <<= w4
      19:	bc 54 00 00 00 00 00 00	w4 = w5
      20:	0c 04 00 00 00 00 00 00	w4 += w0
      21:	61 40 00 00 00 00 00 00	r0 = *(u32 *)(r4 + 0)
      22:	61 46 04 00 00 00 00 00	r6 = *(u32 *)(r4 + 4)
      23:	de 60 02 00 00 00 00 00	if w0 s<= w6 goto +2 <bubblesort+0xd0>
      24:	63 64 00 00 00 00 00 00	*(u32 *)(r4 + 0) = r6
      25:	63 04 04 00 00 00 00 00	*(u32 *)(r4 + 4) = r0
      26:	04 03 00 00 01 00 00 00	w3 += 1
      27:	05 00 f0 ff 00 00 00 00	goto -16 <bubblesort+0x60>
      28:	04 01 00 00 01 00 00 00	w1 += 1
      29:	05 00 ea ff 00 00 00 00	goto -22 <bubblesort+0x40>
      30:	61 a6 08 00 00 00 00 00	r6 = *(u32 *)(r10 + 8)
      31:	61 a9 04 00 00 00 00 00	r9 = *(u32 *)(r10 + 4)
      32:	04 0a 00 00 10 00 00 00	w10 += 16
      33:	95 00 00 00 00 00 00 00	exit
*/

int unsort_list[] = {5923, 3314, 6281, 2408, 9997, 4393, 772, 3983, 4083, 3212, 9096, 1973, 7792, 1627, 1812, 1683, 4615, 8370, 7379, 1188, 2511, 1115, 9226, 9025, 1898, 5529, 3674, 7868, 750, 2393, 9372, 4370};

void print_sorted_list (int arr[], int size) {
  for (int i = 0; i < size; i++) {
    if (i%10 == 0) { printf("\n"); }
    printf("%04d, ", arr[i]);
  }
  return ;
}

struct test_md
{
    int size;
    int* arr; //__bpf_shared_ptr(int*, arr); //CompCert compiles int* as 32-bit
};

struct test_md bpf_input_ctx = {
  .size = (sizeof(unsort_list)/sizeof(unsort_list[0])),
  .arr = (intptr_t)unsort_list,
};
        
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
                                        
static struct memory_region mr_arr = {.start_addr = (uintptr_t)unsort_list,
                                        .block_size = sizeof(unsort_list),
                                        .block_perm = Freeable,
                                        .block_ptr = unsort_list};
                                        
static struct memory_region mr_ctx = {.start_addr = (uintptr_t) &bpf_input_ctx,
                                        .block_size = sizeof(bpf_input_ctx),
                                        .block_perm = Readable,
                                        .block_ptr = (unsigned char *) (uintptr_t) &bpf_input_ctx};
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
                 (void*)unsort_list, sizeof(unsort_list), BPF_MEM_REGION_WRITE);
  
#elif BPF_COQ == 1
  struct memory_region memory_regions[] = { mr_stack, mr_arr, mr_ctx };
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
  ibpf_full_state_init(&ibpf_state, 3);
  ibpf_set_mem_region(&ibpf_state, unsort_list, sizeof(unsort_list), Freeable, 1);
  ibpf_set_mem_region(&ibpf_state, &bpf_input_ctx, sizeof(bpf_input_ctx), Readable, 2);
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
  //printf("CertrBPF C result = 0x:%x\n", (unsigned int)result); //= 0xd4
  
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
  
  //print_sorted_list(unsort_list, (sizeof(unsort_list)/sizeof(unsort_list[0])));
  /*
  	0750, 0772, 1115, 1188, 1627, 1683, 1812, 1898, 1973, 2393, 
	2408, 2511, 3212, 3314, 3674, 3983, 4083, 4370, 4393, 4615, 
	5529, 5923, 6281, 7379, 7792, 7868, 8370, 9025, 9096, 9226
  */
  //printf("\n hello \n");
  return 0;
}
