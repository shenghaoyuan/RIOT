#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "embUnit.h"
#include "timex.h"
#include "ztimer.h"
#include "bpf/shared.h"

#if BPF_COQ == 0
#include "bpf.h"
#else
#include "interpreter.h"
#endif



unsigned char bpf_input_bin[] = {
  0x61, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xc7, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xc5, 0x02, 0x2b, 0x00, 0x02, 0x00, 0x00, 0x00,
  0x79, 0x14, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x7b, 0x4a, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x04, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
  0xbf, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x05, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0xbf, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xa7, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0xbf, 0x27, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0f, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x07, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xc7, 0x07, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xc5, 0x07, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xbf, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x06, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x77, 0x06, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x79, 0xa1, 0xf8, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x09, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xc7, 0x09, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xbf, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x08, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xc7, 0x08, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xdd, 0x98, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x63, 0x17, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x63, 0x97, 0xfc, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x07, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
  0x07, 0x06, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0xbf, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x55, 0x06, 0xf2, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0xbf, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x77, 0x01, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x07, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xbf, 0x36, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x06, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x77, 0x06, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x5d, 0x16, 0xdc, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* make bubblesort BPF_LOW=0 BPF_COMPCERT=0

0000000000000000 bubblesort:
;   int size = ctx->size;
       0:	61 12 00 00 00 00 00 00	r2 = *(u32 *)(r1 + 0)
       1:	67 02 00 00 20 00 00 00	r2 <<= 32
       2:	c7 02 00 00 20 00 00 00	r2 s>>= 32
;   for (i = 0;  i < size-1; i++) {
       3:	c5 02 2b 00 02 00 00 00	if r2 s< 2 goto +43 <LBB0_8>
       4:	79 14 08 00 00 00 00 00	r4 = *(u64 *)(r1 + 8)
       5:	b7 03 00 00 00 00 00 00	r3 = 0
       6:	7b 4a f8 ff 00 00 00 00	*(u64 *)(r10 - 8) = r4
       7:	07 04 00 00 04 00 00 00	r4 += 4
       8:	bf 25 00 00 00 00 00 00	r5 = r2
       9:	07 05 00 00 ff ff ff ff	r5 += -1
      10:	bf 50 00 00 00 00 00 00	r0 = r5

0000000000000058 LBB0_2:
;     for (j = 0; j < size - i-1; j++) {
      11:	bf 36 00 00 00 00 00 00	r6 = r3
      12:	a7 06 00 00 ff ff ff ff	r6 ^= -1
      13:	bf 27 00 00 00 00 00 00	r7 = r2
      14:	0f 67 00 00 00 00 00 00	r7 += r6
      15:	67 07 00 00 20 00 00 00	r7 <<= 32
      16:	c7 07 00 00 20 00 00 00	r7 s>>= 32
      17:	c5 07 14 00 01 00 00 00	if r7 s< 1 goto +20 <LBB0_7>
      18:	bf 06 00 00 00 00 00 00	r6 = r0
      19:	67 06 00 00 20 00 00 00	r6 <<= 32
      20:	77 06 00 00 20 00 00 00	r6 >>= 32
;       if (arr[j] > arr[j+1]) {
      21:	79 a1 f8 ff 00 00 00 00	r1 = *(u64 *)(r10 - 8)
      22:	61 11 00 00 00 00 00 00	r1 = *(u32 *)(r1 + 0)
      23:	bf 47 00 00 00 00 00 00	r7 = r4

00000000000000c0 LBB0_4:
      24:	61 79 00 00 00 00 00 00	r9 = *(u32 *)(r7 + 0)
      25:	67 09 00 00 20 00 00 00	r9 <<= 32
      26:	c7 09 00 00 20 00 00 00	r9 s>>= 32
      27:	bf 18 00 00 00 00 00 00	r8 = r1
      28:	67 08 00 00 20 00 00 00	r8 <<= 32
      29:	c7 08 00 00 20 00 00 00	r8 s>>= 32
      30:	dd 98 03 00 00 00 00 00	if r8 s<= r9 goto +3 <LBB0_6>
;         arr[j+1] = tmp;
      31:	63 17 00 00 00 00 00 00	*(u32 *)(r7 + 0) = r1
;         arr[j] = arr[j+1];
      32:	63 97 fc ff 00 00 00 00	*(u32 *)(r7 - 4) = r9
      33:	bf 19 00 00 00 00 00 00	r9 = r1

0000000000000110 LBB0_6:
;     for (j = 0; j < size - i-1; j++) {
      34:	07 07 00 00 04 00 00 00	r7 += 4
      35:	07 06 00 00 ff ff ff ff	r6 += -1
;       if (arr[j] > arr[j+1]) {
      36:	bf 91 00 00 00 00 00 00	r1 = r9
;     for (j = 0; j < size - i-1; j++) {
      37:	55 06 f2 ff 00 00 00 00	if r6 != 0 goto -14 <LBB0_4>

0000000000000130 LBB0_7:
;   for (i = 0;  i < size-1; i++) {
      38:	07 00 00 00 ff ff ff ff	r0 += -1
      39:	bf 51 00 00 00 00 00 00	r1 = r5
      40:	67 01 00 00 20 00 00 00	r1 <<= 32
      41:	77 01 00 00 20 00 00 00	r1 >>= 32
      42:	07 03 00 00 01 00 00 00	r3 += 1
      43:	bf 36 00 00 00 00 00 00	r6 = r3
      44:	67 06 00 00 20 00 00 00	r6 <<= 32
      45:	77 06 00 00 20 00 00 00	r6 >>= 32
      46:	5d 16 dc ff 00 00 00 00	if r6 != r1 goto -36 <LBB0_2>

0000000000000178 LBB0_8:
; }
      47:	95 00 00 00 00 00 00 00	exit

*/

int unsort_list[] = {5923, 3314, 6281, 2408, 9997, 4393, 772, 3983, 4083, 3212, 9096, 1973, 7792, 1627, 1812, 1683, 4615, 8370, 7379, 1188, 2511, 1115, 9226, 9025, 1898, 5529, 3674, 7868, 750, 2393, 9372, 4370};

void print_sorted_list (int arr[], int size) {
  for (int i = 0; i < size; i++) {
    if (i%10 == 0) { printf("\n"); }
    printf("%04d, ", arr[i]);
  }
  return ;
}
        
static uint8_t _bpf_stack[512];

struct test_md
{
    int size;
    __bpf_shared_ptr(int*, arr);
};

struct test_md bpf_input_ctx = {
  .size = (sizeof(unsort_list)/sizeof(unsort_list[0])),
  .arr = (intptr_t)unsort_list,
};

#if BPF_COQ == 1 || BPF_COQ == 2
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
  bpf_mem_region_t region;
  bpf_setup(&bpf);
  int64_t res = 0;
  bpf_add_region(&bpf, &region,
                 (void*)unsort_list, sizeof(unsort_list), BPF_MEM_REGION_WRITE);
#else

#if BPF_COQ == 2
  for (unsigned int i = 0; i < sizeof(bpf_input_bin)/sizeof(bpf_input_bin[0]); i++) { mycache[i] = 0; }
#endif

  struct memory_region memory_regions[] = { mr_stack, mr_arr, mr_ctx };
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
  
  //print_sorted_list(unsort_list, (sizeof(unsort_list)/sizeof(unsort_list[0])));
  /*
  	0750, 0772, 1115, 1188, 1627, 1683, 1812, 1898, 1973, 2393, 
	2408, 2511, 3212, 3314, 3674, 3983, 4083, 4370, 4393, 4615, 
	5529, 5923, 6281, 7379, 7792, 7868, 8370, 9025, 9096, 9226
  */
  return 0;
}
