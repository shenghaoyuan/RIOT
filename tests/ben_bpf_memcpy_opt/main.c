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
  0x61, 0x12, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x15, 0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x79, 0x13, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x79, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x71, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x73, 0x43, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x07, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x07, 0x02, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0x15, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x05, 0x00, 0xf9, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* make memcpy BPF_LOW=0 BPF_COMPCERT=0

0000000000000000 memcpy_n:
;   uint32_t len = ctx->len;
       0:	61 12 10 00 00 00 00 00	r2 = *(u32 *)(r1 + 16)
;   for (uint32_t i = 0; i < len; i++) {
       1:	15 02 09 00 00 00 00 00	if r2 == 0 goto +9 <LBB0_3>
       2:	79 13 08 00 00 00 00 00	r3 = *(u64 *)(r1 + 8)
       3:	79 11 00 00 00 00 00 00	r1 = *(u64 *)(r1 + 0)

0000000000000020 LBB0_2:
;     dst[i] = src[i];
       4:	71 14 00 00 00 00 00 00	r4 = *(u8 *)(r1 + 0)
       5:	73 43 00 00 00 00 00 00	*(u8 *)(r3 + 0) = r4
;   for (uint32_t i = 0; i < len; i++) {
       6:	07 03 00 00 01 00 00 00	r3 += 1
       7:	07 01 00 00 01 00 00 00	r1 += 1
       8:	07 02 00 00 ff ff ff ff	r2 += -1
       9:	15 02 01 00 00 00 00 00	if r2 == 0 goto +1 <LBB0_3>
      10:	05 00 f9 ff 00 00 00 00	goto -7 <LBB0_2>

0000000000000058 LBB0_3:
;   return 0;
      11:	b7 00 00 00 00 00 00 00	r0 = 0
      12:	95 00 00 00 00 00 00 00	exit

*/

unsigned char src_data[] =
        "AD3Awn4kb6FtcsyE0RU25U7f55Yncn3LP3oEx9Gl4qr7iDW7I8L6Pbw9jNnh0sE4DmCKuc"
        "d1J8I34vn31W924y5GMS74vUrZQc08805aj4Tf66HgL1cO94os10V2s2GDQ825yNh9Yuq3"
        /*"QHcA60xl31rdA7WskVtCXI7ruH1A4qaR6Uk454hm401lLmv2cGWt5KTJmr93d3JsGaRRPs"
        "4HqYi4mFGowo8fWv48IcA3N89Z99nf0A0H2R6P0uI4Tir682Of3Rk78DUB2dIGQRRpdqVT"
        "tLhgfET2gUGU65V3edSwADMqRttI9JPVz8JS37g5QZj4Ax56rU1u0m0K8YUs57UYG5645n"
        "byNy4yqxu7"*/;

unsigned char dst_data[520];
        
static uint8_t _bpf_stack[512];

struct test_md
{
    __bpf_shared_ptr(unsigned char*, src);
    __bpf_shared_ptr(unsigned char*, dst);
    uint32_t len;
};

struct test_md bpf_input_ctx = {
  .src = src_data,
  .dst = dst_data,
  .len = 1, // 1 or 60
};

#if BPF_COQ == 1 || BPF_COQ == 2
static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};
                                        
static struct memory_region mr_dst = {.start_addr = (uintptr_t)dst_data,
                                        .block_size = sizeof(dst_data),
                                        .block_perm = Writable,
                                        .block_ptr = dst_data};
                                        
static struct memory_region mr_src = {.start_addr = (uintptr_t)src_data,
                                        .block_size = sizeof(src_data),
                                        .block_perm = Readable,
                                        .block_ptr = src_data};
                                        
static struct memory_region mr_ctx = {.start_addr = (uintptr_t) &bpf_input_ctx,
                                        .block_size = sizeof(bpf_input_ctx),
                                        .block_perm = Readable,
                                        .block_ptr = (unsigned char *) (uintptr_t) &bpf_input_ctx};
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
  bpf_mem_region_t region_dst, region_src;
  bpf_setup(&bpf);
  int64_t res = 0;
  bpf_add_region(&bpf, &region_dst,
                 (void*)dst_data, sizeof(dst_data), BPF_MEM_REGION_WRITE);
  bpf_add_region(&bpf, &region_src,
                 (void*)src_data, sizeof(src_data), BPF_MEM_REGION_READ);
#else

#if BPF_COQ == 2 
  for (unsigned int i = 0; i < sizeof(bpf_input_bin)/sizeof(bpf_input_bin[0]); i++) { mycache[i] = 0; }
#endif

  struct memory_region memory_regions[] = { mr_stack, mr_src, mr_dst, mr_ctx };
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
  duration = (float)(end-begin) + duration;
  }
  printf("execution time:%f\n", duration);
  
  //printf("%s\n", dst_data);
  return 0;
}
