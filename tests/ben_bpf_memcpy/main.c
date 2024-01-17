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
  0x61, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x10, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x16, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3d, 0x63, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0c, 0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbc, 0x45, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0c, 0x35, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x71, 0x52, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x73, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x05, 0x00, 0xf7, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0xa6, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0xa9, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x04, 0x0a, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
/* make memcpy
0000000000000000 memcpy_n:
       0:	bc a0 00 00 00 00 00 00	w0 = w10
       1:	14 0a 00 00 10 00 00 00	w10 -= 16
       2:	63 0a 00 00 00 00 00 00	*(u32 *)(r10 + 0) = r0
       3:	63 9a 04 00 00 00 00 00	*(u32 *)(r10 + 4) = r9
       4:	63 6a 08 00 00 00 00 00	*(u32 *)(r10 + 8) = r6
       5:	61 14 00 00 00 00 00 00	r4 = *(u32 *)(r1 + 0)
       6:	61 10 04 00 00 00 00 00	r0 = *(u32 *)(r1 + 4)
       7:	61 16 08 00 00 00 00 00	r6 = *(u32 *)(r1 + 8)
       8:	b4 03 00 00 00 00 00 00	w3 = 0
       9:	3e 63 08 00 00 00 00 00	if w3 >= w6 goto +8 <memcpy_n+0x90>
      10:	bc 01 00 00 00 00 00 00	w1 = w0
      11:	0c 31 00 00 00 00 00 00	w1 += w3
      12:	bc 45 00 00 00 00 00 00	w5 = w4
      13:	0c 35 00 00 00 00 00 00	w5 += w3
      14:	71 52 00 00 00 00 00 00	r2 = *(u8 *)(r5 + 0)
      15:	73 21 00 00 00 00 00 00	*(u8 *)(r1 + 0) = r2
      16:	04 03 00 00 01 00 00 00	w3 += 1
      17:	05 00 f7 ff 00 00 00 00	goto -9 <memcpy_n+0x48>
      18:	b4 00 00 00 00 00 00 00	w0 = 0
      19:	61 a6 08 00 00 00 00 00	r6 = *(u32 *)(r10 + 8)
      20:	61 a9 04 00 00 00 00 00	r9 = *(u32 *)(r10 + 4)
      21:	04 0a 00 00 10 00 00 00	w10 += 16
      22:	95 00 00 00 00 00 00 00	exit
*/

unsigned char src_data[] =
        "AD3Awn4kb6FtcsyE0RU25U7f55Yncn3LP3oEx9Gl4qr7iDW7I8L6Pbw9jNnh0sE4DmCKuc"
        "d1J8I34vn31W924y5GMS74vUrZQc08805aj4Tf66HgL1cO94os10V2s2GDQ825yNh9Yuq3"
        /*"QHcA60xl31rdA7WskVtCXI7ruH1A4qaR6Uk454hm401lLmv2cGWt5KTJmr93d3JsGaRRPs"
        "4HqYi4mFGowo8fWv48IcA3N89Z99nf0A0H2R6P0uI4Tir682Of3Rk78DUB2dIGQRRpdqVT"
        "tLhgfET2gUGU65V3edSwADMqRttI9JPVz8JS37g5QZj4Ax56rU1u0m0K8YUs57UYG5645n"
        "byNy4yqxu7"*/;

unsigned char dst_data[520];

struct test_md
{
    char* src;
    char* dst;
    uint32_t len;
};

struct test_md bpf_input_ctx = {
  .src = src_data,
  .dst = dst_data,
  .len = 60, // 1 or 60
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
                                        
static struct memory_region mr_dst = {.start_addr = (uintptr_t)dst_data,
                                        .block_size = sizeof(dst_data),
                                        .block_perm = Writable,
                                        .block_ptr = dst_data};
                                        
static struct memory_region mr_src = {.start_addr = (uintptr_t)src_data,
                                        .block_size = sizeof(src_data),
                                        .block_perm = Readable,
                                        .block_ptr = src_data};
                                        
static struct memory_region mr_ctx = {.start_addr = (uintptr_t)&bpf_input_ctx,
                                        .block_size = sizeof(bpf_input_ctx),
                                        .block_perm = Readable,
                                        .block_ptr = (unsigned char *) (uintptr_t) &bpf_input_ctx};
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

#elif BPF_COQ == 1
  struct memory_region memory_regions[] = { mr_stack, mr_src, mr_dst, mr_ctx };
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
  ibpf_full_state_init(&ibpf_state, 4);
  ibpf_set_mem_region(&ibpf_state, src_data, sizeof(src_data), Readable, 1);
  ibpf_set_mem_region(&ibpf_state, dst_data, sizeof(dst_data), Writable, 2);
  ibpf_set_mem_region(&ibpf_state, &bpf_input_ctx, sizeof(bpf_input_ctx), Readable, 3);
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
  //printf("CertrBPF C result = 0x:%x\n", (unsigned int)result);
  
#else
  int result = ibpf_interpreter(&ibpf_state.st, 10000, (uintptr_t) &bpf_input_ctx);
  
  //printf("flag=%d\n", ibpf_state.st.flag);
  //printf("CertrBPF-JIT C result = 0x:%x\n", (unsigned int)result);
  //_magic_function(0, &ibpf_state.st);
  //printf("CertrBPF-JIT-Pure C result = 0x:%x\n", (unsigned int)(ibpf_state.st.regs_st[0]));
#endif

  uint32_t end = ztimer_now(ZTIMER_USEC);
  duration = (float)(end-begin) + duration;
  }
  printf("execution time:%f\n", duration);
  
  //printf("%s\n", dst_data);
  return 0;
}
