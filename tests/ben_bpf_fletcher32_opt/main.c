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
  0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
  0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
  0x61, 0x13, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x15, 0x03, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x06, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
  0x79, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x18, 0x04, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
  0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
  0xbf, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xa5, 0x03, 0x01, 0x00, 0x67, 0x01, 0x00, 0x00,
  0xb7, 0x07, 0x00, 0x00, 0x67, 0x01, 0x00, 0x00,
  0x1f, 0x73, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x75, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x05, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0x67, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x77, 0x05, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xbf, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x69, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0f, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x08, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0xbf, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0f, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x07, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
  0xbf, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x09, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x77, 0x09, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0xbf, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x55, 0x09, 0xf5, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x5f, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x77, 0x06, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x57, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
  0x0f, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x5f, 0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x77, 0x06, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x57, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
  0x0f, 0x62, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x67, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x0f, 0x51, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0xbf, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x55, 0x03, 0xdd, 0xff, 0x00, 0x00, 0x00, 0x00,
  0x27, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
  0x18, 0x01, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
  0x10, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
  0x5f, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x77, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00,
  0x57, 0x02, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
  0x0f, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x4f, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
/* make fletcher32 BPF_LOW=0 BPF_COMPCERT=0

0000000000000000 fletcher32:
; {
       0:	18 00 00 00 00 00 ff ff 00 00 00 00 00 00 00 00	r0 = 4294901760 ll
       2:	b7 02 00 00 ff ff 00 00	r2 = 65535
;     size_t words = ctx->words;
       3:	61 13 08 00 00 00 00 00	r3 = *(u32 *)(r1 + 8)
;     while (words) {
       4:	15 03 2c 00 00 00 00 00	if r3 == 0 goto +44 <LBB0_8>
       5:	b7 06 00 00 ff ff 00 00	r6 = 65535
;     const uint16_t *data = ctx->data;
       6:	79 11 00 00 00 00 00 00	r1 = *(u64 *)(r1 + 0)
       7:	18 04 00 00 00 00 ff ff 00 00 00 00 00 00 00 00	r4 = 4294901760 ll
       9:	b7 02 00 00 ff ff 00 00	r2 = 65535

0000000000000050 LBB0_2:
;         unsigned tlen = words > 359 ? 359 : words;
      10:	bf 37 00 00 00 00 00 00	r7 = r3
      11:	a5 03 01 00 67 01 00 00	if r3 < 359 goto +1 <LBB0_4>
      12:	b7 07 00 00 67 01 00 00	r7 = 359

0000000000000068 LBB0_4:
;         words -= tlen;
      13:	1f 73 00 00 00 00 00 00	r3 -= r7
;         do {
      14:	bf 75 00 00 00 00 00 00	r5 = r7
      15:	07 05 00 00 ff ff ff ff	r5 += -1
      16:	67 05 00 00 20 00 00 00	r5 <<= 32
      17:	77 05 00 00 20 00 00 00	r5 >>= 32
      18:	bf 18 00 00 00 00 00 00	r8 = r1

0000000000000098 LBB0_5:
;             sum2 += sum1 += *data++;
      19:	69 80 00 00 00 00 00 00	r0 = *(u16 *)(r8 + 0)
      20:	0f 02 00 00 00 00 00 00	r2 += r0
      21:	07 08 00 00 02 00 00 00	r8 += 2
      22:	bf 20 00 00 00 00 00 00	r0 = r2
      23:	0f 60 00 00 00 00 00 00	r0 += r6
;         } while (--tlen);
      24:	07 07 00 00 ff ff ff ff	r7 += -1
      25:	bf 79 00 00 00 00 00 00	r9 = r7
      26:	67 09 00 00 20 00 00 00	r9 <<= 32
      27:	77 09 00 00 20 00 00 00	r9 >>= 32
      28:	bf 06 00 00 00 00 00 00	r6 = r0
      29:	55 09 f5 ff 00 00 00 00	if r9 != 0 goto -11 <LBB0_5>
;         sum2 = (sum2 & 0xffff) + (sum2 >> 16);
      30:	bf 06 00 00 00 00 00 00	r6 = r0
      31:	5f 46 00 00 00 00 00 00	r6 &= r4
      32:	77 06 00 00 10 00 00 00	r6 >>= 16
      33:	57 00 00 00 ff ff 00 00	r0 &= 65535
      34:	0f 60 00 00 00 00 00 00	r0 += r6
;         sum1 = (sum1 & 0xffff) + (sum1 >> 16);
      35:	bf 26 00 00 00 00 00 00	r6 = r2
      36:	5f 46 00 00 00 00 00 00	r6 &= r4
      37:	77 06 00 00 10 00 00 00	r6 >>= 16
      38:	57 02 00 00 ff ff 00 00	r2 &= 65535
      39:	0f 62 00 00 00 00 00 00	r2 += r6
;         do {
      40:	67 05 00 00 01 00 00 00	r5 <<= 1
      41:	0f 51 00 00 00 00 00 00	r1 += r5
      42:	07 01 00 00 02 00 00 00	r1 += 2
      43:	bf 06 00 00 00 00 00 00	r6 = r0
;     while (words) {
      44:	55 03 dd ff 00 00 00 00	if r3 != 0 goto -35 <LBB0_2>
;     sum1 = (sum1 & 0xffff) + (sum1 >> 16);
      45:	27 00 00 00 01 00 01 00	r0 *= 65537
      46:	18 01 00 00 00 00 ff ff 00 00 00 00 03 00 00 00	r1 = 17179803648 ll
      48:	5f 10 00 00 00 00 00 00	r0 &= r1

0000000000000188 LBB0_8:
      49:	bf 21 00 00 00 00 00 00	r1 = r2
      50:	77 01 00 00 10 00 00 00	r1 >>= 16
      51:	57 02 00 00 ff ff 00 00	r2 &= 65535
      52:	0f 12 00 00 00 00 00 00	r2 += r1
;     return (sum2 << 16) | sum1;
      53:	4f 20 00 00 00 00 00 00	r0 |= r2
      54:	95 00 00 00 00 00 00 00	exit

*/




static const unsigned char wrap_around_data[] =
        "AD3Awn4kb6FtcsyE0RU25U7f55Yncn3LP3oEx9Gl4qr7iDW7I8L6Pbw9jNnh0sE4DmCKuc"
        "d1J8I34vn31W924y5GMS74vUrZQc08805aj4Tf66HgL1cO94os10V2s2GDQ825yNh9Yuq3"
        "QHcA60xl31rdA7WskVtCXI7ruH1A4qaR6Uk454hm401lLmv2cGWt5KTJmr93d3JsGaRRPs"
        "4HqYi4mFGowo8fWv48IcA3N89Z99nf0A0H2R6P0uI4Tir682Of3Rk78DUB2dIGQRRpdqVT"
        "tLhgfET2gUGU65V3edSwADMqRttI9JPVz8JS37g5QZj4Ax56rU1u0m0K8YUs57UYG5645n"
        "byNy4yqxu7";

static uint8_t _bpf_stack[512];
        
struct fletcher32_ctx {
  __bpf_shared_ptr(const unsigned short *, data);
  uint32_t words;
};

struct fletcher32_ctx bpf_input_ctx = {
  .data = (const unsigned short *) wrap_around_data,
  .words = sizeof(wrap_around_data)/2,
};

#if BPF_COQ == 1 || BPF_COQ == 2
static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};
                                        
static struct memory_region mr_arr = {.start_addr = (uintptr_t)wrap_around_data,
                                        .block_size = sizeof(wrap_around_data),
                                        .block_perm = Readable,
                                        .block_ptr = wrap_around_data};
                                        
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
                 (void*)wrap_around_data, sizeof(wrap_around_data), BPF_MEM_REGION_READ);
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
  
  return 0;
}
