/*
 * Copyright (C) 2020 Inria
 * Copyright (C) 2020 Koen Zandberg <koen@bergzand.net>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       Tests bpf virtual machine
 *
 * @author      Koen Zandberg <koen@bergzand.net>
 *
 * @}
 */
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include "embUnit.h"
#include "timex.h"
#include "ztimer.h"
#include "bpf/shared.h"
#include "bpf/instruction.h"
#include "unaligned.h"

#if BPF_COQ
#include "interpreter.h"
#else
#include "bpf.h"
#endif

//#include "blob/bpf/average.bin.h"

unsigned char bpf_input_bin[] = {
  0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x15, 0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xb7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
  0xb7, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x0f, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x07, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
  0x07, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
  0xad, 0x23, 0xfb, 0xff, 0x00, 0x00, 0x00, 0x00,
  0xbf, 0x23, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x3f, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* make average BPF_COMPCERT=0 BPF_LOW=0

0000000000000000 average:
; {
       0:	b7 00 00 00 00 00 00 00	r0 = 0
;     for (uint32_t i = 0; i < ctx->num_variables; i++) {
       1:	61 12 00 00 00 00 00 00	r2 = *(u32 *)(r1 + 0)
       2:	b7 03 00 00 00 00 00 00	r3 = 0
       3:	15 02 09 00 00 00 00 00	if r2 == 0 goto +9 <LBB0_4>
       4:	b7 03 00 00 00 00 00 00	r3 = 0
       5:	07 01 00 00 04 00 00 00	r1 += 4
       6:	b7 00 00 00 00 00 00 00	r0 = 0

0000000000000038 LBB0_2:
;         sum += ctx->values[i];
       7:	61 14 00 00 00 00 00 00	r4 = *(u32 *)(r1 + 0)
       8:	0f 40 00 00 00 00 00 00	r0 += r4
;     for (uint32_t i = 0; i < ctx->num_variables; i++) {
       9:	07 01 00 00 04 00 00 00	r1 += 4
      10:	07 03 00 00 01 00 00 00	r3 += 1
      11:	ad 23 fb ff 00 00 00 00	if r3 < r2 goto -5 <LBB0_2>
      12:	bf 23 00 00 00 00 00 00	r3 = r2

0000000000000068 LBB0_4:
;     return sum / ctx->num_variables;
      13:	3f 30 00 00 00 00 00 00	r0 /= r3
      14:	95 00 00 00 00 00 00 00	exit
*/

typedef struct {
    uint32_t num_variables;
    uint32_t values[NUM_VARIABLES];
} averaging_ctx_t;

static uint8_t _bpf_stack[512];

static averaging_ctx_t bpf_input_ctx = { 0 };
#if BPF_COQ
static struct memory_region mr_ctx = {.start_addr = (uintptr_t)&bpf_input_ctx,
                                        .block_size = sizeof(bpf_input_ctx),
                                        .block_perm = Readable,
                                        .block_ptr = (unsigned char *)(uintptr_t)&bpf_input_ctx};

static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};
#endif


int main(void)
{
#if CSV_OUT
    puts("\"test\",\"duration\",\"code\",\"usperexec\",\"kexecspersec\"");
#else
    printf("| %-5s | %-8s | %-6s | %-6s | %-16s |\n",
           "Test", "duration", "code", "us/exec", "execs per sec");
#endif
    for (size_t test_idx = 1; test_idx <= NUM_VARIABLES; test_idx++) {
        bpf_input_ctx.num_variables = test_idx;
#if BPF_COQ
        struct memory_region memory_regions[] = { mr_ctx, mr_stack };
        //rbpf_header_t *header = (rbpf_header_t*)average_bin;
        //const void * text = (uint8_t*)header + sizeof(rbpf_header_t) + header->data_len + header->rodata_len;

#else
        bpf_t bpf = {
            .application = (uint8_t*)bpf_input_bin,
            .application_len = sizeof(bpf_input_bin),
            .stack = _bpf_stack,
            .stack_size = sizeof(_bpf_stack),
    	    .flags = BPF_FLAG_PREFLIGHT_DONE,
        };
        bpf_setup(&bpf);
        int64_t res = 0;
#endif

        uint32_t begin = ztimer_now(ZTIMER_USEC); // unsigned long long -> uint64_t
        volatile int result = 0;
        for (size_t i = 0; i < NUM_ITERATIONS; i++) {
#if BPF_COQ
            struct bpf_state st = {
                .state_pc = 0,
                .regsmap = {0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, (intptr_t)_bpf_stack+512},
                .bpf_flag = vBPF_OK,
                .mrs = memory_regions,
                .mrs_num = ARRAY_SIZE(memory_regions),
                .ins = (unsigned long long *) bpf_input_bin,
                .ins_len = sizeof(bpf_input_bin),
            };
            result = bpf_interpreter(&st, 10000, (uintptr_t) &bpf_input_ctx);
            result = st.bpf_flag;
#else
            result = bpf_execute_ctx(&bpf, &bpf_input_ctx, sizeof(bpf_input_ctx), &res);
#endif
        }
        uint32_t end = ztimer_now(ZTIMER_USEC);
        float duration = (float)(end-begin);
        float us_per_op = duration/NUM_ITERATIONS;
        float kops_per_sec = (float)(NUM_ITERATIONS*US_PER_MS) / duration;
#if CSV_OUT
        printf("\"%u\",\"%f\",\"%d\",\"%f\",\"%f\"\n",
#else
        printf("| %5u | %2.4fms | %6d | %2.4fus | %7.2f kops/sec |\n",
#endif
                test_idx,
                duration/US_PER_MS, (signed)result, us_per_op, kops_per_sec);
    }

    return 0;
}
