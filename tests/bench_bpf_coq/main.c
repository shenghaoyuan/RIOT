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
#include "bpf.h"
#include "bpf/shared.h"
#include "unaligned.h"

#include "interpreter.h"

#include "fletcher32_bpf.h"
#include "fletcher32_bpf.bin.h"


static const unsigned char wrap_around_data[] =
        "AD3Awn4kb6FtcsyE0RU25U7f55Yncn3LP3oEx9Gl4qr7iDW7I8L6Pbw9jNnh0sE4DmCKuc"
        "d1J8I34vn31W924y5GMS74vUrZQc08805aj4Tf66HgL1cO94os10V2s2GDQ825yNh9Yuq3"
        "QHcA60xl31rdA7WskVtCXI7ruH1A4qaR6Uk454hm401lLmv2cGWt5KTJmr93d3JsGaRRPs"
        "4HqYi4mFGowo8fWv48IcA3N89Z99nf0A0H2R6P0uI4Tir682Of3Rk78DUB2dIGQRRpdqVT"
        "tLhgfET2gUGU65V3edSwADMqRttI9JPVz8JS37g5QZj4Ax56rU1u0m0K8YUs57UYG5645n"
        "byNy4yqxu7";
        
static uint8_t _bpf_stack[512];

typedef struct {
    __bpf_shared_ptr(const uint16_t *, data);
    uint32_t words;
} fletcher32_ctx_t;
        
//#if BPF_COQ
static struct memory_region mr_ctx = {
  	.start_addr = 0,
  	.block_size = 0,
  	.block_perm = 0,
  	.block_ptr  = 0
  };
        
static struct memory_region mr_stk = {
  	.start_addr = 0,
  	.block_size = 0,
  	.block_perm = 0,
  	.block_ptr  = 0
  };
  
static struct memory_region mr_content ={
  	.start_addr = 0,
  	.block_size = 0,
  	.block_perm = 0,
  	.block_ptr  = 0
  };
  
static struct bpf_state st = {
    .state_pc    	= 0U,
    .bpf_flag      	= vBPF_OK,
    .regsmap   	= {0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU},
    .ins_len   	= sizeof(bpf_fletcher32_bpf_simpl_bin)/8,
    .ins		= (unsigned long long *) bpf_fletcher32_bpf_simpl_bin,
    .mrs_num   	= 3U,
    .mrs	   	= 0
  };
//#endif


static void tests_bpf_run1(void)
{
    fletcher32_ctx_t ctx = {
        .data = (const uint16_t*)wrap_around_data,
        .words = sizeof(wrap_around_data)/2,
    };
    
//#if BPF_COQ
  mr_ctx.start_addr = (uintptr_t) &ctx;
  mr_ctx.block_size = sizeof(ctx);
  mr_ctx.block_perm = Readable;
  mr_ctx.block_ptr  = (unsigned char *) (uintptr_t) &ctx;
  
  mr_stk.start_addr = (uintptr_t) _bpf_stack;
  mr_stk.block_size = 512;
  mr_stk.block_perm = Writable;
  mr_stk.block_ptr  = (unsigned char *) (uintptr_t) _bpf_stack;
  
  mr_content.start_addr = (uintptr_t) (const uint16_t *) wrap_around_data;
  mr_content.block_size = sizeof(wrap_around_data);
  mr_content.block_perm = Readable;
  mr_content.block_ptr  = (unsigned char *) (uintptr_t) (const uint16_t *) wrap_around_data;

  struct memory_region my_memory_regions[] = {mr_ctx, mr_content, mr_stk};
  
  st.mrs = my_memory_regions;
  
  st.regsmap[10] = (unsigned long long) (uintptr_t) (_bpf_stack+512);

    printf ("fletcher32 start!!! \n");
    uint64_t result;

    uint32_t begin1 = ztimer_now(ZTIMER_USEC); // unsigned long long -> uint64_t
    result = bpf_interpreter(&st, 5000);
    uint32_t end1 = ztimer_now(ZTIMER_USEC);

    printf("rBPF_fletcher32 (dx) C result = 0x%x\n", (uint32_t)result); //unsigned int uint32_t
    printf ("fletcher32 end!!! \n");

    printf("execution time: %f ms\n", (float)(end1-begin1));
    printf("execution time: %f ms\n", (float)(end1-begin1)/US_PER_MS);

/*
#else
    
    bpf_t bpf = {
        .application = fletcher32_bpf_bin,
        .application_len = sizeof(fletcher32_bpf_bin),
        .stack = _bpf_stack,
        .stack_size = sizeof(_bpf_stack),
    };
    bpf_mem_region_t region;
    printf("bpf context size: %u, memory region size: %u\n", (unsigned)sizeof(bpf_t), (unsigned)sizeof(bpf_mem_region_t));
    bpf_setup(&bpf);

    bpf_add_region(&bpf, &region,
                   (void*)wrap_around_data, sizeof(wrap_around_data), BPF_MEM_REGION_READ);
    int64_t result = 0;
    uint32_t start = ztimer_now(ZTIMER_USEC);
    int res = 0;
    for (unsigned i = 0; i < 1000; i++) {
        res = bpf_execute_ctx(&bpf, &ctx, sizeof(ctx), &result);
    }
    uint32_t stop = ztimer_now(ZTIMER_USEC);
    
    printf("execution time: %f ms\n", (float)(stop-start));
    printf("execution time: %f ms\n", (float)(stop-start)/US_PER_MS);

#endif */

    TEST_ASSERT_EQUAL_INT(0x5bac8c3d, (uint32_t)result);
}

Test *tests_bpf(void)
{
    EMB_UNIT_TESTFIXTURES(fixtures) {
        new_TestFixture(tests_bpf_run1),
    };

    EMB_UNIT_TESTCALLER(bpf_tests, NULL, NULL, fixtures);
    return (Test*)&bpf_tests;
}

int main(void)
{
    TESTS_START();
    TESTS_RUN(tests_bpf());
    TESTS_END();

    return 0;
}
