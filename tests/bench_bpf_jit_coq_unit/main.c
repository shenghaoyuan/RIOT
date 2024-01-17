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
#include "util.h"

#ifdef MODULE_GEN_BPF
#include "interpreter.h"
#elif defined(MODULE_GEN_IBPF)
#include "ibpf_util.h"
#else
#include "bpf.h"
#endif

#ifdef MODULE_GEN_IBPF
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

#ifdef MODULE_GEN_BPF
static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};
#endif



static const test_content_t tests[] = {
    {
        .instruction = {
            .opcode = 0x87,
        },
        .name = "ALU neg64",
    },/*
    {
        .instruction = {
            .opcode = 0x84,
        },
        .name = "ALU neg32",
    }, */
    {
        .instruction = {
            .opcode = 0x07,
        },
        .name = "ALU Add",
    },
    {
        .instruction = {
            .opcode = 0x0c,
        },
        .name = "ALU Add32",
    },
    {
        .instruction = {
            .opcode = 0x0f,
        },
        .name = "ALU Add imm",
    },
    {
        .instruction = {
            .opcode = 0x04,
        },
        .name = "ALU Add32 imm",
    },
    {
        .instruction = {
            .opcode = 0x2f,
            .dst = 0,
            .immediate = 45,
        },
        .name = "ALU mul imm",
    },
    {
        .instruction = {
            .opcode = 0x24,
            .dst = 0,
            .immediate = 45,
        },
        .name = "ALU mul32 imm",
    },
    {
        .instruction = {
            .opcode = 0x77,
            .dst = 0,
            .immediate = 5,
        },
        .name = "ALU rsh imm",
    },
    {
        .instruction = {
            .opcode = 0x37,
            .dst = 0,
            .immediate = 5,
        },
        .name = "ALU div imm",
    },
    {
        .instruction = {
            .opcode = 0x79,
            .dst = 0,
            .src = 10,
            .offset = -16,
        },
        .name = "MEM ldxdw",
    },
    {
        .instruction = {
            .opcode = 0x7a,
            .dst = 10,
            .offset = -16,
            .immediate = 45,
        },
        .name = "MEM stdw",
    },
    {
        .instruction = {
            .opcode = 0x7b,
            .dst = 10,
            .src = 0,
            .offset = -16,
        },
        .name = "MEM stxdw",
    },
    {
        .instruction = {
            .opcode = 0x05,
            .offset = 0,
        },
        .name = "Branch always",
    },
    {
        .instruction = {
            .opcode = 0x1d,
            .offset = 0,
            .dst = 10,
            .src = 10,
        },
        .name = "Branch eq (jump)",
    },
    {
        .instruction = {
            .opcode = 0x1d,
            .offset = 0,
            .dst = 0,
            .src = 10,
        },
        .name = "Branch eq (cont)",
    },
};

static test_application_t test_app;

int main(void)
{
#ifdef MODULE_GEN_BPF
    puts("CertrBPF");
#elif defined(MODULE_GEN_IBPF)
    puts("JIT!");
#else
    puts("Other");
#endif
#if CSV_OUT
    puts("duration,code,usperinst,instrpersec");
#else
    printf("| %-16s | %-8s | %-6s | %-6s | %-16s |\n",
           "Test", "duration", "code", "us/instr", "instr per sec");
#endif
    for (size_t test_idx = 0; test_idx < ARRAY_SIZE(tests); test_idx++) {
#ifdef MODULE_GEN_BPF
        struct memory_region memory_regions[] = { mr_stack };
        struct bpf_state st = {
            .state_pc = 0,
            .regsmap = {0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, (intptr_t)_bpf_stack+512},
            .bpf_flag = vBPF_OK,
            .mrs = memory_regions,
            .mrs_num = ARRAY_SIZE(memory_regions),
            .ins = test_app.text,
            .ins_len = sizeof(test_app.text),
        };
#elif defined(MODULE_GEN_IBPF)
        jitted_thumb_list = ibpf_state.jitted_thumb_list;
#else
        bpf_t bpf = {
            .application = (uint8_t*)&test_app,
            .application_len = sizeof(test_app),
            .stack = _bpf_stack,
            .stack_size = sizeof(_bpf_stack),
            .flags = BPF_FLAG_PREFLIGHT_DONE,
        };
        bpf_setup(&bpf);
        int64_t res = 0;
#endif
        fill_instruction(&tests[test_idx].instruction, &test_app);
        
#ifdef MODULE_GEN_IBPF        
        ibpf_full_state_init(&ibpf_state, 2);
        ibpf_set_code(&ibpf_state, test_app.text, sizeof(test_app.text));
        jit_alu32(&ibpf_state.st);
#endif     

        uint32_t begin = ztimer_now(ZTIMER_USEC); // unsigned long long -> uint64_t
#ifdef MODULE_GEN_BPF
        int result = bpf_interpreter(&st, 10000);
#elif defined(MODULE_GEN_IBPF)
        int result = ibpf_interpreter(&ibpf_state.st, 10000);
#else
        int result = bpf_execute_ctx(&bpf, NULL, 0, &res);
#endif
        uint32_t end = ztimer_now(ZTIMER_USEC);
        float duration = (float)(end-begin);
        float us_per_op = duration/NUM_INSTRUCTIONS;
        float kops_per_sec = (float)(NUM_INSTRUCTIONS*US_PER_MS) / duration;
#if CSV_OUT
        printf("%f,%d,%f,%f\n",
                duration/US_PER_MS, (signed)result, us_per_op, kops_per_sec);
#else
        printf("| %-16s | %2.4fms | %6d | %2.4fus | %7.2f kops/sec |\n",
                tests[test_idx].name,
                duration/US_PER_MS, (signed)result, us_per_op, kops_per_sec);
#endif

    }

    return 0;
}
