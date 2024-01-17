#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "embUnit.h"
#include "timex.h"
#include "ztimer.h"

#include "ibpf_interpreter.h"

#include "fletcher32_compcert_bpf.h"




static const unsigned char wrap_around_data[] =
        "AD3Awn4kb6FtcsyE0RU25U7f55Yncn3LP3oEx9Gl4qr7iDW7I8L6Pbw9jNnh0sE4DmCKuc"
        "d1J8I34vn31W924y5GMS74vUrZQc08805aj4Tf66HgL1cO94os10V2s2GDQ825yNh9Yuq3"
        "QHcA60xl31rdA7WskVtCXI7ruH1A4qaR6Uk454hm401lLmv2cGWt5KTJmr93d3JsGaRRPs"
        "4HqYi4mFGowo8fWv48IcA3N89Z99nf0A0H2R6P0uI4Tir682Of3Rk78DUB2dIGQRRpdqVT"
        "tLhgfET2gUGU65V3edSwADMqRttI9JPVz8JS37g5QZj4Ax56rU1u0m0K8YUs57UYG5645n"
        "byNy4yqxu7";
        
static uint8_t _bpf_stack[512];

static struct key_value2 key_value2_list[sizeof(bpf_fletcher32_compcert_bpf_bin)/8];

static unsigned short thumb_list[JITTED_LIST_MAX_LENGTH] = {0U};

__attribute((aligned(4))) static unsigned short jitted_thumb_list[JITTED_LIST_MAX_LENGTH] = {0U};

static unsigned int bpf_load_store_regs[11] = {0U};

 __attribute__ ((noinline)) void _magic_function(unsigned int ofs, struct jit_state* st){
  int res = 0;
  //printf("magic_function ofs=%d\n", ofs);
  //printf("magic_function jitted_thumb start address =0x%hn\n", jitted_thumb_list);
  //printf("magic_function jitted_thumb start address + ofs =0x%hn\n", jitted_thumb_list + ofs);
  //printf("magic_function st start address =0x%x\n", st);
  //printf("magic_function st.jitted_list start address =0x%x\n", (*st).jitted_list);

  // disables some compiler optimizations
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
  //(*st).flag = vBPF_SUCC_RETURN;
  //printf("magic function result = %d\n", res);
  return ;
}

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

static struct jit_state st = {
    .pc_loc    	= 0U,
    .flag      	= vBPF_OK,
    .regs_st   	= {0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU},
    .mrs_num   	= 2U,
    .bpf_mrs   	= 0,
    .ins_len   	= sizeof(bpf_fletcher32_compcert_bpf_bin)/8,
    .jit_ins       	= (unsigned long long *) bpf_fletcher32_compcert_bpf_bin,
    .kv2   		= key_value2_list,
    .use_IR11   	= 0,
    .load_store_regs 	= bpf_load_store_regs,
    .offset		= 0U,
    .thumb_len		= 0U,
    .thumb		= thumb_list,
    .jitted_len	= 0U,
    .jitted_list	= jitted_thumb_list
  };


int main(void){  

  printf ("fletcher32 start!!! \n");
  unsigned long long result;

  mr_stk.start_addr = (uintptr_t) _bpf_stack;
  mr_stk.block_size = 512;
  mr_stk.block_perm = Writable;
  mr_stk.block_ptr  = (unsigned char *) (uintptr_t) _bpf_stack;
  
  mr_content.start_addr = (uintptr_t) (const uint16_t *) wrap_around_data;
  mr_content.block_size = sizeof(wrap_around_data);
  mr_content.block_perm = Readable;
  mr_content.block_ptr  = (unsigned char *) (uintptr_t) (const uint16_t *) wrap_around_data;

  struct memory_region my_memory_regions[] = { mr_stk, mr_content};
  
  st.regs_st[1] = (unsigned long long) (uintptr_t) (const uint16_t *) wrap_around_data;
  st.regs_st[2] = (unsigned long long) sizeof(wrap_around_data)/2;
  st.regs_st[10] = (unsigned long long) (uintptr_t) (_bpf_stack+512);
  
  st.bpf_mrs = my_memory_regions;
  
  
  uint32_t begin = ztimer_now(ZTIMER_USEC);
  jit_alu32(&st);
  //print_jit_state_all(&st);
  
  result = ibpf_interpreter(&st, 10000);
  uint32_t end = ztimer_now(ZTIMER_USEC);
  float duration = (float)(end-begin);
  printf("execution time:%f\n", duration);
  
  printf("iBPF_fletcher32 (dx) C result = 0x:%x\n", (unsigned int)result);
  printf ("fletcher32 end!!! \n");
  return 0;
}
