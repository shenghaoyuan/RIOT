#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "embUnit.h"
#include "timex.h"
#include "ztimer.h"

#include "ibpf_interpreter.h"

#include "fletcher32_compcert_bpf_add_1000.h"

        
static uint8_t _bpf_stack[512];

static unsigned int bpf_flag = vBPF_OK;

unsigned long long bpf_regs_map[11] = {0LLU};

static unsigned int entry_point_list[ENTRY_POINT_MAX_LENGTH] = {0U};

static unsigned short thumb_list[JITTED_LIST_MAX_LENGTH] = {0U};

__attribute((aligned(4))) static unsigned short jitted_thumb_list[JITTED_LIST_MAX_LENGTH] = {0U};

static unsigned int bpf_load_store_regs[11] = {0U};

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

static struct memory_region mr_stk = {
  	.start_addr = 0,
  	.block_size = 0,
  	.block_perm = 0,
  	.block_ptr  = 0
  };
  
static struct jit_state st = {
    .pc_loc    	= 0U,
    .flag      	= &bpf_flag,
    .regs_st   	= bpf_regs_map,
    .mrs_num   	= 1U,
    .bpf_mrs   	= 0,
    .ins_len   	= sizeof(fletcher32_compcert_bpf_add_1000_bin)/8,
    .entry_len 	= 0U,
    .ep_list   	= entry_point_list,
    .use_IR11   	= 0,
    .load_store_regs 	= bpf_load_store_regs,
    .offset		= 0U,
    .thumb_len		= 0U,
    .thumb		= thumb_list,
    .ibpf       	= (unsigned long long *) fletcher32_compcert_bpf_add_1000_bin,
    .jitted_len	= 0U,
    .jitted_list	= jitted_thumb_list
  };



int main(void){  

  printf ("add_1000 start!!! \n");
  unsigned long long result;

  mr_stk.start_addr = (uintptr_t) _bpf_stack;
  mr_stk.block_size = 512;
  mr_stk.block_perm = Writable;
  mr_stk.block_ptr  = (unsigned char *) (uintptr_t) _bpf_stack;

  struct memory_region my_memory_regions[] = { mr_stk};
  
  bpf_regs_map[0] = 1LLU;
  bpf_regs_map[1] = 0LLU;
  bpf_regs_map[10] = (unsigned long long) (uintptr_t) (_bpf_stack+512);
  
  st.bpf_mrs = my_memory_regions;
  
  
  uint32_t begin = ztimer_now(ZTIMER_USEC);
  jit_alu32(&st);
  
  result = ibpf_interpreter(&st, 10000);
  uint32_t end = ztimer_now(ZTIMER_USEC);
  float duration = (float)(end-begin);
  printf("execution time:%f\n", duration);
  
  printf("iBPF_add_1000 (dx) C result = 0x:%x\n", (unsigned int)result);
  printf ("add_1000 end!!! \n");
  return 0;
}
