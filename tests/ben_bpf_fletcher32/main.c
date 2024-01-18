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
#include "havm_interpreter.h"
#endif

#include "fletcher32_compcert_bpf.h"


static const unsigned char wrap_around_data[] =
        "AD3Awn4kb6FtcsyE0RU25U7f55Yncn3LP3oEx9Gl4qr7iDW7I8L6Pbw9jNnh0sE4DmCKuc"
        "d1J8I34vn31W924y5GMS74vUrZQc08805aj4Tf66HgL1cO94os10V2s2GDQ825yNh9Yuq3"
        "QHcA60xl31rdA7WskVtCXI7ruH1A4qaR6Uk454hm401lLmv2cGWt5KTJmr93d3JsGaRRPs"
        "4HqYi4mFGowo8fWv48IcA3N89Z99nf0A0H2R6P0uI4Tir682Of3Rk78DUB2dIGQRRpdqVT"
        "tLhgfET2gUGU65V3edSwADMqRttI9JPVz8JS37g5QZj4Ax56rU1u0m0K8YUs57UYG5645n"
        "byNy4yqxu7";
        
struct fletcher32_ctx {
  const unsigned short * data; // CompCert compiles it as 32-bit
  uint32_t words;
};

struct fletcher32_ctx bpf_input_ctx = {
  .data = (const unsigned short *) wrap_around_data,
  .words = sizeof(wrap_around_data)/2,
};        

static uint8_t _bpf_stack[512];

#if BPF_COQ == 1 || BPF_COQ == 2
static struct memory_region mr_stack = {.start_addr = (uintptr_t)_bpf_stack,
                                        .block_size = sizeof(_bpf_stack),
                                        .block_perm = Freeable,
                                        .block_ptr = _bpf_stack};
                                        
static struct memory_region mr_arr = {.start_addr = (uintptr_t)wrap_around_data,
                                        .block_size = sizeof(wrap_around_data),
                                        .block_perm = Readable,
                                        .block_ptr = wrap_around_data};
                                        
static struct memory_region mr_ctx = {.start_addr = (uintptr_t)&bpf_input_ctx,
                                        .block_size = sizeof(bpf_input_ctx),
                                        .block_perm = Readable,
                                        .block_ptr = (unsigned char *) (uintptr_t) &bpf_input_ctx};
#endif     
  
#if BPF_COQ == 2

__attribute((aligned(4))) unsigned int tp_bin_list[JITTED_LIST_MAX_LENGTH];
struct key_value2 tp_kv_list[sizeof(bpf_input_bin)/8];

__attribute__ ((noinline)) void _magic_function(unsigned int ofs, struct havm_state* st){
  int res = 0;
  __asm volatile (
    "orr %[input_0], #0x1\n\t"
    "mov r12, sp\n\t"
    "sub sp, sp, #48\n\t"
    "str r12, [sp, #0]\n\t"
    "mov pc, %[input_0]\n\t"
    : [result] "=r" (res)
    : [input_1] "r" (st), [input_0] "r" (tp_bin_list + ofs)
    : "cc" //The instruction modifies the condition code flags
  );
  return ;
}
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
  struct memory_region memory_regions[] = { mr_stack, mr_arr, mr_ctx };
  
  struct jit_state jst = {
    .input_len = sizeof(bpf_input_bin)/8,
    .input_ins = (unsigned long long *) bpf_input_bin,
    .tp_kv = tp_kv_list,
    .use_IR11 = 0,
    .ld_set = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U},
    .st_set = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U},
    .tp_bin_len = 0,
    .tp_bin = tp_bin_list,
  };
  
  struct havm_state hst = {
    .regsmap = {0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, (uintptr_t)_bpf_stack+512},
    .pc_loc = 0,
    .bpf_flag = vBPF_OK,
    .mrs_num = ARRAY_SIZE(memory_regions),
    .mrs = memory_regions,
    .input_len = sizeof(bpf_input_bin)/8,
    .input_ins = (unsigned long long *) bpf_input_bin,
    .tp_kv = tp_kv_list,
    .tp_bin_len = 0,
    .tp_bin = tp_bin_list,
  };
  
  
  whole_compiler(&jst);
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
  int result = havm_interpreter(&hst, 10000, (uintptr_t) &bpf_input_ctx);
  
  //printf("flag=%d\n", ibpf_state.st.flag);
  //printf("CertrBPF-JIT C result = 0x:%x\n", (unsigned int)result);
  //_magic_function(0, &ibpf_state.st);
  //printf("CertrBPF-JIT-Pure C result = 0x:%x\n", (unsigned int)(ibpf_state.st.regs_st[0]));
#endif

  uint32_t end = ztimer_now(ZTIMER_USEC);
  float duration = (float)(end-begin);
  
  printf("execution time:%f\n", duration);
  
  return 0;
}
