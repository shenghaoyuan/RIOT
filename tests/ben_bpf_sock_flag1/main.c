#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "embUnit.h"
#include "timex.h"
#include "ztimer.h"
#include "bpf_sock.h"

#ifdef MODULE_GEN_BPF
#include "interpreter.h"
#elif defined(MODULE_GEN_IBPF)
#include "ibpf_util.h"
#else
#include "bpf.h"
#endif


unsigned char sock_flag1_compcert_bpf_bin[] = {
  0xbf, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x61, 0x12, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x55, 0x02, 0x04, 0x00, 0x0a, 0x00, 0x00, 0x00,
  0x61, 0x12, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x55, 0x02, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00,
  0x61, 0x11, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x15, 0x01, 0x01, 0x00, 0x3a, 0x00, 0x00, 0x00,
  0x77, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
  0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

struct bpf_sock mr_bpf_sock = 
{
  .bound_dev_if = 0,
  .family = AF_INET6,
  .type = SOCK_DGRAM,
  .protocol = IPPROTO_ICMPV6,
  .mark = 0,
  .priority = 0,
  .src_ip4 = 0,
  .src_ip6 = {0, 0, 0, 0},
  .src_port = 0,
  .dst_ip4 = 0,
  .dst_ip6 = {0, 0, 0, 0},
  .state = 0,
  .rx_queue_mapping = 0
};

static uint64_t gid_uid = 0x123456789abcdef0;
        
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
static struct memory_region mr_stack1 = {.start_addr = (uintptr_t)&mr_bpf_sock,
                                         .block_size = sizeof(mr_bpf_sock),
                                         .block_perm = Freeable,
                                         .block_ptr = &mr_bpf_sock};
#endif



int main(void){

#ifdef MODULE_GEN_BPF
  struct memory_region memory_regions[] = { mr_stack, mr_stack1 };
  struct bpf_state st = {
    .state_pc = 0,
    .regsmap = {0LLU, (uintptr_t)&mr_bpf_sock, gid_uid, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, 0LLU, (uintptr_t)_bpf_stack+512},
    .bpf_flag = vBPF_OK,
    .mrs = memory_regions,
    .mrs_num = ARRAY_SIZE(memory_regions),
    .ins = (unsigned long long *) sock_flag1_compcert_bpf_bin,
    .ins_len = sizeof(sock_flag1_compcert_bpf_bin),
  };
#elif defined(MODULE_GEN_IBPF)
  jitted_thumb_list = ibpf_state.jitted_thumb_list;
  ibpf_full_state_init(&ibpf_state, 2);
  ibpf_set_mem_region_one(&ibpf_state, &mr_bpf_sock, sizeof(mr_bpf_sock), Readable);
  ibpf_set_code(&ibpf_state, sock_flag1_compcert_bpf_bin, sizeof(sock_flag1_compcert_bpf_bin));
  ibpf_set_input(&ibpf_state, (uintptr_t)&mr_bpf_sock, gid_uid, 0LLU, 0LLU, 0LLU);
  jit_alu32(&ibpf_state.st);
#else
  bpf_t bpf = {
    .application = (uint8_t*)&sock_flag1_compcert_bpf_bin,
    .application_len = sizeof(sock_flag1_compcert_bpf_bin),
    .stack = _bpf_stack,
    .stack_size = sizeof(_bpf_stack),
    .flags = BPF_FLAG_PREFLIGHT_DONE,
  };
  bpf_setup(&bpf);
  int64_t res = 0;
#endif

  uint32_t begin = ztimer_now(ZTIMER_USEC); // unsigned long long -> uint64_t
#ifdef MODULE_GEN_BPF
  int result = bpf_interpreter(&st, 10000);
  
  //printf("flag=%d\n", st.bpf_flag);
  //printf("CertrBPF C result = 0x:%x\n", (unsigned int)result);
#elif defined(MODULE_GEN_IBPF)
  int result = ibpf_interpreter(&ibpf_state.st, 10000);
  
  //printf("flag=%d\n", ibpf_state.st.flag);
  //printf("CertrBPF-JIT C result = 0x:%x\n", (unsigned int)result);
  //_magic_function(0, &ibpf_state.st);
  //printf("CertrBPF-JIT-Pure C result = 0x:%x\n", (unsigned int)(ibpf_state.st.regs_st[0]));
#else
  int result = bpf_execute_ctx(&bpf, NULL, 0, &res);
  
  //printf("Vanilla-rBPF C result = 0x:%x\n", (unsigned int)result);
#endif
  uint32_t end = ztimer_now(ZTIMER_USEC);
  float duration = (float)(end-begin);
  
  printf("execution time:%f\n", duration);
  return 0;
}
