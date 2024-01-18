#include "rbpf_jit_compiler.h"

/*                                                                              
defining bpf_flag                                                               
 */

enum BPF_FLAG {
    vBPF_SUCC_RETURN         = 1,
    vBPF_OK                  = 0,
    vBPF_ILLEGAL_INSTRUCTION = 2,
    vBPF_ILLEGAL_MEM         = 3,
    vBPF_ILLEGAL_JUMP        = 4,
    vBPF_ILLEGAL_CALL        = 5,
    vBPF_ILLEGAL_LEN         = 6,
    vBPF_ILLEGAL_REGISTER    = 7,
    vBPF_NO_RETURN           = 8,
    vBPF_OUT_OF_BRANCHES     = 9,
    vBPF_ILLEGAL_DIV         = 10,
    vBPF_ILLEGAL_SHIFT       = 11,
    vBPF_ILLEGAL_ALU         = 12,
    vBPF_ILLEGAL_JIT         = 13,
    vBPF_ILLEGAL_ARM_LEN     = 14,
    vBPF_ILLEGAL_EP_LEN      = 15,
};

/*                                                                              
defining bpf_permission                                                               
 */

enum BPF_PERM {
    Freeable = 3,
    Writable = 2,
    Readable = 1,
    Nonempty = 0,
};

struct memory_region {
  unsigned int start_addr;
  unsigned int block_size;
  unsigned int block_perm;
  unsigned char* block_ptr;
};

struct havm_state {
  unsigned int regsmap[11]; //44-bytes
  unsigned int pc_loc; //4-bytes
  unsigned int bpf_flag; //4-bytes
  unsigned int mrs_num; //4-bytes
  struct memory_region *mrs; //16-bytes
  unsigned int input_len; //4-bytes
  const unsigned long long * input_ins; // 4-bytes
  struct key_value2* tp_kv; //4-bytes
  unsigned int tp_bin_len; //4-bytes
  unsigned int* tp_bin; //4-bytes
};

/* two global variables:
  - the start_address of jit_state: i.e. &st, it must be provided by the users after `st` is defined
  - the start_address of jitted arm array: i.e. &((*st).arm32), it also must be provided by the users after be defined
unsigned int * jit_state_start_address;
unsigned int * jitted_arm_start_address; */

extern void _magic_function(unsigned int, struct havm_state*);

unsigned int havm_interpreter(struct havm_state *, unsigned int, unsigned int);
