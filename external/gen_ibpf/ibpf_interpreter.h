#include<stdio.h>

#define JITTED_LIST_MAX_LENGTH 1000
#define ENTRY_POINT_MAX_LENGTH 100
//#define JITTED_LIST_MAX_LENGTH 5000
//#define ENTRY_POINT_MAX_LENGTH 600

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

/* defining load_store_regs */
enum LoadStorePerm {
    NonPerm = 0,
    LoadPerm = 1,
    StorePerm = 2,
    LoadAndStore = 3,
};

struct key_value2 {
  unsigned int arm_ofs;
  unsigned int alu32_ofs;
};

struct memory_region {
  unsigned int start_addr;
  unsigned int block_size;
  unsigned int block_perm;
  unsigned char* block_ptr;
};

struct jit_state {
  unsigned int flag;
  unsigned int regs_st[11];
  unsigned int pc_loc;
  unsigned int mrs_num;
  struct memory_region *bpf_mrs;
  unsigned int ins_len;
  unsigned long long *jit_ins;
  struct key_value2 *kv2;
  _Bool use_IR11;
  unsigned int *load_store_regs;
  unsigned int offset;
  unsigned int thumb_len;
  unsigned int jitted_len;
  unsigned short *jitted_list;
};

/* two global variables:
  - the start_address of jit_state: i.e. &st, it must be provided by the users after `st` is defined
  - the start_address of jitted arm array: i.e. &((*st).arm32), it also must be provided by the users after be defined
unsigned int * jit_state_start_address;
unsigned int * jitted_arm_start_address; */

extern void _magic_function(unsigned int, struct jit_state*);
/*
static __attribute__((always_inline)) inline void magic_function(struct jit_state* st, unsigned int ofs){
  
} */

void jit_alu32(struct jit_state *);

unsigned long long ibpf_interpreter(struct jit_state *, unsigned int, unsigned int);

