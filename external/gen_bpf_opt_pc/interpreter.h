#include<stdio.h>

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

struct bpf_state {
  unsigned int state_pc; //4-bytes
  unsigned int bpf_flag; //4-bytes
  unsigned long long regsmap[11]; //88-bytes
  unsigned int mrs_num; //4-bytes
  struct memory_region *mrs; //16-bytes
  unsigned int ins_len; //4-bytes
  const unsigned long long * ins; // 8-bytes
  unsigned int * cache; // 4-bytes
};

unsigned long long bpf_interpreter(struct bpf_state *, unsigned int, unsigned int);
