#include "jit_comm.h"

struct jit_state {
  unsigned int input_len;
  unsigned long long *input_ins;
  
  struct key_value2 *tp_kv;
  _Bool use_IR11;
  
  _Bool ld_set[11];
  _Bool st_set[11];
  
  unsigned int tp_bin_len;
  unsigned int *tp_bin;
};
/*
static __attribute__((always_inline)) inline void magic_function(struct jit_state* st, unsigned int ofs){
  
} */

void whole_compiler(struct jit_state* );
