
#ifndef IBPF_UTIL_H
#define IBPF_UTIL_H

#include <string.h>
#include "havm_interpreter.h"


typedef struct {
    uint8_t stack[512];
    __attribute((aligned(4))) unsigned int tp_bin[JITTED_LIST_MAX_LENGTH];
    unsigned int tp_kv[ENTRY_POINT_MAX_LENGTH];
    struct memory_region mrs[5];
    struct havm_state st;
} ibpf_full_state_t;


static inline void ibpf_full_state_init(ibpf_full_state_t *state, unsigned int num)
{
    memset(state, 0, sizeof(ibpf_full_state_t));
    state->st.flag = vBPF_OK;
    state->st.regs_st[10] = (uintptr_t)(state->stack)+512;
    state->st.mrs_num = num;
    state->st.bpf_mrs = state->mrs;
    state->st.tp_kv = state->tp_kv;
    state->st.tp_bin = state->tp_bin;

    state->mrs[0].start_addr = (uintptr_t)state->stack;
    state->mrs[0].block_size = 512;
    state->mrs[0].block_perm = Writable;
    state->mrs[0].block_ptr = state->stack;
}

static inline void ibpf_set_mem_region(ibpf_full_state_t *state, void *ptr, size_t len, unsigned perm, unsigned num)
{
    state->mrs[num].start_addr = (uintptr_t)ptr;
    state->mrs[num].block_size = len;
    state->mrs[num].block_perm = perm;
    state->mrs[num].block_ptr = ptr;
}

static inline void ibpf_set_code(ibpf_full_state_t *state, void *ptr, size_t len)
{
    state->st.input_ins = ptr;
    state->st.input_len = len/8;
}

static inline void ibpf_set_input(ibpf_full_state_t *state, uint32_t v1, uint32_t v2, uint32_t v3, uint32_t v4, uint32_t v5)
{
    state->st.regsmap[1] = v1;
    state->st.regsmap[2] = v2;
    state->st.regsmap[3] = v3;
    state->st.regsmap[4] = v4;
    state->st.regsmap[5] = v5;
}

#endif /* IBPF_UTIL_H */
