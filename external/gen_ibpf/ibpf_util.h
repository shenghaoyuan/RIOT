
#ifndef IBPF_UTIL_H
#define IBPF_UTIL_H

#include <string.h>
#include "ibpf_interpreter.h"


typedef struct {
    uint8_t stack[512];
    //uint64_t bpf_regs_map[11];
    __attribute((aligned(4))) unsigned short jitted_thumb_list[JITTED_LIST_MAX_LENGTH];
    struct key_value2 key_value2_list[JITTED_LIST_MAX_LENGTH];
    //unsigned short thumb_list[JITTED_LIST_MAX_LENGTH];
    unsigned int bpf_load_store_regs[11];
    struct memory_region mrs[5];
    struct jit_state st;
} ibpf_full_state_t;


static inline void ibpf_full_state_init(ibpf_full_state_t *state, unsigned int num)
{
    memset(state, 0, sizeof(ibpf_full_state_t));
    state->st.flag = vBPF_OK;
    //state->st.regs_st[10] = (uintptr_t)(state->stack);
    state->st.regs_st[10] = (uintptr_t)(state->stack)+512;
    state->st.mrs_num = num;
    state->st.bpf_mrs = state->mrs;
    state->st.kv2 = state->key_value2_list;
    state->st.load_store_regs = state->bpf_load_store_regs;
    //state->st.thumb = state->thumb_list;
    state->st.jitted_list = state->jitted_thumb_list;

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

/*
static inline void ibpf_set_mem_region_two(ibpf_full_state_t *state, void *ptr, size_t len, unsigned perm)
{
    state->mrs[2].start_addr = (uintptr_t)ptr;
    state->mrs[2].block_size = len;
    state->mrs[2].block_perm = perm;
    state->mrs[2].block_ptr = ptr;
} */

static inline void ibpf_set_code(ibpf_full_state_t *state, void *ptr, size_t len)
{
    state->st.jit_ins = ptr;
    state->st.ins_len = len/8;
}

static inline void ibpf_set_input(ibpf_full_state_t *state, uint64_t v1, uint64_t v2, uint64_t v3, uint64_t v4, uint64_t v5)
{
    state->st.regs_st[1] = v1;
    state->st.regs_st[2] = v2;
    state->st.regs_st[3] = v3;
    state->st.regs_st[4] = v4;
    state->st.regs_st[5] = v5;
}

#endif /* IBPF_UTIL_H */
