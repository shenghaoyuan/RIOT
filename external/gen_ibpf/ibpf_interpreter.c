/**************************************************************************/
/*  This file is part of CertrBPF,                                        */
/*  a formally verified rBPF verifier + interpreter + JIT in Coq.         */
/*                                                                        */
/*  Copyright (C) 2022 Inria                                              */
/*                                                                        */
/*  This program is free software; you can redistribute it and/or modify  */
/*  it under the terms of the GNU General Public License as published by  */
/*  the Free Software Foundation; either version 2 of the License, or     */
/*  (at your option) any later version.                                   */
/*                                                                        */
/*  This program is distributed in the hope that it will be useful,       */
/*  but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/*  GNU General Public License for more details.                          */
/*                                                                        */
/**************************************************************************/

#include "ibpf_interpreter.h"
//#include "ibpf_print.h"

static __attribute__((always_inline)) inline _Bool check_pc (struct jit_state* st) {
  return (*st).pc_loc < (*st).ins_len;
}
static __attribute__((always_inline)) inline _Bool check_pc_incr(struct jit_state* st) {
  return (*st).pc_loc+1 < (*st).ins_len;
}

static __attribute__((always_inline)) inline void upd_pc(struct jit_state* st, unsigned int pc) {
  (*st).pc_loc += pc;
  return ;
}

static __attribute__((always_inline)) inline unsigned int eval_reg(struct jit_state* st, unsigned int i){
  return (*st).regs_st[i];
}

static __attribute__((always_inline)) inline void upd_reg (struct jit_state* st, unsigned int i, unsigned int v){
  (*st).regs_st[i] = v;
  return ;
}

static __attribute__((always_inline)) inline unsigned eval_flag(struct jit_state* st){
  return (*st).flag;
}

static __attribute__((always_inline)) inline void upd_flag(struct jit_state* st, unsigned f){
  (*st).flag = f;
  return ;
}

static __attribute__((always_inline)) inline unsigned int eval_mrs_num(struct jit_state* st){
  return (*st).mrs_num;
}

static __attribute__((always_inline)) inline struct memory_region *eval_mrs_regions(struct jit_state* st){
  return (*st).bpf_mrs;
}


static __attribute__((always_inline)) inline unsigned int load_mem(struct jit_state* st, unsigned int chunk, unsigned char* addr){
  switch (chunk) {
    case 1: return *(unsigned char *) addr;
    case 2: return *(unsigned short *) addr;
    case 4: return *(unsigned int *) addr;
    //case 8: return *(unsigned long long *) addr;
    default: /*printf ("load:addr = %" PRIu64 "\n", v); (*st).flag = BPF_ILLEGAL_MEM;*/ return 0LLU;
  }
}

static __attribute__((always_inline)) inline void store_mem_reg(struct jit_state* st, unsigned char* addr, unsigned int chunk, unsigned int v){
  switch (chunk) {
    case 1: *(unsigned char *) addr = v; return ;
    case 2: *(unsigned short *) addr = v; return ;
    case 4: *(unsigned int *) addr = v; return ;
    //case 8: *(unsigned long long *) addr = v; return ;
    default: /*printf ("store_reg:addr = %" PRIu64 "\n", addr); (*st).flag = BPF_ILLEGAL_MEM;*/ return ;
  }
}

static __attribute__((always_inline)) inline void store_mem_imm(struct jit_state* st, unsigned char* addr, unsigned int chunk, int v){
  switch (chunk) {
    case 1: *(unsigned char *) addr = v; return ;
    case 2: *(unsigned short *) addr = v; return ;
    case 4: *(unsigned int *) addr = v; return ;
    //case 8: *(unsigned long long *) addr = v; return ;
    default: /*printf ("store_imm:addr = %" PRIu64 "\n", addr); (*st).flag = BPF_ILLEGAL_MEM;*/ return ;
  }
}

static __attribute__((always_inline)) inline unsigned int eval_ins_len(struct jit_state* st)
{
  return (*st).ins_len;
}

static __attribute__((always_inline)) inline unsigned long long eval_ins(struct jit_state* st)
{
  return *((*st).jit_ins + (*st).pc_loc);
}

static __attribute__((always_inline)) inline unsigned long long eval_ins_key(struct jit_state* st, unsigned int pc)
{
  return *((*st).jit_ins + pc);
}


static __attribute__((always_inline)) inline _Bool cmp_ptr32_nullM(unsigned char* addr){
   return (addr == 0);
}

static __attribute__((always_inline)) inline unsigned int get_dst(unsigned long long ins)
{
  return (unsigned int) ((ins & 4095LLU) >> 8LLU);
}

static __attribute__((always_inline)) inline unsigned int get_src(unsigned long long ins)
{
  return (unsigned int) ((ins & 65535LLU) >> 12LLU);
}

static __attribute__((always_inline)) inline struct memory_region *get_mem_region(unsigned int n, struct memory_region *mrs)
{
  return mrs + n;
}

static __attribute__((always_inline)) inline unsigned char *_bpf_get_call(int imm) {
  /* deleting `return NULL;` and adding your system APIs
  switch (imm) {
    default: return ...
  }
  */
  return NULL;
}

static __attribute__((always_inline)) inline unsigned int exec_function(struct jit_state* st, unsigned char * ptr){
  if (ptr == 0){
    (*st).flag = vBPF_ILLEGAL_CALL;
    return 0U;
  }
  else {
    /**do something e.g. print; */
    return 0U;
  }
}

static __attribute__((always_inline)) inline void upd_IR11_jittedthumb(struct jit_state* st, _Bool f){
  (*st).use_IR11 = f;
  return ;
}

static __attribute__((always_inline)) inline void upd_bpf_offset_jittedthumb(struct jit_state* st){
  (*st).offset = (*st).offset + 1U;
  return ;
}

static __attribute__((always_inline)) inline void upd_load_store_regs_jittedthumb(struct jit_state* st, unsigned int r, _Bool ls){
  (*st).load_store_regs[r] = ls;
  return ;
}

static __attribute__((always_inline)) inline void upd_jitted_list(struct jit_state* st, unsigned int ins){
  if ((*st).jitted_len + (*st).thumb_len + 2 <= JITTED_LIST_MAX_LENGTH) {
    (*st).jitted_list[(*st).jitted_len+(*st).thumb_len] = ins;
    (*st).thumb_len = (*st).thumb_len + 1U;
    return ;
  }
  else
  {
    (*st).flag = vBPF_ILLEGAL_ARM_LEN;
    return ;
  }
}


static __attribute__((always_inline)) inline void magic_function(struct jit_state* st, unsigned int ofs){
  //_magic_function is user-defined or compcert build-in
  // for user-defined, we swapped the order to make sure r0 is the start address of jitted_list while r1 is the start address of jit_state.
  _magic_function(ofs, st);
  return ;
}

static __attribute__((always_inline)) inline _Bool eval_use_IR11(struct jit_state* st){
  return (*st).use_IR11;
}

static __attribute__((always_inline)) inline unsigned int eval_offset(struct jit_state* st){
  return (*st).offset;
}

static __attribute__((always_inline)) inline unsigned int eval_thumb_len(struct jit_state* st){
  return (*st).thumb_len;
}

static __attribute__((always_inline)) inline unsigned int eval_jitted_len(struct jit_state* st){
  return (*st).jitted_len;
}

static __attribute__((always_inline)) inline _Bool eval_LoadStoreRegs(struct jit_state* st, unsigned int r){
  return (*st).load_store_regs[r];
}

// a recursion implementation of power2 to replace pow(2, _) from math.h because CompCert doesn't support math.h
unsigned int power2(unsigned int width){
  if (width == 0U) {
    return 1U;
  }
  else {
    return 2U * power2(width - 1U);
  }
}

static __attribute__((always_inline)) inline unsigned int decode_thumb(unsigned int ins, unsigned int from, unsigned int size){
  return ( (ins >> from) & (power2(size) - 1U) );
}

static __attribute__((always_inline)) inline unsigned int decode_thumb_sign(int ins, unsigned int from, unsigned int size){
  return ( (ins >> from) & (power2(size) - 1U) );
}

static __attribute__((always_inline)) inline unsigned int encode_thumb(unsigned int v, unsigned int ins, unsigned int from, unsigned int size){
  unsigned int mask;
  mask = (power2(size) - 1U) << from;
  return ( ((v & (power2(size) - 1U)) << from) | (ins & (~mask)) );
}

static __attribute__((always_inline)) inline unsigned int encode_thumb_sign(int v, unsigned int ins, unsigned int from, unsigned int size){
  unsigned int mask;
  mask = (power2(size) - 1U) << from;
  return ( ((v & (power2(size) - 1U)) << from) | (ins & (~mask)) );
}

static __attribute__((always_inline)) inline unsigned int reg_of_ireg(unsigned int ir){
  return ir;
}

static __attribute__((always_inline)) inline unsigned char opcode_reg_of_imm(unsigned char op){
  switch (op) {
    case 4:
      return 12;
    case 20:
      return 28;
    case 36:
      return 44;
    case 68:
      return 76;
    case 84:
      return 92;
    case 164:
      return 172;
    case 180:
      return 188;
    default:
      return 0;
  }
}

static __attribute__((always_inline)) inline _Bool ins_is_bpf_alu32(unsigned long long ins){
  unsigned char op;
  op = (unsigned char) (ins & 255LLU);
  return (op == 4) || (op == 12) ||
  	 (op == 20) || (op == 28) ||
  	 (op == 36) || (op == 44) ||
  	 (op == 52) ||
  	 (op == 68) || (op == 76) ||
  	 (op == 84) || (op == 92) ||
  	 (op == 100) || (op == 108) ||
  	 (op == 116) || (op == 124) ||
  	 (op == 132) ||
  	 (op == 164) || (op == 172) ||
  	 (op == 180) || (op == 188) ||
  	 (op == 196) || (op == 204);
}
static __attribute__((always_inline)) inline _Bool ins_is_bpf_jump(unsigned long long ins){
  unsigned char op;
  op = (unsigned char) (ins & 255LLU);
  return (op == 5) ||
  	 (op == 21) || (op == 29) ||
  	 (op == 37) || (op == 45) ||
  	 (op == 53) || (op == 61) ||
  	 (op == 69) || (op == 77) ||
  	 (op == 85) || (op == 93) ||
  	 (op == 101) || (op == 109) ||
  	 (op == 117) || (op == 125) ||
  	 (op == 165) || (op == 173) ||
  	 (op == 181) || (op == 189) ||
  	 (op == 197) || (op == 205) ||
  	 (op == 213) || (op == 221);
  
}

static __attribute__((always_inline)) inline void reset_init_jittedthumb(struct jit_state* st){
  (*st).use_IR11 = 0;
  for (int i = 0; i < 11; i ++) { (*st).load_store_regs[i] = NonPerm; }
  (*st).offset = 0U;
  (*st).thumb_len = 0U;
  return ;
}

static __attribute__((always_inline)) inline unsigned int eval_key_value2_arm_ofs(struct jit_state* st){
  return (*st).kv2[(*st).pc_loc].arm_ofs;
}

static __attribute__((always_inline)) inline unsigned int eval_key_value2_alu32_ofs(struct jit_state* st){
  return (*st).kv2[(*st).pc_loc].alu32_ofs;
}

static __attribute__((always_inline)) inline void upd_jitted_list_jitted_len(struct jit_state* st){
  (*st).jitted_len += (*st).thumb_len; 
  return ;
}

static __attribute__((always_inline)) inline void add_key_value2(struct jit_state* st, unsigned int pc, unsigned int ofs0, unsigned int ofs1){
  (*st).kv2[pc].arm_ofs = ofs0;
  (*st).kv2[pc].alu32_ofs = ofs1;
  return ;
}

/*******************below code are automatically generated by dx (after repatch) ***************************/

static __attribute__((always_inline)) inline void construct_thumb_b(struct jit_state* st, unsigned int cd, unsigned int imm20)
{
  unsigned int ins_imm11;
  unsigned int ins_imm6;
  unsigned int ins_j1;
  unsigned int ins_j2;
  unsigned int ins_s;
  unsigned int ins_lo_i6;
  unsigned int ins_lo_cd;
  unsigned int ins_lo;
  unsigned int ins_hi_11;
  unsigned int ins_hi_j2;
  unsigned int ins_hi;
  ins_imm11 = decode_thumb(imm20, 0U, 11U);
  ins_imm6 = decode_thumb(imm20, 11U, 6U);
  ins_j1 = decode_thumb(imm20, 17U, 1U);
  ins_j2 = decode_thumb(imm20, 18U, 1U);
  ins_s = decode_thumb(imm20, 19U, 1U);
  ins_lo_i6 = encode_thumb(ins_imm6, 61440, 0U, 6U);
  ins_lo_cd = encode_thumb(cd, ins_lo_i6, 6U, 4U);
  ins_lo = encode_thumb(ins_s, ins_lo_cd, 10U, 1U);
  ins_hi_11 = encode_thumb(ins_imm11, 32768, 0U, 11U);
  ins_hi_j2 = encode_thumb(ins_j2, ins_hi_11, 11U, 1U);
  ins_hi = encode_thumb(ins_j1, ins_hi_j2, 13U, 1U);
  upd_jitted_list(st, ins_lo);
  upd_jitted_list(st, ins_hi);
  return;
}

static __attribute__((always_inline)) inline unsigned short construct_thumb2_shift_rd_rm(unsigned short rd, unsigned short rm)
{
  unsigned int ins_rd;
  ins_rd = encode_thumb(rd, rm, 8U, 4U);
  return encode_thumb(15, ins_rd, 12U, 4U);
}

static __attribute__((always_inline)) inline void jit_alu32_thumb_store_template_jit(struct jit_state* st, unsigned short rt, unsigned short rn, unsigned short imm12)
{
  unsigned int str_low;
  unsigned int str_high;
  str_low = encode_thumb(rn, 63680, 0U, 4U);
  str_high = encode_thumb(rt, imm12, 12U, 4U);
  upd_jitted_list(st, str_low);
  upd_jitted_list(st, str_high);
  return;
}

static __attribute__((always_inline)) inline void jit_alu32_thumb_load_template_jit(struct jit_state* st, unsigned short rt, unsigned short rn, unsigned short imm12)
{
  unsigned int str_low;
  unsigned int str_high;
  str_low = encode_thumb(rn, 63696, 0U, 4U);
  str_high = encode_thumb(rt, imm12, 12U, 4U);
  upd_jitted_list(st, str_low);
  upd_jitted_list(st, str_high);
  return;
}

static __attribute__((always_inline)) inline int get_offset(unsigned long long ins)
{
  return (int) (short) (ins << 32LLU >> 48LLU);
}

static __attribute__((always_inline)) inline void jit_alu32_store_flag(struct jit_state* st, unsigned int f)
{
  unsigned int movw_hi;
  movw_hi = encode_thumb(11U, f, 8U, 4U);
  upd_jitted_list(st, 62016);
  upd_jitted_list(st, movw_hi);
  jit_alu32_thumb_store_template_jit(st, 11U, 12U, 0U);
  return;
}

static __attribute__((always_inline)) inline void jit_alu32_pre(struct jit_state* st)
{
  unsigned int ins_rdn;
  unsigned int ins_rm;
  unsigned int ins_mov;
  ins_rdn = encode_thumb(4, 17920, 0U, 3U);
  ins_rm = encode_thumb(1, ins_rdn, 3U, 4U);
  ins_mov = encode_thumb(1, ins_rm, 7U, 1U);
  upd_jitted_list(st, ins_mov);
  return;
}

static __attribute__((always_inline)) inline void jit_alu32_thumb_upd_save(struct jit_state* st, unsigned int r)
{
  _Bool b;
  b = eval_LoadStoreRegs(st, r);
  if (b) {
    jit_alu32_thumb_store_template_jit(st, r, 13U, r * 4);
    return;
  } else {
    return;
  }
}

static __attribute__((always_inline)) inline void jit_alu32_thumb_save(struct jit_state* st)
{
  _Bool b;
  jit_alu32_thumb_upd_save(st, 4U);
  jit_alu32_thumb_upd_save(st, 5U);
  jit_alu32_thumb_upd_save(st, 6U);
  jit_alu32_thumb_upd_save(st, 7U);
  jit_alu32_thumb_upd_save(st, 8U);
  jit_alu32_thumb_upd_save(st, 9U);
  jit_alu32_thumb_upd_save(st, 10U);
  b = eval_use_IR11(st);
  if (b) {
    jit_alu32_thumb_store_template_jit(st, 11, 13U, 44);
    return;
  } else {
    return;
  }
}

static __attribute__((always_inline)) inline void jit_alu32_thumb_upd_load(struct jit_state* st, unsigned int r)
{
  _Bool b;
  b = eval_LoadStoreRegs(st, r);
  if (b) {
    jit_alu32_thumb_load_template_jit(st, r, 12, r * 4 + 4);
    return;
  } else {
    return;
  }
}

static __attribute__((always_inline)) inline void jit_alu32_thumb_load(struct jit_state* st)
{
  jit_alu32_thumb_upd_load(st, 10U);
  jit_alu32_thumb_upd_load(st, 9U);
  jit_alu32_thumb_upd_load(st, 8U);
  jit_alu32_thumb_upd_load(st, 7U);
  jit_alu32_thumb_upd_load(st, 6U);
  jit_alu32_thumb_upd_load(st, 5U);
  jit_alu32_thumb_upd_load(st, 4U);
  jit_alu32_thumb_upd_load(st, 3U);
  jit_alu32_thumb_upd_load(st, 2U);
  jit_alu32_thumb_upd_load(st, 1U);
  jit_alu32_thumb_upd_load(st, 0U);
  return;
}

static __attribute__((always_inline)) inline void bpf_alu32_reg_comm(struct jit_state* st, unsigned short op, unsigned int dst, unsigned int src)
{
  unsigned int ins_lo;
  unsigned int ins_hi;
  ins_lo = encode_thumb(dst, op, 0U, 4U);
  ins_hi = encode_thumb(dst, src, 8U, 4U);
  upd_jitted_list(st, ins_lo);
  upd_jitted_list(st, ins_hi);
  return;
}

int get_bl_cur_ofs(unsigned int len)
{
  return (int) -((len * 2U + 4U) / 2U);
}

static __attribute__((always_inline)) inline void bpf_alu32_reg_shift_comm(struct jit_state* st, unsigned short op, unsigned int dst, unsigned int src)
{
  unsigned int cmp_lo;
  unsigned int len;
  int cur_ofs;
  unsigned int lsl_lo;
  unsigned short lsl_hi;
  cmp_lo = encode_thumb(src, 61872, 0U, 4U);
  upd_jitted_list(st, cmp_lo);
  upd_jitted_list(st, 3872);
  construct_thumb_b(st, 11, 6);
  jit_alu32_store_flag(st, 11U);
  len = eval_thumb_len(st);
  if (len <= 2U) {
    upd_flag(st, 12U);
    return;
  } else {
    cur_ofs = get_bl_cur_ofs(len);
    if (-65536 <= cur_ofs && cur_ofs <= 65535) {
      construct_thumb_b(st, 10, cur_ofs);
      lsl_lo = encode_thumb(dst, op, 0U, 4U);
      lsl_hi = construct_thumb2_shift_rd_rm(dst, src);
      upd_jitted_list(st, lsl_lo);
      upd_jitted_list(st, lsl_hi);
      return;
    } else {
      upd_flag(st, 12U);
      return;
    }
  }
}

static __attribute__((always_inline)) inline void bpf_alu32_to_thumb_reg(struct jit_state* st, unsigned char op, unsigned int dst, unsigned int src)
{
  unsigned int d;
  unsigned int rdn;
  unsigned int ins_rdn;
  unsigned int ins_rm;
  unsigned int ins;
  unsigned int ins_lo;
  unsigned int ins_hi0;
  unsigned int ins_hi;
  unsigned int cmp_lo;
  unsigned int len;
  int cur_ofs;
  switch (op) {
    case 12:
      if (dst < 8) {
        d = 0;
      } else {
        d = 1;
      }
      if (dst < 8) {
        rdn = dst;
      } else {
        rdn = dst - 8;
      }
      ins_rdn = encode_thumb(rdn, 17408, 0U, 3U);
      ins_rm = encode_thumb(src, ins_rdn, 3U, 4U);
      ins = encode_thumb(d, ins_rm, 7U, 1U);
      upd_jitted_list(st, ins);
      return;
    case 28:
      bpf_alu32_reg_comm(st, 60320, dst, src);
      return;
    case 44:
      ins_lo = encode_thumb(dst, 64256, 0U, 4U);
      ins_hi0 = encode_thumb(dst, src, 8U, 4U);
      ins_hi = encode_thumb(15, ins_hi0, 12U, 4U);
      upd_jitted_list(st, ins_lo);
      upd_jitted_list(st, ins_hi);
      return;
    case 60:
      if (dst == 0U && src == 1U) {
        cmp_lo = encode_thumb(src, 61872, 0U, 4U);
        upd_jitted_list(st, cmp_lo);
        upd_jitted_list(st, 3840);
        construct_thumb_b(st, 1, 6);
        jit_alu32_store_flag(st, 10U);
        len = eval_thumb_len(st);
        if (len <= 2U) {
          upd_flag(st, 12U);
          return;
        } else {
          cur_ofs = get_bl_cur_ofs(len);
          if (-65536 <= cur_ofs && cur_ofs <= 65535) {
            construct_thumb_b(st, 0, cur_ofs);
            upd_jitted_list(st, 64432);
            upd_jitted_list(st, 61681);
            return;
          } else {
            upd_flag(st, 12U);
            return;
          }
        }
      } else {
        upd_flag(st, 10U);
        return;
      }
    case 76:
      bpf_alu32_reg_comm(st, 59968, dst, src);
      return;
    case 92:
      bpf_alu32_reg_comm(st, 59904, dst, src);
      return;
    case 108:
      bpf_alu32_reg_shift_comm(st, 64000, dst, src);
      return;
    case 124:
      bpf_alu32_reg_shift_comm(st, 64032, dst, src);
      return;
    case 172:
      bpf_alu32_reg_comm(st, 60032, dst, src);
      return;
    case 188:
      if (dst == src) {
        return;
      } else {
        if (dst < 8) {
          d = 0;
        } else {
          d = 1;
        }
        if (dst < 8) {
          rdn = dst;
        } else {
          rdn = dst - 8;
        }
        ins_rdn = encode_thumb(rdn, 17920, 0U, 3U);
        ins_rm = encode_thumb(src, ins_rdn, 3U, 4U);
        ins = encode_thumb(d, ins_rm, 7U, 1U);
        upd_jitted_list(st, ins);
        return;
      }
    case 204:
      bpf_alu32_reg_shift_comm(st, 64064, dst, src);
      return;
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

static __attribute__((always_inline)) inline void mov_int_to_movw(struct jit_state* st, unsigned int i, unsigned int r)
{
  unsigned int lo_imm8;
  unsigned int lo_imm3;
  unsigned int lo_i;
  unsigned int lo_imm4;
  unsigned int movw_lo_0;
  unsigned int movw_lo;
  unsigned int movw_hi_0;
  unsigned int movw_hi;
  lo_imm8 = decode_thumb(i, 0U, 8U);
  lo_imm3 = decode_thumb(i, 8U, 3U);
  lo_i = decode_thumb(i, 11U, 1U);
  lo_imm4 = decode_thumb(i, 12U, 4U);
  movw_lo_0 = encode_thumb(lo_imm4, 62016, 0U, 4U);
  movw_lo = encode_thumb(lo_i, movw_lo_0, 10U, 1U);
  movw_hi_0 = encode_thumb(r, lo_imm8, 8U, 4U);
  movw_hi = encode_thumb(lo_imm3, movw_hi_0, 12U, 3U);
  upd_jitted_list(st, movw_lo);
  upd_jitted_list(st, movw_hi);
  return;
}

static __attribute__((always_inline)) inline void mov_int_to_movt(struct jit_state* st, unsigned int i, unsigned int r)
{
  unsigned int hi_imm8;
  unsigned int hi_imm3;
  unsigned int hi_i;
  unsigned int hi_imm4;
  unsigned int movt_lo_0;
  unsigned int movt_lo;
  unsigned int movt_hi_0;
  unsigned int movt_hi;
  hi_imm8 = decode_thumb(i, 16U, 8U);
  hi_imm3 = decode_thumb(i, 24U, 3U);
  hi_i = decode_thumb(i, 27U, 1U);
  hi_imm4 = decode_thumb(i, 28U, 4U);
  movt_lo_0 = encode_thumb(hi_imm4, 62144, 0U, 4U);
  movt_lo = encode_thumb(hi_i, movt_lo_0, 10U, 1U);
  movt_hi_0 = encode_thumb(r, hi_imm8, 8U, 4U);
  movt_hi = encode_thumb(hi_imm3, movt_hi_0, 12U, 3U);
  upd_jitted_list(st, movt_lo);
  upd_jitted_list(st, movt_hi);
  return;
}

static __attribute__((always_inline)) inline void bpf_alu32_imm_comm(struct jit_state* st, unsigned short op, unsigned char opreg, unsigned int dst, unsigned int imm32)
{
  unsigned int ins_lo;
  unsigned int ins_hi;
  unsigned int hi_32;
  if (0U <= imm32 && imm32 <= 255) {
    ins_lo = encode_thumb(dst, op, 0U, 4U);
    ins_hi = encode_thumb(dst, imm32, 8U, 4U);
    upd_jitted_list(st, ins_lo);
    upd_jitted_list(st, ins_hi);
    return;
  } else {
    hi_32 = decode_thumb(imm32, 16U, 16U);
    if (hi_32 == 0U) {
      mov_int_to_movw(st, imm32, 11U);
      bpf_alu32_to_thumb_reg(st, opreg, dst, 11U);
      return;
    } else {
      mov_int_to_movw(st, imm32, 11U);
      mov_int_to_movt(st, imm32, 11U);
      bpf_alu32_to_thumb_reg(st, opreg, dst, 11U);
      return;
    }
  }
}

static __attribute__((always_inline)) inline void bpf_alu32_imm_shift_comm(struct jit_state* st, unsigned char opreg, unsigned int dst, unsigned int imm32)
{
  if (0U <= imm32 && imm32 < 32) {
    mov_int_to_movw(st, imm32, 11U);
    bpf_alu32_to_thumb_reg(st, opreg, dst, 11U);
    return;
  } else {
    upd_flag(st, 11U);
    return;
  }
}

static __attribute__((always_inline)) inline void bpf_alu32_to_thumb_imm(struct jit_state* st, unsigned char op, unsigned int dst, unsigned int imm32)
{
  unsigned int hi_32;
  unsigned int ins_lo;
  unsigned int ins_hi;
  switch (op) {
    case 4:
      bpf_alu32_imm_comm(st, 61696, 12U, dst, imm32);
      return;
    case 20:
      bpf_alu32_imm_comm(st, 61856, 28U, dst, imm32);
      return;
    case 36:
      hi_32 = decode_thumb(imm32, 16U, 16U);
      if (hi_32 == 0U) {
        mov_int_to_movw(st, imm32, 11U);
        bpf_alu32_to_thumb_reg(st, 44U, dst, 11U);
        return;
      } else {
        mov_int_to_movw(st, imm32, 11U);
        mov_int_to_movt(st, imm32, 11U);
        bpf_alu32_to_thumb_reg(st, 44U, dst, 11U);
        return;
      }
    case 68:
      bpf_alu32_imm_comm(st, 61504, 76U, dst, imm32);
      return;
    case 84:
      bpf_alu32_imm_comm(st, 61440, 92U, dst, imm32);
      return;
    case 100:
      bpf_alu32_imm_shift_comm(st, 108U, dst, imm32);
      return;
    case 116:
      bpf_alu32_imm_shift_comm(st, 124U, dst, imm32);
      return;
    case 132:
      hi_32 = decode_thumb(imm32, 16U, 16U);
      if (hi_32 == 0U) {
        mov_int_to_movw(st, imm32, 11U);
        ins_lo = encode_thumb(11U, 61888, 0U, 4U);
        ins_hi = encode_thumb(dst, 0U, 8U, 4U);
        upd_jitted_list(st, ins_lo);
        upd_jitted_list(st, ins_hi);
        return;
      } else {
        mov_int_to_movw(st, imm32, 11U);
        mov_int_to_movt(st, imm32, 11U);
        ins_lo = encode_thumb(11U, 61888, 0U, 4U);
        ins_hi = encode_thumb(dst, 0U, 8U, 4U);
        upd_jitted_list(st, ins_lo);
        upd_jitted_list(st, ins_hi);
        return;
      }
    case 164:
      bpf_alu32_imm_comm(st, 61568, 172U, dst, imm32);
      return;
    case 180:
      hi_32 = decode_thumb(imm32, 16U, 16U);
      if (hi_32 == 0U) {
        mov_int_to_movw(st, imm32, dst);
        return;
      } else {
        mov_int_to_movw(st, imm32, dst);
        mov_int_to_movt(st, imm32, dst);
        return;
      }
    case 196:
      bpf_alu32_imm_shift_comm(st, 204U, dst, imm32);
      return;
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

static __attribute__((always_inline)) inline int get_immediate(unsigned long long ins)
{
  return (int) (ins >> 32LLU);
}

static __attribute__((always_inline)) inline unsigned char get_opcode_ins(unsigned long long ins)
{
  return (unsigned char) (ins & 255LLU);
}

static __attribute__((always_inline)) inline unsigned char nat_to_opcode_alu32(unsigned char op)
{
  if ((op & 7U) == 4U) {
    if (0U == (op & 8U)) {
      return 4U;
    } else {
      return 12U;
    }
  } else {
    return 0U;
  }
}

static __attribute__((always_inline)) inline unsigned char nat_to_opcode_alu32_reg(unsigned char op)
{
  return op;
}

static __attribute__((always_inline)) inline unsigned char nat_to_opcode_alu32_imm(unsigned char op)
{
  return op;
}

static __attribute__((always_inline)) inline void bpf_alu32_to_thumb(struct jit_state* st, unsigned long long ins)
{
  unsigned char op;
  unsigned char opc;
  unsigned int dst;
  int imm32;
  unsigned char opr;
  unsigned int src;
  unsigned char opi;
  op = get_opcode_ins(ins);
  opc = nat_to_opcode_alu32(op);
  dst = get_dst(ins);
  imm32 = get_immediate(ins);
  switch (opc) {
    case 12:
      opr = nat_to_opcode_alu32_reg(op);
      src = get_src(ins);
      bpf_alu32_to_thumb_reg(st, opr, dst, src);
      return;
    case 4:
      opi = nat_to_opcode_alu32_imm(op);
      bpf_alu32_to_thumb_imm(st, opi, dst, imm32);
      return;
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

void jit_alu32_to_thumb_pass(struct jit_state* st, unsigned int fuel, unsigned int entry_point)
{
  unsigned int n;
  unsigned long long ins;
  _Bool b;
  if (fuel == 0U) {
    return;
  } else {
    n = fuel - 1U;
    ins = eval_ins_key(st, entry_point);
    b = ins_is_bpf_alu32(ins);
    if (b) {
      bpf_alu32_to_thumb(st, ins);
      upd_bpf_offset_jittedthumb(st);
      jit_alu32_to_thumb_pass(st, n, entry_point + 1U);
      return;
    } else {
      return;
    }
  }
}

static __attribute__((always_inline)) inline void jit_alu32_thumb_upd_store(struct jit_state* st, unsigned int r)
{
  _Bool b;
  b = eval_LoadStoreRegs(st, r);
  if (b) {
    jit_alu32_thumb_store_template_jit(st, r, 12, r * 4 + 4);
    return;
  } else {
    return;
  }
}

static __attribute__((always_inline)) inline void jit_alu32_thumb_store(struct jit_state* st)
{
  jit_alu32_thumb_upd_store(st, 0U);
  jit_alu32_thumb_upd_store(st, 1U);
  jit_alu32_thumb_upd_store(st, 2U);
  jit_alu32_thumb_upd_store(st, 3U);
  jit_alu32_thumb_upd_store(st, 4U);
  jit_alu32_thumb_upd_store(st, 5U);
  jit_alu32_thumb_upd_store(st, 6U);
  jit_alu32_thumb_upd_store(st, 7U);
  jit_alu32_thumb_upd_store(st, 8U);
  jit_alu32_thumb_upd_store(st, 9U);
  jit_alu32_thumb_upd_store(st, 10U);
  return;
}

static __attribute__((always_inline)) inline void jit_alu32_thumb_upd_reset(struct jit_state* st, unsigned int r)
{
  _Bool b;
  b = eval_LoadStoreRegs(st, r);
  if (b) {
    jit_alu32_thumb_load_template_jit(st, r, 13U, r * 4);
    return;
  } else {
    return;
  }
}

static __attribute__((always_inline)) inline void jit_alu32_thumb_reset(struct jit_state* st)
{
  _Bool f;
  f = eval_use_IR11(st);
  if (f) {
    jit_alu32_thumb_load_template_jit(st, 11, 13U, 44);
  }
  jit_alu32_thumb_upd_reset(st, 10U);
  jit_alu32_thumb_upd_reset(st, 9U);
  jit_alu32_thumb_upd_reset(st, 8U);
  jit_alu32_thumb_upd_reset(st, 7U);
  jit_alu32_thumb_upd_reset(st, 6U);
  jit_alu32_thumb_upd_reset(st, 5U);
  jit_alu32_thumb_upd_reset(st, 4U);
  return;
}

static __attribute__((always_inline)) inline void jit_alu32_post(struct jit_state* st)
{
  unsigned int ins_rm;
  jit_alu32_thumb_load_template_jit(st, 13U, 13U, 0);
  ins_rm = encode_thumb(14U, 18176, 3U, 4U);
  upd_jitted_list(st, ins_rm);
  return;
}

static __attribute__((always_inline)) inline void bpf_alu32_load_sotre_ir11_reg(struct jit_state* st, unsigned char op, unsigned int dst, unsigned int src)
{
  switch (op) {
    case 12:
      return;
    case 28:
      return;
    case 44:
      return;
    case 60:
      upd_IR11_jittedthumb(st, 1);
      return;
    case 76:
      return;
    case 92:
      return;
    case 108:
      upd_IR11_jittedthumb(st, 1);
      return;
    case 124:
      upd_IR11_jittedthumb(st, 1);
      return;
    case 172:
      return;
    case 188:
      return;
    case 204:
      upd_IR11_jittedthumb(st, 1);
      return;
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

static __attribute__((always_inline)) inline void bpf_alu32_load_sotre_ir11_imm(struct jit_state* st, unsigned char op, unsigned int dst, unsigned int imm32)
{
  switch (op) {
    case 4:
      if (0U <= imm32 && imm32 <= 255) {
        return;
      } else {
        upd_IR11_jittedthumb(st, 1);
        return;
      }
    case 20:
      if (0U <= imm32 && imm32 <= 255) {
        return;
      } else {
        upd_IR11_jittedthumb(st, 1);
        return;
      }
    case 36:
      upd_IR11_jittedthumb(st, 1);
      return;
    case 68:
      if (0U <= imm32 && imm32 <= 255) {
        return;
      } else {
        upd_IR11_jittedthumb(st, 1);
        return;
      }
    case 84:
      if (0U <= imm32 && imm32 <= 255) {
        return;
      } else {
        upd_IR11_jittedthumb(st, 1);
        return;
      }
    case 100:
      upd_IR11_jittedthumb(st, 1);
      return;
    case 116:
      upd_IR11_jittedthumb(st, 1);
      return;
    case 132:
      upd_IR11_jittedthumb(st, 1);
      return;
    case 164:
      if (0U <= imm32 && imm32 <= 255) {
        return;
      } else {
        upd_IR11_jittedthumb(st, 1);
        return;
      }
    case 180:
      return;
    case 196:
      upd_IR11_jittedthumb(st, 1);
      return;
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

static __attribute__((always_inline)) inline void bpf_alu32_load_sotre_ir11(struct jit_state* st, unsigned long long ins)
{
  unsigned char op;
  unsigned char opc;
  unsigned int dst;
  unsigned int src;
  int imm32;
  unsigned char opr;
  unsigned char opi;
  op = get_opcode_ins(ins);
  opc = nat_to_opcode_alu32(op);
  dst = get_dst(ins);
  src = get_src(ins);
  imm32 = get_immediate(ins);
  switch (opc) {
    case 12:
      opr = nat_to_opcode_alu32_reg(op);
      bpf_alu32_load_sotre_ir11_reg(st, opr, dst, src);
      upd_load_store_regs_jittedthumb(st, dst, 1);
      upd_load_store_regs_jittedthumb(st, src, 1);
      return;
    case 4:
      opi = nat_to_opcode_alu32_imm(op);
      bpf_alu32_load_sotre_ir11_imm(st, opi, dst, imm32);
      upd_load_store_regs_jittedthumb(st, dst, 1);
      return;
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

void jit_alu32_load_sotre_ir11_list(struct jit_state* st, unsigned int fuel, unsigned int ep)
{
  unsigned int n;
  unsigned long long ins;
  _Bool b;
  if (fuel == 0U) {
    return;
  } else {
    n = fuel - 1U;
    ins = eval_ins_key(st, ep);
    b = ins_is_bpf_alu32(ins);
    if (b) {
      bpf_alu32_load_sotre_ir11(st, ins);
      jit_alu32_load_sotre_ir11_list(st, n, ep + 1U);
      return;
    } else {
      return;
    }
  }
}

static __attribute__((always_inline)) inline void jit_alu32_jump_to_begin(struct jit_state* st)
{
  unsigned int len;
  int cur_ofs;
  upd_jitted_list(st, 17664);
  len = eval_thumb_len(st);
  if (len <= 2U) {
    upd_flag(st, 12U);
    return;
  } else {
    cur_ofs = get_bl_cur_ofs(len);
    if (-65536 <= cur_ofs && cur_ofs <= 65535) {
      construct_thumb_b(st, 0, cur_ofs);
      return;
    } else {
      upd_flag(st, 12U);
      return;
    }
  }
}

static __attribute__((always_inline)) inline void jit_alu32_to_thumb(struct jit_state* st, unsigned int pc)
{
  unsigned int len;
  unsigned int len0;
  unsigned int len1;
  unsigned int arm_blk_ofs;
  unsigned int ofs;
  len = eval_ins_len(st);
  reset_init_jittedthumb(st);
  jit_alu32_load_sotre_ir11_list(st, len, pc);
  jit_alu32_thumb_reset(st);
  jit_alu32_post(st);
  len0 = eval_jitted_len(st);
  len1 = eval_thumb_len(st);
  arm_blk_ofs = len0 + len1;
  jit_alu32_pre(st);
  jit_alu32_thumb_save(st);
  jit_alu32_thumb_load(st);
  jit_alu32_to_thumb_pass(st, len, pc);
  jit_alu32_thumb_store(st);
  jit_alu32_jump_to_begin(st);
  ofs = eval_offset(st);
  add_key_value2(st, pc, arm_blk_ofs, ofs - 1U);
  upd_jitted_list_jitted_len(st);
  return;
}

void jit_alu32_aux(struct jit_state* st, unsigned int fuel, unsigned int pc, _Bool pre_is_alu32)
{
  unsigned int n;
  unsigned long long ins;
  _Bool b;
  int ofs;
  unsigned int next_pc;
  unsigned long long next_ins;
  if (fuel == 0U) {
    return;
  } else {
    n = fuel - 1U;
    ins = eval_ins_key(st, pc);
    b = ins_is_bpf_alu32(ins);
    if (b) {
      if (pre_is_alu32 == 0) {
        jit_alu32_to_thumb(st, pc);
        jit_alu32_aux(st, n, pc + 1U, 1);
        return;
      } else {
        jit_alu32_aux(st, n, pc + 1U, 1);
        return;
      }
    } else {
      b = ins_is_bpf_jump(ins);
      if (b) {
        ofs = get_offset(ins);
        next_pc = pc + ofs + 1U;
        next_ins = eval_ins_key(st, next_pc);
        b = ins_is_bpf_alu32(next_ins);
        if (b) {
          jit_alu32_to_thumb(st, next_pc);
          jit_alu32_aux(st, n, pc + 1U, 0);
          return;
        } else {
          jit_alu32_aux(st, n, pc + 1U, 0);
          return;
        }
      } else {
        jit_alu32_aux(st, n, pc + 1U, 0);
        return;
      }
    }
  }
}

void jit_alu32(struct jit_state* st)
{
  unsigned int len;
  len = eval_ins_len(st);
  jit_alu32_aux(st, len, 0U, 0);
  return;
}

static __attribute__((always_inline)) inline long long eval_immediate(int ins)
{
  return (long long) ins;
}

static __attribute__((always_inline)) inline unsigned int get_src32(struct jit_state* st, unsigned char x, unsigned long long ins)
{
  int imm;
  unsigned int src;
  unsigned int src32;
  if (0U == (x & 8U)) {
    imm = get_immediate(ins);
    return imm;
  } else {
    src = get_src(ins);
    src32 = eval_reg(st, src);
    return src32;
  }
}

static __attribute__((always_inline)) inline unsigned char get_opcode_alu32(unsigned char op)
{
  return (unsigned char) (op & 240);
}

static __attribute__((always_inline)) inline unsigned char get_opcode_branch(unsigned char op)
{
  return (unsigned char) (op & 240);
}

static __attribute__((always_inline)) inline unsigned char get_opcode_mem_ld_reg(unsigned char op)
{
  return (unsigned char) (op & 255);
}

static __attribute__((always_inline)) inline unsigned char get_opcode_mem_st_imm(unsigned char op)
{
  return (unsigned char) (op & 255);
}

static __attribute__((always_inline)) inline unsigned char get_opcode_mem_st_reg(unsigned char op)
{
  return (unsigned char) (op & 255);
}

static __attribute__((always_inline)) inline unsigned char get_opcode(unsigned char op)
{
  return (unsigned char) (op & 7);
}

unsigned int get_add(unsigned int x, unsigned int y)
{
  return x + y;
}

unsigned int get_sub(unsigned int x, unsigned int y)
{
  return x - y;
}

static __attribute__((always_inline)) inline unsigned int get_addr_ofs(unsigned int x, int ofs)
{
  return x + ofs;
}

static __attribute__((always_inline)) inline unsigned int get_start_addr(struct memory_region *mr)
{
  return (*mr).start_addr;
}

static __attribute__((always_inline)) inline unsigned int get_block_size(struct memory_region *mr)
{
  return (*mr).block_size;
}

static __attribute__((always_inline)) inline unsigned int get_block_perm(struct memory_region *mr)
{
  return (*mr).block_perm;
}

static __attribute__((always_inline)) inline unsigned char *check_mem_aux2(struct memory_region *mr, unsigned int perm, unsigned int addr, unsigned int chunk)
{
  unsigned int start;
  unsigned int size;
  unsigned int mr_perm;
  unsigned int lo_ofs;
  unsigned int hi_ofs;
  start = get_start_addr(mr);
  size = get_block_size(mr);
  mr_perm = get_block_perm(mr);
  lo_ofs = get_sub(addr, start);
  hi_ofs = get_add(lo_ofs, chunk);
  if (hi_ofs <= size
        && (lo_ofs <= 4294967295U - chunk && 0U == lo_ofs % chunk)
        && mr_perm >= perm) {
    return (*mr).block_ptr + lo_ofs;
  } else {
    return 0;
  }
}

static __attribute__((always_inline)) inline unsigned char *check_mem_aux(struct jit_state* st, unsigned int num, unsigned int perm, unsigned int chunk, unsigned int addr, struct memory_region *mrs)
{
  unsigned int n;
  struct memory_region *cur_mr;
  unsigned char *check_ptr;
  _Bool is_null;
  if (num == 0U) {
    return 0;
  } else {
    n = num - 1U;
    cur_mr = get_mem_region(n, mrs);
    check_ptr = check_mem_aux2(cur_mr, perm, addr, chunk);
    is_null = cmp_ptr32_nullM(check_ptr);
    if (is_null) {
      return check_mem_aux(st, n, perm, chunk, addr, mrs);
    } else {
      return check_ptr;
    }
  }
}

unsigned char *check_mem(struct jit_state* st, unsigned int perm, unsigned int chunk, unsigned int addr)
{
  unsigned int mem_reg_num;
  struct memory_region *mrs;
  unsigned char *check_ptr;
  _Bool is_null;
  mem_reg_num = eval_mrs_num(st);
  mrs = eval_mrs_regions(st);
  check_ptr =
    check_mem_aux(st, mem_reg_num, perm, chunk, addr, mrs);
  is_null = cmp_ptr32_nullM(check_ptr);
  if (is_null) {
    return 0;
  } else {
    return check_ptr;
  }
}

static __attribute__((always_inline)) inline void step_opcode_alu32(struct jit_state* st, unsigned char op)
{
  unsigned char opcode_alu32;
  unsigned int ofs0;
  unsigned int ofs1;
  opcode_alu32 = get_opcode_alu32(op);
  switch (opcode_alu32) {
    case 0:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 16:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 32:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 48:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 64:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 80:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 96:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 112:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 128:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 144:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 160:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 176:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    case 192:
      ofs0 = eval_key_value2_arm_ofs(st);
      ofs1 = eval_key_value2_alu32_ofs(st);
      upd_pc(st, ofs1);
      magic_function(st, ofs0);
      return;
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

static __attribute__((always_inline)) inline void step_opcode_branch(struct jit_state* st, unsigned int dst32, unsigned int src32, unsigned int ofs, unsigned char op)
{
  unsigned char opcode_jmp;
  unsigned char *f_ptr;
  _Bool is_null;
  unsigned int res;
  opcode_jmp = get_opcode_branch(op);
  switch (opcode_jmp) {
    case 0:
      if (op == 5) {
        upd_pc(st, ofs);
        return;
      } else {
        upd_flag(st, 2U);
        return;
      }
    case 16:
      if (dst32 == src32) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 32:
      if (dst32 > src32) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 48:
      if (dst32 >= src32) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 160:
      if (dst32 < src32) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 176:
      if (dst32 <= src32) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 64:
      if ((dst32 & src32) != 0U) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 80:
      if (dst32 != src32) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 96:
      if ((int) dst32 > (int) src32) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 112:
      if ((int) dst32 >= (int) src32) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 192:
      if ((int) dst32 < (int) src32) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 208:
      if ((int) dst32 <= (int) src32) {
        upd_pc(st, ofs);
        return;
      } else {
        return;
      }
    case 128:
      if (op == 133) {
        f_ptr = _bpf_get_call(src32);
        is_null = cmp_ptr32_nullM(f_ptr);
        if (is_null) {
          upd_flag(st, 5U);
          return;
        } else {
          res = exec_function(st, f_ptr);
          upd_reg(st, 0U, res);
          return;
        }
      } else {
        upd_flag(st, 2U);
        return;
      }
    case 144:
      if (op == 149) {
        upd_flag(st, 1U);
        return;
      } else {
        upd_flag(st, 2U);
        return;
      }
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

static __attribute__((always_inline)) inline void step_opcode_mem_ld_reg(struct jit_state* st, unsigned int addr, unsigned int dst, unsigned char op)
{
  unsigned char opcode_ld;
  unsigned char *addr_ptr;
  _Bool is_null;
  unsigned long long v;
  opcode_ld = get_opcode_mem_ld_reg(op);
  switch (opcode_ld) {
    case 97:
      addr_ptr = check_mem(st, 1U, 4U, addr);
      is_null = cmp_ptr32_nullM(addr_ptr);
      if (is_null) {
        upd_flag(st, 3U);
        return;
      } else {
        v = load_mem(st, 4U, addr_ptr);
        upd_reg(st, dst, v);
        return;
      }
    case 105:
      addr_ptr = check_mem(st, 1U, 2U, addr);
      is_null = cmp_ptr32_nullM(addr_ptr);
      if (is_null) {
        upd_flag(st, 3U);
        return;
      } else {
        v = load_mem(st, 2U, addr_ptr);
        upd_reg(st, dst, v);
        return;
      }
    case 113:
      addr_ptr = check_mem(st, 1U, 1U, addr);
      is_null = cmp_ptr32_nullM(addr_ptr);
      if (is_null) {
        upd_flag(st, 3U);
        return;
      } else {
        v = load_mem(st, 1U, addr_ptr);
        upd_reg(st, dst, v);
        return;
      }
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

static __attribute__((always_inline)) inline void step_opcode_mem_st_imm(struct jit_state* st, int imm, unsigned int addr, unsigned char op)
{
  unsigned char opcode_st;
  unsigned char *addr_ptr;
  _Bool is_null;
  opcode_st = get_opcode_mem_st_imm(op);
  switch (opcode_st) {
    case 98:
      addr_ptr = check_mem(st, 2U, 4U, addr);
      is_null = cmp_ptr32_nullM(addr_ptr);
      if (is_null) {
        upd_flag(st, 3U);
        return;
      } else {
        store_mem_imm(st, addr_ptr, 4U, imm);
        return;
      }
    case 106:
      addr_ptr = check_mem(st, 2U, 2U, addr);
      is_null = cmp_ptr32_nullM(addr_ptr);
      if (is_null) {
        upd_flag(st, 3U);
        return;
      } else {
        store_mem_imm(st, addr_ptr, 2U, imm);
        return;
      }
    case 114:
      addr_ptr = check_mem(st, 2U, 1U, addr);
      is_null = cmp_ptr32_nullM(addr_ptr);
      if (is_null) {
        upd_flag(st, 3U);
        return;
      } else {
        store_mem_imm(st, addr_ptr, 1U, imm);
        return;
      }
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

static __attribute__((always_inline)) inline void step_opcode_mem_st_reg(struct jit_state* st, unsigned int src32, unsigned int addr, unsigned char op)
{
  unsigned char opcode_st;
  unsigned char *addr_ptr;
  _Bool is_null;
  opcode_st = get_opcode_mem_st_reg(op);
  switch (opcode_st) {
    case 99:
      addr_ptr = check_mem(st, 2U, 4U, addr);
      is_null = cmp_ptr32_nullM(addr_ptr);
      if (is_null) {
        upd_flag(st, 3U);
        return;
      } else {
        store_mem_reg(st, addr_ptr, 4U, src32);
        return;
      }
    case 107:
      addr_ptr = check_mem(st, 2U, 2U, addr);
      is_null = cmp_ptr32_nullM(addr_ptr);
      if (is_null) {
        upd_flag(st, 3U);
        return;
      } else {
        store_mem_reg(st, addr_ptr, 2U, src32);
        return;
      }
    case 115:
      addr_ptr = check_mem(st, 2U, 1U, addr);
      is_null = cmp_ptr32_nullM(addr_ptr);
      if (is_null) {
        upd_flag(st, 3U);
        return;
      } else {
        store_mem_reg(st, addr_ptr, 1U, src32);
        return;
      }
    default:
      upd_flag(st, 2U);
      return;
    
  }
}

static __attribute__((always_inline)) inline void step(struct jit_state* st)
{
  unsigned long long ins;
  unsigned char op;
  unsigned char opc;
  unsigned int dst;
  unsigned int dst32;
  int ofs;
  unsigned int src32;
  unsigned int src;
  unsigned int addr;
  int imm;
  ins = eval_ins(st);
  op = get_opcode_ins(ins);
  opc = get_opcode(op);
  dst = get_dst(ins);
  switch (opc) {
    case 4:
      step_opcode_alu32(st, op);
      return;
    case 5:
      dst32 = eval_reg(st, dst);
      ofs = get_offset(ins);
      src32 = get_src32(st, op, ins);
      step_opcode_branch(st, dst32, src32,
                                (unsigned int) ofs, op);
      return;
    case 1:
      src = get_src(ins);
      src32 = eval_reg(st, src);
      ofs = get_offset(ins);
      addr = get_addr_ofs(src32, ofs);
      step_opcode_mem_ld_reg(st, addr, dst, op);
      return;
    case 2:
      dst32 = eval_reg(st, dst);
      ofs = get_offset(ins);
      imm = get_immediate(ins);
      addr = get_addr_ofs(dst32, ofs);
      step_opcode_mem_st_imm(st, imm, addr, op);
      return;
    case 3:
      dst32 = eval_reg(st, dst);
      src = get_src(ins);
      src32 = eval_reg(st, src);
      ofs = get_offset(ins);
      addr = get_addr_ofs(dst32, ofs);
      step_opcode_mem_st_reg(st, src32, addr, op);
      return;
    default:
      upd_flag(st, 2U);
      return;
  }
}

static __attribute__((always_inline)) inline void interpreter_aux(struct jit_state* st, unsigned int fuel)
{
  unsigned int fuel0;
  _Bool b0;
  unsigned int f;
  _Bool b1;
  if (fuel == 0U) {
    upd_flag(st, 6U);
    return;
  } else {
    fuel0 = fuel - 1U;
    b0 = check_pc(st);
    if (b0) {
      step(st); //print_jit_state(st);
      f = eval_flag(st);
      if (f == 0U) {
        b1 = check_pc_incr(st);
        if (b1) {
          upd_pc(st, 1U);
          interpreter_aux(st, fuel0);
          return;
        } else {
          upd_flag(st, 6U);
          return;
        }
      } else {
        return;
      }
    } else {
      upd_flag(st, 6U);
      return;
    }
  }
}


unsigned long long ibpf_interpreter(struct jit_state* st, unsigned int fuel, unsigned int ctx_ptr)
{
  unsigned int f;
  unsigned long long res;
  upd_reg(st, 1U, ctx_ptr);
  interpreter_aux(st, fuel);
  f = eval_flag(st);
  if (f == 1U) {
    res = eval_reg(st, 0U);
    return res;
  } else {
    return 0LLU;
  }
}
