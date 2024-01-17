void print_reg (unsigned int r) {
  printf("R%d ", r);
  return ;
}

void print_bpf_instruction (unsigned long long ins){
  unsigned int op, dst, src;
  int imm, ofs;
  op  = (unsigned int) ins & 255LLU;
  dst = (unsigned int) ((ins & 4095LLU) >> 8LLU);
  src = (unsigned int) ((ins & 65535LLU) >> 12LLU);
  imm = (int) (ins >> 32LLU);
  ofs = (int) (short) (ins << 32LLU >> 48LLU);
  switch (op) {
    //alu64
    case 0x07:
      printf("bpf_add64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x17:
      printf("bpf_sub64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x27:
      printf("bpf_mul64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x37:
      printf("bpf_div64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x47:
      printf("bpf_or64  "); print_reg(dst); printf("%d", imm); return ;
    case 0x57:
      printf("bpf_and64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x67:
      printf("bpf_lsh64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x77:
      printf("bpf_rsh64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x87:
      printf("bpf_neg64 "); print_reg(dst); printf("%d", imm); return ;
    case 0x97:
      printf("bpf_mod64 "); print_reg(dst); printf("%d", imm); return ;
    case 0xa7:
      printf("bpf_xor64 "); print_reg(dst); printf("%d", imm); return ;
    case 0xb7:
      printf("bpf_mov64 "); print_reg(dst); printf("%d", imm); return ;
    case 0xc7:
      printf("bpf_arsh64 "); print_reg(dst); printf("%d", imm); return ;
      
    case 0x0f:
      printf("bpf_add64 "); print_reg(dst); print_reg(src); return ;
    case 0x1f:
      printf("bpf_sub64 "); print_reg(dst); print_reg(src); return ;
    case 0x2f:
      printf("bpf_mul64 "); print_reg(dst); print_reg(src); return ;
    case 0x3f:
      printf("bpf_div64 "); print_reg(dst); print_reg(src); return ;
    case 0x4f:
      printf("bpf_or64  "); print_reg(dst); print_reg(src); return ;
    case 0x5f:
      printf("bpf_and64 "); print_reg(dst); print_reg(src); return ;
    case 0x6f:
      printf("bpf_lsh64 "); print_reg(dst); print_reg(src); return ;
    case 0x7f:
      printf("bpf_rsh64 "); print_reg(dst); print_reg(src); return ;
    case 0x9f:
      printf("bpf_mod64 "); print_reg(dst); print_reg(src); return ;
    case 0xaf:
      printf("bpf_xor64 "); print_reg(dst); print_reg(src); return ;
    case 0xbf:
      printf("bpf_mov64 "); print_reg(dst); print_reg(src); return ;
    case 0xcf:
      printf("bpf_arsh64 "); print_reg(dst); print_reg(src); return ;
      
    //alu32  
    case 0x04:
      printf("bpf_add32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x14:
      printf("bpf_sub32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x24:
      printf("bpf_mul32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x34:
      printf("bpf_div32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x44:
      printf("bpf_or32  "); print_reg(dst); printf("%d", imm); return ;
    case 0x54:
      printf("bpf_and32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x64:
      printf("bpf_lsh32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x74:
      printf("bpf_rsh32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x84:
      printf("bpf_neg32 "); print_reg(dst); printf("%d", imm); return ;
    case 0x94:
      printf("bpf_mod32 "); print_reg(dst); printf("%d", imm); return ;
    case 0xa4:
      printf("bpf_xor32 "); print_reg(dst); printf("%d", imm); return ;
    case 0xb4:
      printf("bpf_mov32 "); print_reg(dst); printf("%d", imm); return ;
    case 0xc4:
      printf("bpf_arsh32 "); print_reg(dst); printf("%d", imm); return ;
    case 0xd4:
      printf("bpf_jit "); printf("%d", ofs); printf(", %d", imm); return ;
      
    case 0x0c:
      printf("bpf_add32 "); print_reg(dst); print_reg(src); return ;
    case 0x1c:
      printf("bpf_sub32 "); print_reg(dst); print_reg(src); return ;
    case 0x2c:
      printf("bpf_mul32 "); print_reg(dst); print_reg(src); return ;
    case 0x3c:
      printf("bpf_div32 "); print_reg(dst); print_reg(src); return ;
    case 0x4c:
      printf("bpf_or32  "); print_reg(dst); print_reg(src); return ;
    case 0x5c:
      printf("bpf_and32 "); print_reg(dst); print_reg(src); return ;
    case 0x6c:
      printf("bpf_lsh32 "); print_reg(dst); print_reg(src); return ;
    case 0x7c:
      printf("bpf_rsh32 "); print_reg(dst); print_reg(src); return ;
    case 0x9c:
      printf("bpf_mod32 "); print_reg(dst); print_reg(src); return ;
    case 0xac:
      printf("bpf_xor32 "); print_reg(dst); print_reg(src); return ;
    case 0xbc:
      printf("bpf_mov32 "); print_reg(dst); print_reg(src); return ;
    case 0xcc:
      printf("bpf_arsh32 "); print_reg(dst); print_reg(src); return ;
      
    //memory  
    case 0x10:
      printf("bpf_lddw_low "); print_reg(dst); printf("%d", imm); return ;
    case 0x18:
      printf("bpf_lddw_high "); print_reg(dst); printf("%d", imm); return ;
      
    case 0x61:
      printf("bpf_ldxw  "); print_reg(dst); printf(", ["); print_reg(src); printf("+ %d]", ofs); return ;
    case 0x69:
      printf("bpf_ldxh  "); print_reg(dst); printf(", ["); print_reg(src); printf("+ %d]", ofs); return ;
    case 0x71:
      printf("bpf_ldxb  "); print_reg(dst); printf(", ["); print_reg(src); printf("+ %d]", ofs); return ;
    case 0x79:
      printf("bpf_ldxdw "); print_reg(dst); printf(", ["); print_reg(src); printf("+ %d]", ofs); return ;
      
    case 0x62:
      printf("bpf_stw  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x6a:
      printf("bpf_sth  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x72:
      printf("bpf_stb  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x7a:
      printf("bpf_stdw "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
      
    case 0x63:
      printf("bpf_stxw  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x6b:
      printf("bpf_stxh  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x73:
      printf("bpf_stxb  "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    case 0x7b:
      printf("bpf_stxdw "); printf("["); print_reg(dst); printf("+ %d]", ofs); printf(", %d", imm); return ;
    
    //branch
    case 0x05:
      printf("bpf_ja "); printf(" +%d]", ofs); return ;
      
    case 0x15:
      printf("bpf_jeq "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x25:
      printf("bpf_jgt "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x35:
      printf("bpf_jge "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0xa5:
      printf("bpf_jlt "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0xb5:
      printf("bpf_jle "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x45:
      printf("bpf_jset "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x55:
      printf("bpf_jne "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x65:
      printf("bpf_jsgt "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0x75:
      printf("bpf_jsge "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0xc5:
      printf("bpf_jslt "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
    case 0xd5:
      printf("bpf_jsle "); print_reg(dst); printf(", %d", imm);  printf(", +%d", ofs); return ;
      
    case 0x1d:
      printf("bpf_jeq "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x2d:
      printf("bpf_jgt "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x3d:
      printf("bpf_jge "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0xad:
      printf("bpf_jlt "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0xbd:
      printf("bpf_jle "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x4d:
      printf("bpf_jset "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x5d:
      printf("bpf_jne "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x6d:
      printf("bpf_jsgt "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0x7d:
      printf("bpf_jsge "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0xcd:
      printf("bpf_jslt "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
    case 0xdd:
      printf("bpf_jsle "); print_reg(dst); printf(", "); print_reg(src);  printf(", +%d", ofs); return ;
      
    case 0x85:
      printf("bpf_call "); printf(" %d", imm); return ;
    case 0x95:
      printf("bpf_exit "); return ;
    default: printf("error: op = %x", op);
      return;
      
  }
}

void print_bpf_state(struct bpf_state* st){ //print_bpf_instruction (*((*st).ins + (*st).state_pc));
  print_u64_hex((*st).ins[(*st).state_pc]);
    printf("(PC)\n");
  printf("pc= %02d flag= %d\n", (*st).state_pc, (*st).bpf_flag);
    print_u64_dec((*st).regsmap[0]);
    printf("(R0)\n");
    print_u64_dec((*st).regsmap[1]);
    printf("(R1)\n");
    print_u64_dec((*st).regsmap[2]);
    printf("(R2)\n");
    print_u64_dec((*st).regsmap[3]);
    printf("(R3)\n");
    print_u64_dec((*st).regsmap[4]);
    printf("(R4)\n");
    print_u64_dec((*st).regsmap[5]);
    printf("(R5)\n");
    print_u64_dec((*st).regsmap[6]);
    printf("(R6)\n");
    print_u64_dec((*st).regsmap[7]);
    printf("(R7)\n");
    print_u64_dec((*st).regsmap[8]);
    printf("(R8)\n");
    print_u64_dec((*st).regsmap[9]);
    printf("(R9)\n");
    print_u64_dec((*st).regsmap[10]);
    printf("(R10)\n");
  return ;
}
