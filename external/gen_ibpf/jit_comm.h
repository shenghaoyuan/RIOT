#include<stdio.h>

#define JITTED_LIST_MAX_LENGTH 1000
#define ENTRY_POINT_MAX_LENGTH 100

struct key_value2 {
  unsigned int arm_ofs;
  unsigned int alu32_ofs;
};
