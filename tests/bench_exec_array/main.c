#include <stdio.h>
#include <string.h>
#include <stdint.h>

__attribute__((aligned(4))) unsigned char code[] = {
  //0x4f, 0xf0, 0x2a, 0x00, 0x70, 0x47 //encoding T2
  //0x32, 0xdb,
  0x01, 0xdb,
  0x40, 0xf2, 0x0b, 0x0b,
  0xcc, 0xf8, 0x06, 0xb0,
  0x32, 0xdb,
  0x25, 0xfa, 0x04, 0xf5,
  0x40, 0xf2, 0x2a, 0x00, 0x70, 0x47, 0x40, 0xf2, 0x3a, 0x00, 0x70, 0x47 //encoding T3
};

/*
  0x00, 0xdb,
  0x40, 0xf2, 0x0b, 0x0b,
  0xcc, 0xf8, 0x06, 0xb0,
  0x32, 0xdb,
  0x25, 0xfa, 0x04, 0xf5,
  
  ===> b always +4??? (0+4)
  
0x20000200 <code>               blt.n   0x20000204 <code+4>
0x20000202 <code+2>             movw    r11, #11
0x20000206 <code+6>             str.w   r11, [r12, #6]
0x2000020a <code+10>            blt.n   0x20000272 <impure_data+78>
0x2000020c <code+12>            lsr.w   r5, r5, r4

*/

/*
  0x01, 0xdb
  ...
  ===> b always +4??? (2+4)
  
0x20000200 <code>               blt.n   0x20000206 <code+6>
 
*/

/*
002af04f mov.w r0, #42; 0x2a
4770     bx lr
002af04f mov.w r0, #0x58; 0x3a
4770     bx lr
*/

/*
002af04f -> adopts MOVW encodeing T2 where 002a is low-16: `0 000 0000 00101010` and f04f is high-16: `11110 0 0 0010 0 1111`
*/

/*
Let's try MOVW encoding T3: 40 F2 2a 00
*/

int main(void) {
    /*
    union {
      uintptr_t as_int;
      int(*fn)(void);
    } helper;

    helper.as_int = ((uintptr_t)&code[0] | 0x1);

    int i = helper.fn();

    printf("get this done. returned: %d\n", i);
    */
    
    int j, i;
    
    __asm volatile ("orr %[input_0], #0x1\n\t"
    "blx %[input_0]\n\t"
    "mov r1, r0\n\t"
    : [result] "=r" (i)
    : [input_0] "r" (code)
    :
    );
    if (i > 10) {
       j = 10;
    }
    else {
       j = 0xdffff;
    }
    
    printf("get this done. returned: %d\n", i);
    printf("get this done. returned: %d\n", j);
    

    return 0;
}
