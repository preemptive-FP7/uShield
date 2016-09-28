
/*
    Chaskey-8 MAC for fixed-size 128-bit messages, based on chaskey-8 implementation for cortext M0 by B. Haase (http://mouha.be/wp-content/uploads/chaskey_cortex_m0.zip)
    (c) Jos Wetzels

arm-linux-gnueabihf-as -o chaskey_mini.o chaskey_mini.S
arm-linux-gnueabihf-ld -o chaskey_mini chaskey_mini.o
arm-linux-gnueabihf-ld -dynamic-linker /lib/ld-linux.so.3 -lc -o chaskey_mini chaskey_mini.o

*/

.data

m:
.word 0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c

k:
.word 0x833d3433, 0x009f389f, 0x2398e64f, 0x417acf39

k1:
.word 0x067a6866, 0x013e713f, 0x4731cc9e, 0x82f59e72

tag:
.word 0x79271ca9, 0xd66a1c71, 0x81ca474e, 0x49831cad

.text
.arm
.globl _start
_start:
    // load data for call
    ldr r0, =m
    ldr r8, =k1

    // chaskey_mini(r0, r8)
    bl chaskey_mini

    ldr r8, =tag
    ldr r4, [r8, #0]
    ldr r5, [r8, #4]
    ldr r6, [r8, #8]
    ldr r7, [r8, #12]

    cmp r0, r4
    bne tag_fail
    cmp r1, r5
    bne tag_fail
    cmp r2, r6
    bne tag_fail
    cmp r3, r7
    bne tag_fail
    eor r0, r0
    b tag_success
tag_fail:
    mov r0, #1
tag_success:    
    nop
    nop

/*
    chaskey_mini
        Transparant function, only clobbers r0..r3

    args:
        r0: pointer to message M followed by key k
        r8: pointer to key k1

    returns:
        tag in (r0, r1, r2, r3)
*/
chaskey_mini:
    // save program state
    push {r4-r12, lr}

    // initialize permutation input state
    ldm r0, {r0, r1, r2, r3, r4, r5, r6, r7} // get M (r0, r1, r2, r3) and k (r4, r5, r6, r7)
    eor r4, r0 // v[0] = M[0] ^ k[0]
    eor r5, r1 // v[1] = M[1] ^ k[1]
    eor r6, r2 // v[2] = M[2] ^ k[2]
    eor r7, r3 // v[3] = M[3] ^ k[3]

    ldm r8, {r0, r1, r2, r3} // get k1
    eor r4, r0 // v[0] = M[0] ^ k[0] ^ k1[0];
    eor r5, r1 // v[1] = M[1] ^ k[1] ^ k1[1];
    eor r6, r2 // v[2] = M[2] ^ k[2] ^ k1[2];
    eor r7, r3 // v[3] = M[3] ^ k[3] ^ k1[3];

    // chaskey permute 
    // expects input of state in r4 (v0),r5 (v1),r6 (v2),r7 (v3)
    // clobbers r0 ... r3
    mov r0,#16
    mov r1,#27
    mov r2,#24
    add r4,r5
    ror r5,r1
    eor r5,r4
    ror r4,r0
    add r6,r7
    ror r7,r2
    eor r7,r6
    add r4,r7
    mov r3,#19
    ror r7,r3
    eor r7,r4
    add r6,r5
    mov r3,#25
    ror r5,r3
    eor r5,r6
    ror r6,r0
    add r4,r5
    ror r5,r1
    eor r5,r4
    ror r4,r0
    add r6,r7
    ror r7,r2
    eor r7,r6
    add r4,r7
    mov r3,#19
    ror r7,r3
    eor r7,r4
    add r6,r5
    mov r3,#25
    ror r5,r3
    eor r5,r6
    ror r6,r0
    add r4,r5
    ror r5,r1
    eor r5,r4
    ror r4,r0
    add r6,r7
    ror r7,r2
    eor r7,r6
    add r4,r7
    mov r3,#19
    ror r7,r3
    eor r7,r4
    add r6,r5
    mov r3,#25
    ror r5,r3
    eor r5,r6
    ror r6,r0
    add r4,r5
    ror r5,r1
    eor r5,r4
    ror r4,r0
    add r6,r7
    ror r7,r2
    eor r7,r6
    add r4,r7
    mov r3,#19
    ror r7,r3
    eor r7,r4
    add r6,r5
    mov r3,#25
    ror r5,r3
    eor r5,r6
    ror r6,r0
    add r4,r5
    ror r5,r1
    eor r5,r4
    ror r4,r0
    add r6,r7
    ror r7,r2
    eor r7,r6
    add r4,r7
    mov r3,#19
    ror r7,r3
    eor r7,r4
    add r6,r5
    mov r3,#25
    ror r5,r3
    eor r5,r6
    ror r6,r0
    add r4,r5
    ror r5,r1
    eor r5,r4
    ror r4,r0
    add r6,r7
    ror r7,r2
    eor r7,r6
    add r4,r7
    mov r3,#19
    ror r7,r3
    eor r7,r4
    add r6,r5
    mov r3,#25
    ror r5,r3
    eor r5,r6
    ror r6,r0
    add r4,r5
    ror r5,r1
    eor r5,r4
    ror r4,r0
    add r6,r7
    ror r7,r2
    eor r7,r6
    add r4,r7
    mov r3,#19
    ror r7,r3
    eor r7,r4
    add r6,r5
    mov r3,#25
    ror r5,r3
    eor r5,r6
    ror r6,r0
    add r4,r5
    ror r5,r1
    eor r5,r4
    ror r4,r0
    add r6,r7
    ror r7,r2
    eor r7,r6
    add r4,r7
    mov r3,#19
    ror r7,r3
    eor r7,r4
    add r6,r5
    mov r3,#25
    ror r5,r3
    eor r5,r6
    ror r6,r0
    // end chaskey permute

    // get k1 from stack
    ldm r8, {r0, r1, r2, r3}    
    eor r0, r4 // v[0] ^= k1[0]
    eor r1, r5 // v[1] ^= k1[1]
    eor r2, r6 // v[2] ^= k1[2]
    eor r3, r7 // v[3] ^= k1[3]

    // Returns full-128 bit tag in r0, r1, r2, r3
    pop {r4-r12, pc}
