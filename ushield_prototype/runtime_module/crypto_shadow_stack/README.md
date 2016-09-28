# Runtime Protection Module (RPM): Crypto Shadow Stack Feature

----------

# Intro

The Runtime Protection Module (RPM) implements a parallel shadow-stack for backward-edge CFI. In many academic and practical implementations of CFI the shadow stack itself is left unprotected however, meaning a sufficiently powerful attacker (eg. one with an infoleak and write-anything-anywhere primitive) could compromise the shadow-stack in order to bypass CFI.

Our solution offers the option to address this via a crypto shadow-stack (CSS). We borrowed [this idea](http://www.scs.stanford.edu/ccfi/) from [Mashtizadeh et al.](http://iot.stanford.edu/pubs/mashtizadeh-ccfi-ccs15.pdf) (who call it Cryptographically-Enforced CFI (CCFI)) and made several improvements to it suitable to our environment:

* **Hardware-agnostic**: Whereas CCFI relies on the x86 AES-NI instruction our approach makes use of advances in lightweight blockcipher cryptography for small and fast Message Authentication (MAC) that is hardware-agnostic.

* **Binary COTS support**: Whereas CCFI requires access to the source-code and is implemented as a compiler patch, our approach can be applied to binary Commercial-Off-The-Shelf (COTS) applications.

It should be noted that AES-NI support is available for some [ARM 64-bit processors](https://en.wikipedia.org/wiki/AES_instruction_set) but since we strive for general hardware agnosticism and many embedded systems have simple CPUs without such features our solution cannot rely on any hardware-facilitated cryptographic operations.

# Design

Our CSS is a simple extension of our existing parallel shadow-stack which stores a [Message Authentication Code (MAC) tag](https://en.wikipedia.org/wiki/Message_authentication_code) on the shadow stack rather than the return address. It produces `tag = MAC(return_address | shadow_address, key)` and stores `tag` at `shadow_address` during the prologue handler. It includes the shadow-stack address with the return address in order to prevent attackers from swapping two tags on the shadow-stack (analogous to replay protection). During the epilogue handler validation is done by taking `stored_tag` from the top of the shadow stack (at address `shadow_address`), `return_address` from the top of the actual stack and producing `check_tag = MAC(return_address | shadow_address, key)` and then verifying whether `check_tag == stored_tag`. An attacker targeting the shadow stack thus needs to be able to forge a MAC for the particular entry which is reducable to the cryptographic security of the MAC in question.

Two design elements here are crucial, however:

* **Performance of the MAC**: Since we cannot draw upon the benefits of hardware-facilitated cryptography we chose to draw upon advances in [lightweight cryptography](https://www.cryptolux.org/index.php/Lightweight_Cryptography) in order to use an algorithm which offers both strong security while simultaneously taking up little space (in terms of code and memory) and clockcycles.

* **Secrecy of the MAC key**: The security of the MAC rests on the secrecy of the key so it is crucially important that it not leak to the attacker. In order to prevent this CCFI stores the key in dedicated registers (`XMM5–XMM15` on x86-64) which never leak to the program memory. We will similarly store the key in a dedicated register.

# Chaskey

After [evaluating the state-of-the-art](https://www.cryptolux.org/index.php/Lightweight_Cryptography) in lightweight blockcipher cryptography we settled for [Chaskey](https://www.cryptolux.org/index.php/Lightweight_Block_Ciphers#Chaskey_Cipher). [Chaskey is a lightweight MAC algorithm](http://mouha.be/chaskey/) optimised for 32-bit micro-controllers, has a 128-bit blocksize and 128-bit keysize. It is intended for applications that require 128-bit security, yet cannot implement standard MAC algorithms because of stringent requirements on speed, energy consumption or code size. Tests show that on an ARM Cortex-M4, Chaskey runs at 7.0 cycles/byte, compared to 89.4 cycles/byte for AES-128-CMAC and can be implemented in 402 bytes of ROM, being about ten times smaller than the smallest available AES-128-ECB implementation on this platform. This can be even further reduced by stripping Chaskey of any key-scheduling or variable-length input related functionality as those are unnecessary for our purposes.

[In tests](https://www.cryptolux.org/index.php/Lightweight_Cryptography), Chaskey outperformed similar lightweight ciphers on a variety of architectures (but especially on ARM) in terms of codesize, memory usage and speed. Regardless of the usage scenario (with or without keyschedule, encryption or decryption, etc.) Chaskey turned out to be consistently the fastest algorithm which is our primary performance-related selection metric. As such Chaskey was deemed ideal for our use-case in terms of offered security combined with performance.

Given that Chaskey is being actively researched and developed there are several variants with different security claims, eg. Chaskey-12 was proposed in order to increase the security margin of the original Chaskey-8 in the face of differential-linear attacks and Chaskey-LTS (Long Time Support) was proposed to have 16 rounds. The designers, however, remain confident that the original 8-round Chaskey will remain secure and as such our proposal will focus on this smaller 8-round Chaskey variant. Should future results lead to a break of Chaskey-8, however, a higher-round version could be readily adopted in the same manner for our CSS.

## Stripping down Chaskey

We chose the [optimized ARM Cortex-M0 assembly implementation](http://mouha.be/wp-content/uploads/chaskey_cortex_m0.zip) as our reference implementation. Chaskey is designed to work with arbitrary-length messages and as such contains block-splitting and message-absorbtion code. This functionality, however, is superfluous to our use-case as we only ever work with fixed-size message inputs (namely, a combination of return address and shadow stack address). Chaskey operates on 128-bit blocks and we have messages consisting of two addresses that are at most 64 bits. As such our input message will never exceed the length of a single block and we can discard any logic relating to full message absorbtion. From here on, we will assume addresses are 32 bits for simplicity's sake and further pad the message with a fixed-size padding rule (eg. all-zeros or the 10* padding).

Consider the [speed-optimized C implementation](http://mouha.be/wp-content/uploads/chaskey-speed.c), when stripped down in the above manner this gives us the following reduced Chaskey-8 code operating on a single block:

```c
#define ROTL(x,b) (uint32_t)( ((x) >> (32 - (b))) | ( (x) << (b)) )

#define ROUND \
  do { \
    v[0] += v[1]; v[1]=ROTL(v[1], 5); v[1] ^= v[0]; v[0]=ROTL(v[0],16); \
    v[2] += v[3]; v[3]=ROTL(v[3], 8); v[3] ^= v[2]; \
    v[0] += v[3]; v[3]=ROTL(v[3],13); v[3] ^= v[0]; \
    v[2] += v[1]; v[1]=ROTL(v[1], 7); v[1] ^= v[2]; v[2]=ROTL(v[2],16); \
  } while(0)
  
#define PERMUTE \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND; \
  ROUND;

void chaskey_mini(uint8_t *tag, const uint8_t *m, const uint32_t k[4], const uint32_t k1[4]) 
{
  const uint32_t *M = (uint32_t*)m;
  uint32_t v[4];

  v[0] = k[0];
  v[1] = k[1];
  v[2] = k[2];
  v[3] = k[3];

  v[0] ^= M[0];
  v[1] ^= M[1];
  v[2] ^= M[2];
  v[3] ^= M[3];

  v[0] ^= k1[0];
  v[1] ^= k1[1];
  v[2] ^= k1[2];
  v[3] ^= k1[3];

  PERMUTE;

  v[0] ^= k1[0];
  v[1] ^= k1[1];
  v[2] ^= k1[2];
  v[3] ^= k1[3];

  memcpy(tag, v, 16);
}
```

# Storing the secret key

Mashtizadeh's CCFI makes us of the [XMM registers](https://en.wikipedia.org/wiki/Streaming_SIMD_Extensions#Registers) available on x86 (eg. `XMM5–XMM15` on x86-64) to store the secret key and makes certain ABI changes for the compiler to ensure these registers never leak to memory. This approach can't be translated directly to our platform, however, since we have the following constraints:

* **Binary COTS support**: Hence we cannot make any retroactive ensurances a given application does not leak a certain register to memory
* **XMM registers are an x86 feature**: and as such aren't uniformely available across hardware

So what we require is an approach where we can store 256 bits of key data (two keys from the expanded key schedule) in a manner that can make reasonable guarantees they are not leaked to memory.

Many architectures, even those with limited features common in embedded environments, tend to have extensions for Single-Instruction Multiple Data (SIMD) functionality or Floating Pointer operations which come with their own dedicated (often large) registers. Like Mashtizadeh's solution we will draw upon such registers for key storage, provided they are not leaked to memory. For ARM we have basicically two options, storing the key in either:

* [NEON](http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.dht0002a/ch01s03s02.html) registers

* [VFP](https://www.arm.com/products/processors/technologies/vector-floating-point.php) registers

NEON is a SIMD extension for ARM, included in eg. all cortex-A8, which offers a register bank that consists of 32 64-bit registers which can be viewed as sixteen 128-bit quadword registers (Q0-Q15) or thirty-two 64-bit doubleword registers (D0-D31). With sixteen 128-bit quadword SIMD registers we could use two of them for key storage.

ARM Vector Floating Point (VFP) is a vector floating point extension for ARM with VFPv2 being included from ARMv5TE onward and VFPv3 included from ARMv7-A and ARMv7-R onward. VFPv2 offers 16 64-bit FPU registers while VFPv3 offers either 16 or 32 64-bit FPU registers. Hence, with at least sixteen 64-bit registers we could use four of them for key storage.

Other architectures common in embedded environments, such as eg. [MIPS](https://en.wikipedia.org/wiki/MIPS_instruction_set#MIPS_SIMD), often have dedicated SIMD extensions as well.

Since we have to work with COTS binaries and we cannot reliably determine (without complicated and incomplete control/data-flow reconstruction) whether a given register ends up in memory we will use a simple heuristic to select our registers for key storage during the setup phase. The setup module will disassemble the target binary (which does not require full CFG reconstruction) and mark which SIMD/FPU registers are used in instructions. From those registers which are not used in any instruction we will select the registers for key storage, thus guaranteeing their content does not end up in memory. If there are not sufficient free registers after such a selection the crypto shadow-stack cannot be used with the target binary in question. We consider this drawback acceptable in order to provide binary COTS support.

# Implementation

We wrote the following pure assembly (ARM) implementation of the above reduced single-block version of Chaskey-8, callable as a function. The implementation consists of 166 instructions, 148 of which are part of the Chaskey implementation and 18 of which are part of the caller/checker stub:

```asm
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
```

This function would be called during instrumented function prologues (to calculate a MAC for storage) and during instrumented function epilogues (to calculate a MAC for checking). Initialization of key values for `k` and `k1` is done only once during shadow stack initialization, keys are randomly generated by drawing upon a (suitably) secure PRNG offered by the system (eg. /dev/urandom). Note that in the above implementation these keys are drawn from memory but in a real-world deployment would draw them from dedicated register(s). We have not implemented our crypto shadow-stack approach in our RPM prototype due to time constraints but the above implementation shows the leanest and fastest option to date for non-hardware facilitated crypto shadow-stacks.