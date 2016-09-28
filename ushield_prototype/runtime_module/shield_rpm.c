/*
uShield - Runtime Protection Module (RPM)
(c) Jos Wetzels, Wouter Bokslag

This code implements the runtime protection module (RPM) of uShield

gcc -Wall -fPIC -shared -o shield_rpm.so shield_rpm.c -ldl
LD_PRELOAD=./shield_rpm.so ./test

*/
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>

/* --------------------------------------------------------
					CONFIGURATION START
   -------------------------------------------------------- */

#define APP_NAME "test"

// Alert logging functionality
#define ALERT_LOG_FILE "/home/pi/prototype/rpm/alert_log"

#define MEASURE_LOG "log"
#define MEASURE_RESTART "restart"
#define MEASURE_KILL "kill"

// Policy measures (log, restart, kill)
#define DETECT_MEASURE MEASURE_LOG

// Enable forward-edge protection
#define FORWARD_EDGE_PROTECTION
// Enable backward-edge protection
#define BACKWARD_EDGE_PROTECTION

// Shadow stack size (in bytes), default is 4MB
#define SHADOW_STACK_SIZE (1024 * 1024 * 4)

// Instruction count threshold within which we have to find stackcookie setup
#define CPTR_PROLOGUE_COOKIE_THRESHOLD 25

// Notification function that's always available, regardless of debugging mode
#define notify_msg(...) fprintf(stdout, __VA_ARGS__); fflush(stdout)

#define DEBUG_MODE

#ifdef DEBUG_MODE
	//#define DEBUG_MODE_TECHNICAL
	//#define DEBUG_MODE_VERBOSE
	//#define DEBUG_MODE_VERBOSE2

	#define debug_log(...) fprintf(stdout, __VA_ARGS__); fflush(stdout)
#endif

//#define SUPPRESS_ALERTS
//#define VERBOSE_ALERTS

#ifdef VERBOSE_ALERTS
	#define verbose_alert(...) fprintf(stdout, __VA_ARGS__); fflush(stdout)
#endif

/*
	CEF alert constants
*/
#define DEV_PLC 1
#define DEV_RTU 2
#define DEV_IED 3
#define DEV_PMU 4
#define DEV_PDC 5

#define CEF_TOOL_IP "192.168.0.102"
#define CEF_DVC_HOST "rpi"
#define CEF_VERSION 0
#define CEF_TOOL_ID 5
#define CEF_DEVICE_NUM DEV_PLC
#define CEF_TOOL_VERSION 1
#define CEF_EVENT_ID 1
#define CEF_EVENT_NAME "Exploitation of memory corruption vulnerability"
#define CEF_SEVERITY_LEVEL 7

// Constructor and Destructor prototypes
void __attribute__ ((constructor)) on_load(void);
void __attribute__ ((destructor)) on_unload(void);

/*
	ARM specific types and constants
*/
typedef uint8_t  arm_regindex;
typedef uint32_t arm_memword;
typedef uint32_t arm_addr;
typedef uint32_t arm_ins;
typedef uint16_t thumb_ins;

#define ARM_POINTER_SIZE (sizeof(arm_memword))
#define ARM_INSTRUCTION_SIZE (sizeof(arm_ins))
#define THUMB_INSTRUCTION_SIZE (sizeof(thumb_ins))

#include "protect_config.h"

#define MAX_ALLOC_DISTANCE 0xF42400

/* --------------------------------------------------------
					CONFIGURATION END
   				DO NOT EDIT BELOW THIS LINE
   -------------------------------------------------------- */

// Alert types
#define MISC_ALERT 1
#define SHADOWSTACK_ALERT 2
#define CPTRCALL_ALERT 3

#define alert_log(...) FILE* log_file_ptr = fopen(ALERT_LOG_FILE, "a+"); fprintf(log_file_ptr, __VA_ARGS__); fflush(log_file_ptr); fclose(log_file_ptr)

/*
	Globally useful addresses
*/

// Address of the main program image's base
void* PROG_image_base_address;
// Start/End eddresses of the main program image's code section
void* PROG_code_section_start_address;
void* PROG_code_section_end_address;
// Address of the main program's entrypoint
void* PROG_entry_point;
// Address of the main program's main() routine
void* PROG_main_address;
// Original entrypoint instruction
arm_ins PROG_orig_entry_ins;
// Stack cookie storage address in .bss segment
void* PROG_stackcookie_address;

// Shadowstack bottom
void* PROG_shadow_stack_bottom;
// Shadowstack top
void* PROG_shadow_stack_top;
// Shadow stack offset
arm_addr PROG_shadow_stack_offset;

/*
	Handler templates
*/

arm_ins prologue_template[] = {
	0xe52d0004,  // push {r0} 					(save scratch register)

	0xe59f0018,  // ldr r0, [pc, #24] 			(load shadow stack offset holder)	
	0xe5900000,  // ldr r0, [r0] 				(dereference pointer to get offset value)
	0xe04d0000,  // sub r0, sp, r0 				(subtract offset from stackpointer to get shadowstack)
	0xe2800004,  // add	r0, r0, #4 				(account for scratch register saving)	
		
	0xe580e000,  // str	lr, [r0] 				(store shadow returnaddress)

	0xe49d0004,  // pop	{r0} 					(restore scratch register)

	0x00000000,  // orig. instruction 			(execute original prologue instruction)
	0xe59ff000,  // ldr	pc, [pc] 				(branch back to prologue)

	0x00000000,  // *shadow stack offset holder
	0x00000000   // *prologue return point address
};

arm_ins epilogue_template[] = {

	0xe1a00000,  // mod. orig. instruction 		(execute modified original instruction)

	0xe92d0003,  // push {r0, r1} 				(save scratch register and dummy spot on the stack)

	0xe59f0030,  // ldr r0, [pc, #48] 			(load shadow stack offset holder)
	0xe5900000,  // ldr r0, [r0] 				(dereference pointer to get offset value)
	0xe04d0000,  // sub r0, sp, r0 				(subtract offset from stackpointer to get shadowstack)
	0xe280000c,  // add r0, r0, #12				(account for scratch register saving and unpopped PC register)
	0xe5900000,  // ldr r0, [r0] 				(get shadow return address)
		
	0xe59d1008,  // ldr r1, [sp, #8] 			(load actual return address)
	0xe1500001,  // cmp r0, r1 					(compare shadow and actual)
	0x1a000000,  // bne raise_alert 			(if mismatch, raise alert)

	0xe8bd8003,  // pop {r0, r1, pc} 			(restore scratch registers and branch to shadow return address)

	// raise_alert:
	0xe92d5fff,  // push {r0-r12, lr} 			(save program state)
	0xe59f200c,  // ldr r2, [pc, #12] 			(load address of alert routine)
	0xe12fff32,  // blx r2 						(call alert routine, r0 = shadow return, r1 = actual return)
	0xe8bd5fff,  // pop {r0-r12, lr} 			(restore program state)
	0xe8bd8003,  // pop {r0, r1, pc} 		    (restore scratch registers and branch to shadow return address)

	0x00000000,  // *shadow stack offset holder
	0x00000000   // *alert routine address
	};

arm_ins cptrcall_template[] = {
	0xe92d5fff,  // push {r0-r12, lr} 			(save program state)

	0xe1a00000,  // set r0 to dst reg 			(set r0 to dst reg)
	0xe59f100c,  // ldr r1, [pc, #12] 			(load address of checking routine)
	0xe12fff31,  // blx r1 						(call checking routine)

	0xe8bd5fff,  // pop {r0-r12, lr} 			(restore program state)
	0xe59fe004,  // ldr lr, [pc, #4] 			(set lr)
	0xe1a00000,  // orig. instruction 			(execute original instruction)

	0x00000000,  // *checking routine address
	0x00000000   // *lr value
};

arm_ins shadow_template[] = {
	0xe92d5fff,  // push {r0-r12, lr} 			(save program state)
	0xe1a0000d,  // mov r0, sp 					(current stackpointer value)
	0xe59f1008,  // ldr r1, [pc, #8] 			(load address of handler)
	0xe12fff31,  // blx r1 						(call handler)
	0xe8bd5fff,  // pop {r0-r12, lr} 			(restore program state)
	0xe59ff000,  // ldr pc, [pc] 				(branch back to entry point)

	0x00000000,  // *shadowstack setup handler address
	0x00000000   // *entrypoint address
};

/*
	Handler offsets
*/
#define PROLOGUE_HANDLER_ORIG_INS_OFFSET 7
#define PROLOGUE_HANDLER_SHDW_STACK_OFFSET 9
#define PROLOGUE_HANDLER_GOBACK_ADDR_OFFSET 10

#define EPILOGUE_HANDLER_MOD_INS_OFFSET 0
#define EPILOGUE_HANDLER_SHDW_STACK_OFFSET 16
#define EPILOGUE_HANDLER_ALERT_ADDR_OFFSET 17

#define CPTRCALL_HANDLER_R0_SETTER_OFFSET 1
#define CPTRCALL_HANDLER_ORIG_INS_OFFSET 6
#define CPTRCALL_HANDLER_CHECK_ADDR_OFFSET 7
#define CPTRCALL_HANDLER_LR_VALUE_OFFSET 8

#define SHADOW_TRAMPOLINE_HANDLER_OFFSET 6
#define SHADOW_TRAMPOLINE_ENTRYPOINT_OFFSET 7

/*
	Handler sizes
*/

#define PROLOGUE_HANDLER_SIZE (sizeof(prologue_template))
#define EPILOGUE_HANDLER_SIZE (sizeof(epilogue_template))
#define CPTRCALL_HANDLER_SIZE (sizeof(cptrcall_template))
#define SHADOW_TRAMPOLINE_SIZE (sizeof(shadow_template))

/*
	Handler memory area pointers
*/
void* trampoline_area;
size_t trampoline_size;

void* PROLOGUE_HANDLERs;
void* EPILOGUE_HANDLERs;
void* CPTRCALL_HANDLERs;
void* SHADOW_TRAMPOLINE;

/*
	Instruction rewriting routines
*/

// Epilogue instruction types
#define INS_UNKNOWN 0
#define INS_LDM_SP_PC 1

// Instruction decoding, modification and parsing masks and values

/*
	Instructions of the type
		LDM<FD/FA/ED/EA> SP!, {..., PC}

Block Data Transfer instruction format:
	[Cond 31..28] [100 27..25] [P U S W L 24..20] [Rn 19..16] [Register list 15..00]

	L (20): 0 = store to memory, 1 = load from memory
	Register list: each bit in 16-bit register list corresponds to a register

	Mask checks whether bits 27..25 are 100, bit 20 is 1, Rn is 1101 (R13/SP) and register list bit 15 (R15/PC) is 1

	Type Mask:  00001110000111111000000000000000
	Type Value: 00001000000111011000000000000000
	Mod Mask:   11111111111111110111111111111111

*/

#define ARM_LDM_SP_PC_TYPE_MASK 0xE1F8000
#define ARM_LDM_SP_PC_TYPE_VALUE 0x81D8000
#define ARM_LDM_SP_PC_MOD_MASK 0xFFFF7FFF

#define ARM_INS_MOV 0xE1A00000
#define ARM_INS_BLX 0x012fff30
#define ARM_INDIRECT_BRANCH_REGARG_MASK 0xF

/*
Single Data Transfer instruction format:
	[Cond 31..28] [01 27..26] [I P U B W L 25..20] [Rn 19..16] [Rd 15..12] [Offset 11..0]

	L (20): 0 = store to memory, 1 = load from memory

	STR Ry, [...]
		Mask checks whether bits 27..26 are 01, bit 20 is 0 and Rd = Ry

		Mask
			00001100000100001111000000000000
		Value
			00000100000000000000000000000000 | (Ry << 12)

	LDR Ry, [Rx]
		Mask checks whether bits 27..26 are 01, bit 25 is 0, bit 20 is 1, Rn = Rx and Offset is all-zero

		Mask
			00001110000111110000111111111111

		Value
			00000100000100000000000000000000 | (Rx << 16)

		Ry extract
			00000000000000001111000000000000 >> 12

	LDR Rx, [PC, #...]
		Mask checks whether bits 27..26 are 01, bit 25 is 0, bit 20 is 1 and Rn = R15 (PC)

		Mask
			00001110000111110000000000000000

		Value
			00000100000111110000000000000000

		Rx extract
			00000000000000001111000000000000 >> 12

		Offset extract
			111111111111

	LDR PC, ...
		Mask checks whether bits 27..26 are 01, bit 20 is 1 and Rd = R15 (PC)

		Mask
			00001100000100001111000000000000

		Value
			00000100000100001111000000000000
	

Block Data Transfer instruction format:
	[Cond 31..28] [100 27..25] [P U S W L 24..20] [Rn 19..16] [Register list 15..00]

	L (20): 0 = store to memory, 1 = load from memory
	Register list: each bit in 16-bit register list corresponds to a register

	LDM.. ..., {..., PC}
		Mask checks whether bits 27..25 are 100, bit 20 is 1 and register list bit 15 (R15 = PC) is 1

		Mask
			00001110000100001000000000000000

		Value
			00001000000100001000000000000000


Branch(-with-Link)-and-Exchange (indirect) instruction format:
	[Cond 31..28] [0001 27..24] [0010 23..20] [1111 19..16] [1111 15..12] [1111 11..8] [0001 7..4] [Rn 3..0]

	B(L)X Rx
		Mask check full range of bits 27..4	

		Mask
			00001111111111111111111111110000

		Value
			00000001001011111111111100010000


Branch / Branch-with-Link(-and-Exchange) (direct) instruction format:
	[Cond 31..28] [101 27..25] [L 24] [offset 23..0]

	L (24): 0 = branch, 1 = branch-with-link

	B(LX) label
		Mask checks whether bits 27..25 are 101

		Mask
			00001110000000000000000000000000

		Value
			00001010000000000000000000000000



*/
#define ARM_STR_RY_MASK 0xC10F000
#define ARM_INS_STR_RY(ry) (arm_ins)(0x4000000 | (ry << 12))

#define ARM_LDR_RY_RX_MASK 0xE1F0FFF
#define ARM_LDR_RY_RX_EXTRACT_RY(ins) (arm_regindex)((ins & 0xF000) >> 12)
#define ARM_INS_LDR_RY_RX(rx) (arm_ins)(0x4100000 | (rx << 16))

#define ARM_LDR_RX_PC_MASK 0xE1F0000
#define ARM_INS_LDR_RX_PC 0x41F0000
#define ARM_LDR_RX_PC_EXTRACT_RX(ins) (arm_regindex)((ins & 0xF000) >> 12)
#define ARM_LDR_RX_PC_EXTRACT_OFFSET(ins) (arm_addr)(ins & 0xFFF)

#define ARM_LDR_PC_MASK 0xC10F000
#define ARM_INS_LDR_PC 0x410F000

#define ARM_LDM_PC_MASK 0xE108000
#define ARM_INS_LDM_PC 0x8108000

#define ARM_DATA_PC_MASK 0xC00F000
#define ARM_INS_DATA_PC 0xF000

#define ARM_INDIRECT_BRANCH_MASK 0xFFFFFF0
#define ARM_INS_INDIRECT_BRANCH 0x12FFF10

#define ARM_DIRECT_BRANCH_MASK 0xE000000
#define ARM_INS_DIRECT_BRANCH 0xA000000

int decode_epilogue_ins_type(arm_ins orig_ins)
{
	if ((orig_ins & ARM_LDM_SP_PC_TYPE_MASK) == ARM_LDM_SP_PC_TYPE_VALUE)
	{
		return INS_LDM_SP_PC;
	}

	return INS_UNKNOWN;
}

// Rewrite original epilogue instruction to omit branching part
void rewrite_orig_epilogue_ins(arm_ins* handler_addr, arm_addr orig_addr)
{
	arm_ins orig_ins = *(arm_ins*)(orig_addr);

	int ins_type = decode_epilogue_ins_type(orig_ins);
	switch (ins_type)
	{
		// pop {..., pc}
		case INS_LDM_SP_PC:
		{
			/*
				We rewrite this instruction by zero'ing the R15/PC bit so that the PC doesn't get set by it
			*/
			handler_addr[EPILOGUE_HANDLER_MOD_INS_OFFSET] = (arm_ins)(orig_ins & ARM_LDM_SP_PC_MOD_MASK);

			return;
		}break;

		// If we can't properly decode the instruction we can't rewrite it and hence not hook the epilogue, terminate shield
		default:
		{
			#ifdef DEBUG_MODE
				debug_log("[-] rewrite_orig_epilogue_ins: instruction 0x%x at 0x%x has invalid type %x\n", orig_ins, orig_addr, ins_type);
			#endif
		}break;
	}

	#ifdef DEBUG_MODE
		debug_log("[-] rewrite_orig_epilogue_ins: cannot recover from error, terminating...\n");
	#endif

	exit(-1);
	return;
}

arm_ins craft_regsetter(int dst_reg, arm_ins orig_ins)
{
	// Confirm orig_ins is of type BLX rx
	if ((orig_ins & ARM_INDIRECT_BRANCH_MASK) != ARM_INS_BLX)
	{
		return (arm_ins)0;
	}

	// Extract rx from orig_ins as src_reg and craft mov dst_reg, src_reg
	return (arm_ins)(ARM_INS_MOV | (dst_reg << 12) | (orig_ins & ARM_INDIRECT_BRANCH_REGARG_MASK));
}

#define ARM_BLX_LINKBIT_ZERO_MASK 0xFFFFFFDF

arm_ins rewrite_blx_to_bx_arm(arm_ins orig_ins)
{
	// Zero out link-bit in instruction
	return (orig_ins & ARM_BLX_LINKBIT_ZERO_MASK);
}

/*
	Handler functions
*/
void raise_alert_handler(int alert_code, void* target_address, void* shadow_return)
{
	#ifndef SUPPRESS_ALERTS
		char* msgs[] = {"SECURITY_OK (should never occur)", "Unspecified (misc.)", "Shadow-stack mismatch (backward-edge violation)", "Invalid codepointer call destination address (forward-edge violation)"};

  		// Cannot use eg. localtime or gmtime due to getenv problems since we're called from within LD_PRELOADed lib
  		// and localtime/gmtime/ctime etc. seem to segfault (probably due to them being called in corrupted context)
  		// so currently we just supply raw timestamp

		time_t rawtime;
  		time(&rawtime);
		pid_t app_pid = getpid();

		if (alert_code == SHADOWSTACK_ALERT)
		{
			alert_log("[!] ..:: [uShield RPM ALERT] ::..\n[!] [%ld %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s return-address %p, expected %p]\n", rawtime, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, app_pid, APP_NAME, DETECT_MEASURE, msgs[alert_code], target_address, shadow_return);

			#ifdef DEBUG_MODE
				debug_log("[!] ..:: [uShield RPM ALERT] ::..\n[!] [%ld %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s return-address %p, expected %p]\n", rawtime, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, app_pid, APP_NAME, DETECT_MEASURE, msgs[alert_code], target_address, shadow_return);
			#else
				#ifdef VERBOSE_ALERTS
					verbose_alert("[!] ..:: [uShield RPM ALERT] ::..\n[!] [%ld %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s return-address %p, expected %p]\n", rawtime, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, app_pid, APP_NAME, DETECT_MEASURE, msgs[alert_code], target_address, shadow_return);
				#endif
			#endif

		}
		else if (alert_code == CPTRCALL_ALERT)
		{
			alert_log("[!] ..:: [uShield RPM ALERT] ::..\n[!] [%ld %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s codepointer %p]\n", rawtime, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, app_pid, APP_NAME, DETECT_MEASURE, msgs[alert_code], target_address);

			#ifdef DEBUG_MODE
				debug_log("[!] ..:: [uShield RPM ALERT] ::..\n[!] [%ld %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s codepointer %p]\n", rawtime, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, app_pid, APP_NAME, DETECT_MEASURE, msgs[alert_code], target_address);
			#else
				#ifdef VERBOSE_ALERTS
					verbose_alert("[!] ..:: [uShield RPM ALERT] ::..\n[!] [%ld %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s codepointer %p]\n", rawtime, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, app_pid, APP_NAME, DETECT_MEASURE, msgs[alert_code], target_address);
				#endif
			#endif
		}
		else
		{
			alert_log("[!] ..:: [uShield RPM ALERT] ::..\n[!] [%ld %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s]\n", rawtime, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, app_pid, APP_NAME, DETECT_MEASURE, msgs[alert_code]);

			#ifdef DEBUG_MODE
				debug_log("[!] ..:: [uShield RPM ALERT] ::..\n[!] [%ld %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s]\n", rawtime, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, app_pid, APP_NAME, DETECT_MEASURE, msgs[alert_code]);
			#else
				#ifdef VERBOSE_ALERTS
					verbose_alert("[!] ..:: [uShield RPM ALERT] ::..\n[!] [%ld %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s]\n", rawtime, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, app_pid, APP_NAME, DETECT_MEASURE, msgs[alert_code]);
				#endif
			#endif
		}
	#endif

	if (!strcmp(DETECT_MEASURE, MEASURE_LOG))
	{
		#ifdef DEBUG_MODE
			debug_log("[!] raise_alert_handler: MEASURE_LOG activated!\n");
		#endif
	}
	else if (!strcmp(DETECT_MEASURE, MEASURE_KILL))
	{
		#ifdef DEBUG_MODE
			debug_log("[!] raise_alert_handler: MEASURE_KILL activated!\n");
		#endif

		exit(-1);
	}
	else if (!strcmp(DETECT_MEASURE, MEASURE_RESTART))
	{
		#ifdef DEBUG_MODE
			debug_log("[-] raise_alert_handler: MEASURE_RESTART not implemented yet ...\n");
		#endif
	}
	return;
}

/*
	Raise shadow-stack violation alert
*/
void raise_shadow_stack_alert()
{
	void* shadow_return, *actual_return;

	asm volatile("mov %0, r0\n\t"
				 "mov %1, r1"
				 : "=r" (shadow_return), "=r" (actual_return)
				);

	#ifdef DEBUG_MODE_VERBOSE
		debug_log("[DEBUG] raise_shadow_stack_alert: Shadowstack mismatch detected: shadow [%p], actual [%p]\n", shadow_return, actual_return);
	#endif

	raise_alert_handler(SHADOWSTACK_ALERT, actual_return, shadow_return);
	return;
}

/*
	Validation routines
*/

/*
	Checks whether instruction at address is of form LDR rx, [pc, #...] and extracts pc-offset and rx
*/
arm_addr get_stackcookie_address(arm_addr instruction_address, arm_regindex* rx)
{
	arm_ins instruction = *(arm_ins*)(instruction_address);

	// Confirm instruction is of the form ldr rx, [pc, #...]
	if ((instruction & ARM_LDR_RX_PC_MASK) != ARM_INS_LDR_RX_PC)
	{
		return (arm_addr)0;
	}

	*rx = ARM_LDR_RX_PC_EXTRACT_RX(instruction);

	// Extract offset to pc from instruction and add to instruction address to obtain candidate storage address for stack cookie address
	// Load candidate stack cookie address from this candidate address
	return *(arm_addr*)((instruction_address + (arm_addr)(ARM_LDR_RX_PC_EXTRACT_OFFSET(instruction)) + (2 * ARM_POINTER_SIZE)));
}

/*
	Checks whether instruction at address is of form LDR ry, [rx] and extracts ry
*/
int is_ldr_ry_rx(arm_addr instruction_address, arm_regindex rx, arm_regindex* ry)
{
	arm_ins instruction = (*(arm_ins*)(instruction_address));

	if ((instruction & ARM_LDR_RY_RX_MASK) == ARM_INS_LDR_RY_RX(rx))
	{
		*ry = ARM_LDR_RY_RX_EXTRACT_RY(instruction);
		return 1;
	}
	else
	{
		return 0;
	}
}

/*
	Checks whether instruction at given address is branch of any kind.

	We consider something a branch iff:
		* It is an indirect branching instruction: B(LX) Rx (we have to allow for direct branches because of instrumentation code)
		* It is a data transfer instruction (single or block) with the PC as its destination address
		* It is a data processing instruction with the PC as its destination address

*/
int is_branch_ARM(arm_addr instruction_address)
{
	arm_ins instruction = (*(arm_ins*)(instruction_address));

	// Check for B(LX) Rx
	if ((instruction & ARM_INDIRECT_BRANCH_MASK) == ARM_INS_INDIRECT_BRANCH)
	{
		return 1;
	}

	// Check for LDR PC, ...
	if ((instruction & ARM_LDR_PC_MASK) == ARM_INS_LDR_PC)
	{
		return 1;
	}

	// Check for LDM ..., {..., PC}
	if ((instruction & ARM_LDM_PC_MASK) == ARM_INS_LDM_PC)
	{
		return 1;
	}

	// Check for data processing with PC as dst
	if ((instruction & ARM_DATA_PC_MASK) == ARM_INS_DATA_PC)
	{
		return 1;
	}

	return 0;
}


/*
	Validate codepointer call destination address

	The heuristic checks whether it finds, within a certain threshold value, the following sequence
		* LDR Rx, [PC, #...]
		* ...;
		* LDR Ry, [Rx]
		* ...;
		* STR Ry, [...]

	If it does, it extracts the corresponding stackcookie storage address and checks it against the one identified during startup.
	If it does not, or the addresses don't match, an alert is raised as the heuristic is violated.

	If we encounter a branch of any kind (ie. a branching instruction or data instruction that has the PC as a dst register) before the
	heuristic is validated we consider the heuristic violated in order to prevent attackers from targeting gadgets residing just before a valid
	function prologue that would otherwise validate the gadget during a linear downward scan. Since any gadget has to terminate in a branch
	we thus restrict attackers here to targeting valid function starts only.

	Note that due to the structure of the routine we only do the bulk of the look-ahead checking if the rare condition of a match
	between addresses has been already confirmed (which itself takes only a few instructions during the linear forward scan of the prologue)

*/
void check_cptr_call()
{
	void* dst_address;
	arm_addr scan_addr1, scan_addr2, scan_addr3, cookie_upper_bound;
	arm_regindex rx, ry;

	asm volatile("mov %0, r0"
				 : "=r" (dst_address)
				);

	cookie_upper_bound = (arm_addr)(dst_address + (CPTR_PROLOGUE_COOKIE_THRESHOLD * ARM_POINTER_SIZE));

	#ifdef DEBUG_MODE_VERBOSE2
		debug_log("[DEBUG+] check_cptr_call: validating codepointer call to address %p, scanning in range [%p - 0x%x]\n", dst_address, dst_address, cookie_upper_bound);
	#endif

	// Bounded lookahead for LDR rx, =__stack_chk_guard
	for (scan_addr1 = (arm_addr)(dst_address); scan_addr1 < cookie_upper_bound; scan_addr1 += ARM_POINTER_SIZE)
	{
		if (is_branch_ARM(scan_addr1))
		{
			#ifdef DEBUG_MODE_VERBOSE2
				debug_log("[DEBUG+] check_cptr_call: encountered illegal branch at 0x%x\n", scan_addr1);
			#endif

			goto NOT_VALIDATED;
		}

		// Validate instruction is LDR rx, =__stack_chk_guard
		if (get_stackcookie_address(scan_addr1, &rx) != (arm_addr)PROG_stackcookie_address)
		{
			// No LDR rx, =__stack_chk_guard found, continue scanning
			continue;
		}

		#ifdef DEBUG_MODE_VERBOSE2
			debug_log("[DEBUG+] check_cptr_call: found LDR R%d, [PC, #...] heuristic marker at 0x%x\n", rx, scan_addr1);
			debug_log("[DEBUG+] check_cptr_call: validated with stackcookie storage address at %p\n", PROG_stackcookie_address);
		#endif

		// Bounded lookahead for LDR ry, [rx]
		for (scan_addr2 = (scan_addr1 + ARM_POINTER_SIZE); scan_addr2 < cookie_upper_bound; scan_addr2 += ARM_POINTER_SIZE)
		{
			if (is_branch_ARM(scan_addr2))
			{
				#ifdef DEBUG_MODE_VERBOSE2
					debug_log("[DEBUG+] check_cptr_call: encountered illegal branch at 0x%x\n", scan_addr2);
				#endif

				goto NOT_VALIDATED;
			}

			if (is_ldr_ry_rx(scan_addr2, rx, &ry))
			{

				#ifdef DEBUG_MODE_VERBOSE2
					debug_log("[DEBUG+] check_cptr_call: found LDR R%d, [R%d] heuristic marker at 0x%x\n", ry, rx, scan_addr2);
				#endif

				// Bounded lookahead for STR ry, [...]
				for (scan_addr3 = (scan_addr2 + ARM_POINTER_SIZE); scan_addr3 < cookie_upper_bound; scan_addr3 += ARM_POINTER_SIZE)
				{
					if (is_branch_ARM(scan_addr3))
					{
						#ifdef DEBUG_MODE_VERBOSE2
							debug_log("[DEBUG+] check_cptr_call: encountered illegal branch at 0x%x\n", scan_addr3);
						#endif

						goto NOT_VALIDATED;
					}

					if (((*(arm_ins*)(scan_addr3)) & ARM_STR_RY_MASK) == ARM_INS_STR_RY(ry))
					{

						#ifdef DEBUG_MODE_VERBOSE2
							debug_log("[DEBUG+] check_cptr_call: found STR R%d, [...] heuristic marker at 0x%x\n", ry, scan_addr3);
						#endif

						// Found valid stackcookie setup within prologue threshold bounds, valid dst address
						return;
					}
				}

				// No STR ry, [...] found anywhere while we did find LDR rx, =__stack_chk_guard; LDR ry, [rx]. Raise alert.
				goto NOT_VALIDATED;
			}
		}

		// No LDR ry, [rx] found anywhere while we did find LDR rx, =__stack_chk_guard. Raise alert.
		goto NOT_VALIDATED;
	}

NOT_VALIDATED:
	// Couldn't find valid stackcookie setup within bounds, raise alert
	raise_alert_handler(CPTRCALL_ALERT, dst_address, (void*)NULL);
	return;
}

/*
	Handler construction routines
*/

void build_PROLOGUE_HANDLER(void* handler_addr, arm_addr prologue_addr)
{
	memcpy(handler_addr, (void*)prologue_template, PROLOGUE_HANDLER_SIZE);

	// Store original instruction within prologue handler
	((arm_ins*)handler_addr)[PROLOGUE_HANDLER_ORIG_INS_OFFSET] = *(arm_ins*)(prologue_addr);

	// Store shadow stack offset holder within prologue handler (note: this code requires sizeof(arm_addr) == sizeof(arm_ins))
	((arm_addr*)handler_addr)[PROLOGUE_HANDLER_SHDW_STACK_OFFSET] = (arm_addr)(&PROG_shadow_stack_offset);
		
	// Store prologue return point address within prologue handler (note: this code requires sizeof(arm_addr) == sizeof(arm_ins))
	((arm_addr*)handler_addr)[PROLOGUE_HANDLER_GOBACK_ADDR_OFFSET] = (arm_addr)(prologue_addr + ARM_INSTRUCTION_SIZE);

	return;
}

void build_EPILOGUE_HANDLER(void* handler_addr, arm_addr epilogue_addr)
{
	memcpy(handler_addr, (void*)epilogue_template, EPILOGUE_HANDLER_SIZE);

	// Store modified original instruction within epilogue handler
	rewrite_orig_epilogue_ins(((arm_ins*)handler_addr), epilogue_addr);

	// Store shadow stack offset holder within epilogue handler (note: this code requires sizeof(arm_addr) == sizeof(arm_ins))
	((arm_addr*)handler_addr)[EPILOGUE_HANDLER_SHDW_STACK_OFFSET] = (arm_addr)(&PROG_shadow_stack_offset);

	// Store alert routine address within epilogue handler (note: this code requires sizeof(arm_addr) == sizeof(arm_ins))
	((arm_addr*)handler_addr)[EPILOGUE_HANDLER_ALERT_ADDR_OFFSET] = (arm_addr)(raise_shadow_stack_alert);

	return;
}

void build_CPTRCALL_HANDLER(void* handler_addr, arm_addr cptrcall_addr)
{
	memcpy(handler_addr, (void*)cptrcall_template, CPTRCALL_HANDLER_SIZE);

	arm_ins orig_ins = *(arm_ins*)(cptrcall_addr);
	arm_ins regset_ins = craft_regsetter(0, orig_ins);

	if (regset_ins == (arm_ins)0)
	{
		#ifdef DEBUG_MODE
			debug_log("[-] build_CPTRCALL_HANDLER: Invalid instruction %x at address %x, could not craft regsetter, exiting...\n", orig_ins, cptrcall_addr);
		#endif

		exit(-1);
	}

	// Set r0 to dst register within cptrcall handler
	((arm_ins*)handler_addr)[CPTRCALL_HANDLER_R0_SETTER_OFFSET] = regset_ins;

	// Store original instruction within cptrcall handler
	((arm_ins*)handler_addr)[CPTRCALL_HANDLER_ORIG_INS_OFFSET] = rewrite_blx_to_bx_arm(orig_ins);

	// Store checking function address within cptrcall handler (note: this code requires sizeof(arm_addr) == sizeof(arm_ins))
	((arm_addr*)handler_addr)[CPTRCALL_HANDLER_CHECK_ADDR_OFFSET] = (arm_addr)(check_cptr_call);

	// Store lr value within cptrcall handler (note: this code requires sizeof(arm_addr) == sizeof(arm_ins))
	((arm_addr*)handler_addr)[CPTRCALL_HANDLER_LR_VALUE_OFFSET] = (arm_addr)(cptrcall_addr + 4);

	return;
}

void build_SHADOW_TRAMPOLINE(void* trampoline_addr, arm_addr handler_addr, arm_addr entrypoint_addr)
{
	memcpy(trampoline_addr, (void*)shadow_template, SHADOW_TRAMPOLINE_SIZE);
	((arm_ins*)trampoline_addr)[SHADOW_TRAMPOLINE_HANDLER_OFFSET] = handler_addr;
	((arm_ins*)trampoline_addr)[SHADOW_TRAMPOLINE_ENTRYPOINT_OFFSET] = entrypoint_addr;
	return;
}

/*
	Memory allocation, protection and management routines
*/
int page_protect(void* addr, size_t min_size, int flags)
{
    // Constant holding the page size value
    size_t page_size = sysconf(_SC_PAGE_SIZE);

    if(page_size < min_size)
    {
    	page_size = min_size;
    }

    // Calculate relative page offset
    size_t temp = (size_t)addr;
    temp -= temp % page_size;

    // Update address
    addr = (void*)temp;

    // Update memory area protection
    return mprotect(addr, page_size, flags);
}

/*
	Allocates a block of memory at closest possible distance to a given address

	Params:
		area_address = base address of area near where we want to allocate
		scan_length = length (in bytes) of area in which we want to allocate
		alloc_len = length (in bytes) of area we want to allocate

	Return:
		Returns NULL upon failure.
		Upon success returns address of free memory of at least size alloc_len within scan_length distance of area_address.

*/
void* alloc_closest_free_area(void* area_address, size_t min_distance, size_t max_distance, size_t alloc_len, int area_prots)
{
	size_t i;
	// Counter for free pages
	size_t consec_free_page_ctr = 0;
	// Start index of consecutive free pages
	size_t start_page_index = 0;
	// boolean indicating scan success
	int found_area = 0;
	// System page size
	size_t page_size = sysconf(_SC_PAGE_SIZE);
	// Number of pages to scan
	size_t scan_len = (size_t)((max_distance + (page_size - 1))/page_size);
	// Number of consecutive free pages required for alloc_len
	size_t consec_pages = (size_t)((alloc_len + (page_size - 1))/page_size);
	// Scan on a page-by-page basis so use a single-page sized vector (ie. 1 byte)
	unsigned char vec;
	// Pointers
	void* scan_ptr, *start_address, *alloc_address;

	if(max_distance < min_distance)
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] alloc_closest_free_area: max distance smaller than min distance\n");
		#endif
		return NULL;
	}

	if((max_distance - min_distance) < alloc_len)
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] alloc_closest_free_area: max distance minus min distance too small to accomodate area\n");
		#endif
		return NULL;
	}

	scan_ptr = (void*)(area_address + min_distance);

	for(i = 0; i < scan_len; i++)
	{
		// If mincore fails with errno == ENOMEM we are dealing with an unmapped page
		if(mincore(scan_ptr, page_size, &vec) != 0)
		{
			if(errno == ENOMEM)
			{
				if(start_page_index == 0)
				{
					start_page_index = i;
				}

				consec_free_page_ctr++;

				// We have enough consecutive free pages
				if(consec_free_page_ctr >= consec_pages)
				{
					found_area = 1;
					break;
				}
			}
			else
			{
				// if we find a non-free page reset consec counter
				consec_free_page_ctr = 0;
				start_page_index = 0;
			}
		}
		else
		{
			// if we find a non-free page reset consec counter
			consec_free_page_ctr = 0;
			start_page_index = 0;
		}

		scan_ptr += page_size;
	}

	if(found_area)
	{
		start_address = (void*)(area_address + (page_size * start_page_index));

		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] alloc_closest_free_area: Found free area of %d pages in-range starting at address [%p]\n", consec_pages, start_address);
		#endif

		alloc_address = mmap(start_address, alloc_len, area_prots, MAP_FIXED|MAP_SHARED|MAP_ANONYMOUS, -1, 0);

		if((alloc_address == MAP_FAILED) || (alloc_address != start_address))
		{
			#ifdef DEBUG_MODE_VERBOSE
				debug_log("[DEBUG] alloc_closest_free_area: mmap failed to allocate properly\n");
			#endif
			return NULL;
		}
		else
		{
			return alloc_address;
		}
	}
	else
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] alloc_closest_free_area: Could not find free area of %d pages within acceptable range\n", consec_pages);
		#endif
		return NULL;
	}
}

/*
	ELF image processing code
*/
Elf32_Phdr** get_elf_program_headers(void* base_address, Elf32_Ehdr* elf_header)
{	
	int i;
	void* rptr;

	//Create an array of program headers using malloc
	Elf32_Phdr** elf_header_list = (Elf32_Phdr**)malloc(sizeof(Elf32_Phdr*) * elf_header->e_phnum);
	
	//allocate memory for each individual program header.
	for(i = 0; i<elf_header->e_phnum; i++)
	{
		elf_header_list[i] = (Elf32_Phdr*)malloc(elf_header->e_phentsize);
	}

	rptr = (void*)(base_address + elf_header->e_phoff);
	
	//copy the data from our elf into the allocated memory.
	for(i = 0; i< elf_header->e_phnum; i++)
	{
		memcpy(elf_header_list[i], rptr, elf_header->e_phentsize);
		rptr += elf_header->e_phentsize;
	}

	return elf_header_list;
}

void free_header_list(void** listptr, int count)
{
	int i;

	if(!listptr)
		return;

	for(i = 0; i < count; i++)
	{
		if(listptr[i])
			free(listptr[i]);
	}

	free(listptr);
	return;
}

/*
	We identify the main() routine heuristically by starting at the program entrypoint and scanning for the sequence:

		* LDR Rx, =main
		  LDR Ry, =__libc_csu_init
		  BL __libc_start_main
		
	and extract the main() address from it.
*/

#define ARM_INS_LDR_R0_PC 0x41F0000
#define ARM_INS_LDR_R3_PC 0x41F3000

void* get_main_address(void* program_entry_point, void* code_end_address)
{
	void* scan_addr = program_entry_point;

	for (scan_addr = program_entry_point; scan_addr < code_end_address; scan_addr += ARM_POINTER_SIZE)
	{
		if ((((arm_ins)(*(arm_ins*)(scan_addr)) & ARM_LDR_RX_PC_MASK) == ARM_INS_LDR_RX_PC) && (((arm_ins)(*(arm_ins*)(scan_addr + ARM_POINTER_SIZE)) & ARM_LDR_RX_PC_MASK) == ARM_INS_LDR_RX_PC) && (((arm_ins)(*(arm_ins*)(scan_addr + (2 * ARM_POINTER_SIZE))) & ARM_DIRECT_BRANCH_MASK) == ARM_INS_DIRECT_BRANCH))
		{
			return (void*)(*(arm_addr*)(scan_addr + ARM_LDR_RX_PC_EXTRACT_OFFSET(*(arm_ins*)(scan_addr)) + (2 * ARM_POINTER_SIZE)));
		}
	}

	return (void*)NULL;
}

/*
	Extract program entrypoint, code segment start/end address, main() address and stackcookie storage address given ELF image base address
	Returns 0 upon success
*/
int parse_elf(void* base_address, void** code_start_address, void** code_end_address, void** program_entry_point, void** program_main_addr, void** stackcookie_address)
{
	int i;
	Elf32_Phdr** program_headers;
	Elf32_Ehdr* elf_header = (Elf32_Ehdr*)base_address;

	void* candidate_cookie_address;
	arm_addr scan_addr1, scan_addr2, scan_addr3, cookie_upper_bound;
	arm_regindex rx, ry;

	if(elf_header->e_ident[EI_CLASS] == ELFCLASS64)
	{
		// We only support 32-bit ELF executables on 32-bit platforms
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] get_code_start_address: ELF image is 64-bit, unsupported ...\n");
		#endif			
		return -1;
	}

	if(elf_header->e_ident[EI_DATA] != ELFDATA2LSB)
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] get_code_start_address: ELF image is non-little endian, unsupported ...\n");
		#endif
		return -1;
	}

	// Get program entrypoint
	*program_entry_point = (void*)elf_header->e_entry;

	#ifdef DEBUG_MODE_VERBOSE
		debug_log("[DEBUG] get_code_start_address: found program entrypoint [%p]\n", *program_entry_point);
	#endif

	/*
		Get .text (code) segment address from program headers
		NOTE: this is a bit hacky since it assumes the code section is the first executable/loadable section
		      which is usually the case but not per se. This suffices for the prototype though.
	*/		
	program_headers = get_elf_program_headers(base_address, elf_header);

	if(!program_headers)
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] get_code_start_address: error fetching program headers\n");
		#endif
		return -1;
	}

	for(i = 0; i < elf_header->e_phnum; i++)
	{
		if((program_headers[i]->p_type == PT_LOAD) && ((program_headers[i]->p_flags & (PF_R | PF_X)) != 0))
		{
			*code_start_address = (void*)program_headers[i]->p_vaddr;
			*code_end_address = (void*)(program_headers[i]->p_vaddr + program_headers[i]->p_filesz);
			break;
		}
	}

	#ifdef DEBUG_MODE_VERBOSE
		debug_log("[DEBUG] get_code_start_address: found code start and end addresses at %p - %p\n", *code_start_address, *code_end_address);
	#endif

	/*
		We don't want to rely on the existence of a symbol table for performing a __stack_chk_guard lookup
		so we use the following heuristic:
			* Knowing the application has been compiled with -fstack-protector-all we know that the main() routine will
			  have a stack cookie setup element within its prologue so we simply do a heuristic scan of the main() prologue
			  and extract the stack cookie storage address from there

			* The heuristic scan looks for LDR rx, [PC, #...]; ...; LDR ry, [rx]; ...; STR ry, [...] where the stackcookie address will be located in the .bss
			  segment
	*/

	candidate_cookie_address = (void*)NULL;
	*program_main_addr = get_main_address(*program_entry_point, *code_end_address);

	if (*program_main_addr == (void*)NULL)
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] get_code_start_address: error finding program main() address\n");
		#endif
		return -1;
	}

	#ifdef DEBUG_MODE_VERBOSE
		debug_log("[DEBUG] get_code_start_address: found program main() address [%p]\n", *program_main_addr);
	#endif

	cookie_upper_bound = (arm_addr)(*program_main_addr + (CPTR_PROLOGUE_COOKIE_THRESHOLD * ARM_POINTER_SIZE));

	#ifdef DEBUG_MODE_VERBOSE
		debug_log("[DEBUG] get_code_start_address: scanning for stackcookie storage address in range [0x%x - 0x%x]\n", (arm_addr)*program_entry_point, cookie_upper_bound);
	#endif

	// Bounded lookahead for LDR rx, =__stack_chk_guard
	for (scan_addr1 = (arm_addr)(*program_main_addr); scan_addr1 < cookie_upper_bound; scan_addr1 += ARM_POINTER_SIZE)
	{
		if (is_branch_ARM(scan_addr1))
		{
			goto MALFORMATTED_MAIN;
		}

		// Validate instruction is LDR rx, =__stack_chk_guard
		candidate_cookie_address = (void*)get_stackcookie_address(scan_addr1, &rx);

		if ((candidate_cookie_address == (void*)0))
		{
			// No LDR rx, =__stack_chk_guard candidate found, continue scanning
			continue;
		}

		#ifdef DEBUG_MODE_VERBOSE2
			debug_log("[DEBUG+] get_code_start_address: found LDR R%d, [PC, #...] heuristic marker at 0x%x\n", rx, scan_addr1);
			debug_log("[DEBUG+] get_code_start_address: found candidate stackcookie storage address at %p\n", candidate_cookie_address);
		#endif

		// Bounded lookahead for LDR ry, [rx]
		for (scan_addr2 = (scan_addr1 + ARM_POINTER_SIZE); scan_addr2 < cookie_upper_bound; scan_addr2 += ARM_POINTER_SIZE)
		{
			if (is_branch_ARM(scan_addr2))
			{
				goto MALFORMATTED_MAIN;
			}

			if (is_ldr_ry_rx(scan_addr2, rx, &ry))
			{
				#ifdef DEBUG_MODE_VERBOSE2
					debug_log("[DEBUG+] get_code_start_address: found LDR R%d, [R%d] heuristic marker at 0x%x\n", ry, rx, scan_addr2);
				#endif

				// Bounded lookahead for STR ry, [...]
				for (scan_addr3 = (scan_addr2 + ARM_POINTER_SIZE); scan_addr3 < cookie_upper_bound; scan_addr3 += ARM_POINTER_SIZE)
				{
					if (is_branch_ARM(scan_addr3))
					{
						goto MALFORMATTED_MAIN;
					}

					if (((*(arm_ins*)(scan_addr3)) & ARM_STR_RY_MASK) == ARM_INS_STR_RY(ry))
					{
						#ifdef DEBUG_MODE_VERBOSE2
							debug_log("[DEBUG+] get_code_start_address: found STR R%d, [...] heuristic marker at 0x%x\n", ry, scan_addr3);
						#endif

						// Found valid stackcookie setup within prologue threshold bounds, valid dst address
						goto COOKIE_LOOKAHEAD_DONE;
					}
				}
				// No STR ry, [...] found anywhere while we did find LDR rx, =__stack_chk_guard; LDR ry, [rx]. Raise alert.
				goto MALFORMATTED_MAIN;
			}
		}
		// No LDR ry, [rx] found anywhere while we did find LDR rx, =__stack_chk_guard. Raise alert.
		goto MALFORMATTED_MAIN;
	}

COOKIE_LOOKAHEAD_DONE:
	if ((candidate_cookie_address == (void*)0))
	{
		MALFORMATTED_MAIN:
			#ifdef DEBUG_MODE
				debug_log("[-] get_code_start_address: error finding stackcookie storage address, malformatted main() routine\n");
			#endif
			return -1;
	}
	else
	{
		*stackcookie_address = candidate_cookie_address;
	}

	#ifdef DEBUG_MODE_VERBOSE
		debug_log("[DEBUG] get_code_start_address: found stack cookie address [%p]\n", *stackcookie_address);
	#endif

	free_header_list((void**)program_headers, elf_header->e_phnum);
	return 0;
}

/*
	Handler routines
*/

/*
			- initialization handler takes current stack pointer and finds first memory address which satisfies:
				* is at specified minimum offset from SP
				* contains at least N consecutive bytes of free memory
				* note that the stack growns down, we can allocate after the stack so we can use a subtract offset to prevent collision alltogether

			- this area will serve as the shadow stack and we will mmap the shadowstack here
*/

void shadowstack_setup_handler()
{
	void* stack_pointer;

	asm volatile("mov %0, r0"
				 : "=r" (stack_pointer)
				);

	// Adjust stackpointer for register-saving operation
	stack_pointer += (14 * ARM_POINTER_SIZE);

	// Find adequate shadowstack area and map it
	PROG_shadow_stack_bottom = (void*)malloc(SHADOW_STACK_SIZE);

	if (PROG_shadow_stack_bottom == NULL)
	{
		#ifdef DEBUG_MODE
			debug_log("[-] shadowstack_setup_handler: could not allocate shadow stack, exiting...\n");
		#endif

		exit(-1);
	}

	// Shadowstack top (end of heap blob since stacks grow from top to bottom)
	PROG_shadow_stack_top = (void*)(PROG_shadow_stack_bottom + (SHADOW_STACK_SIZE - ARM_POINTER_SIZE));

	// Offset between regular and shadow stack (heap is usually below stack so subtract from SP)
	PROG_shadow_stack_offset = (arm_addr)(stack_pointer - PROG_shadow_stack_top);

	#ifdef DEBUG_MODE_VERBOSE	
		debug_log("[DEBUG] shadowstack_setup_handler: SP at %p\n", stack_pointer);
		debug_log("[DEBUG] shadowstack_setup_handler: allocated shadowstack (%d bytes) at [%p - %p], offset set to %x\n", SHADOW_STACK_SIZE, PROG_shadow_stack_bottom, PROG_shadow_stack_top, PROG_shadow_stack_offset);
	#endif
	
	// Restore original instruction to program entry point

	int old_prot = (PROT_READ | PROT_EXEC);

	// Make target memory writable
	if (page_protect((void*)PROG_entry_point, sizeof(arm_ins), old_prot | PROT_WRITE) != 0)
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] shadowstack_setup_handler: couldn't set +W page_protect on address %p, exiting...\n", (void*)PROG_entry_point);
		#endif

		exit(-1);
	}

	// Restore original instruction
	*((arm_ins*)PROG_entry_point) = PROG_orig_entry_ins;

	// Restore previous memory protections
	if (page_protect((void*)PROG_entry_point, sizeof(arm_ins), old_prot) != 0)
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] shadowstack_setup_handler: couldn't restore prior memory protections with page_protect on address %p, exiting...\n", (void*)PROG_entry_point);
		#endif
		
		exit(-1);
	}
	return;
}

/*
	Instrumentation routines
*/

int set_dispatcher(void* target_addr, arm_addr handler_addr)
{
	// Forward branch argument (will always be within 16MB range and hence within 24-bit bounds)
	arm_addr branch_forward_distance = (arm_addr)((handler_addr - (arm_addr)target_addr - 8) / 4);
	
	// Create direct branch instruction
	arm_ins dispatch_branch = (arm_ins)(0xea000000 | branch_forward_distance);
	
	int old_prot = (PROT_READ | PROT_EXEC);

	// Make target memory writable
	if (page_protect(target_addr, sizeof(arm_ins), old_prot | PROT_WRITE) != 0)
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] set_dispatcher: couldn't set +W page_protect on address %p\n", target_addr);
		#endif
		return -1;
	}

	// Overwrite address with dispatching branch
	*((arm_ins*)target_addr) = dispatch_branch;

	// Restore previous memory protections
	if (page_protect(target_addr, sizeof(arm_ins), old_prot) != 0)
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] set_dispatcher: couldn't restore prior memory protections with page_protect on address %p\n", target_addr);
		#endif
		return -1;
	}

	return 0;
}

int instrument_prologues(void* image_base_address)
{
	int i;
	arm_addr prologue_addr;
	arm_addr handler_addr;

	#ifdef DEBUG_MODE
		debug_log("[*] Instrumenting prologues...\n");
	#endif

	for (i = 0; i < PROLOGUE_COUNT; i++)
	{
		prologue_addr = (arm_addr)(image_base_address + prologues[i]);
		handler_addr = (arm_addr)(PROLOGUE_HANDLERs + (i * PROLOGUE_HANDLER_SIZE));
		build_PROLOGUE_HANDLER((void*)handler_addr, prologue_addr);

		if(set_dispatcher((void*)prologue_addr, handler_addr) != 0)
		{
			return -1;
		}
	}
	return 0;
}

int instrument_epilogues(void* image_base_address)
{
	int i;
	arm_addr epilogue_addr;
	arm_addr handler_addr;

	#ifdef DEBUG_MODE
		debug_log("[*] Instrumenting epilogues...\n");
	#endif

	for (i = 0; i < EPILOGUE_COUNT; i++)
	{
		epilogue_addr = (arm_addr)(image_base_address + epilogues[i]);
		handler_addr = (arm_addr)(EPILOGUE_HANDLERs + (i * EPILOGUE_HANDLER_SIZE));
		build_EPILOGUE_HANDLER((void*)handler_addr, epilogue_addr);

		if(set_dispatcher((void*)epilogue_addr, handler_addr) != 0)
		{
			return -1;
		}
	}
	return 0;
}

int instrument_code_pointer_calls(void* image_base_address)
{
	int i;
	arm_addr cptrcall_addr;
	arm_addr handler_addr;

	#ifdef DEBUG_MODE
		debug_log("[*] Instrumenting codepointer calls...\n");
	#endif

	for (i = 0; i < CPTRCALL_COUNT; i++)
	{
		cptrcall_addr = (arm_addr)(image_base_address + cptrcalls[i]);
		handler_addr = (arm_addr)(CPTRCALL_HANDLERs + (i * CPTRCALL_HANDLER_SIZE));
		build_CPTRCALL_HANDLER((void*)handler_addr, cptrcall_addr);

		if(set_dispatcher((void*)cptrcall_addr, handler_addr) != 0)
		{
			return -1;
		}
	}
	return 0;
}

int instrument_shadowstack_initializer(void* image_base_address, void* entry_point)
{
	#ifdef DEBUG_MODE
		debug_log("[*] Setting up shadow stack initialization routine...\n");
	#endif

	PROG_orig_entry_ins = *(arm_ins*)(entry_point);
	
	build_SHADOW_TRAMPOLINE((void*)SHADOW_TRAMPOLINE, (arm_addr)shadowstack_setup_handler, (arm_addr)entry_point);

	if(set_dispatcher((void*)entry_point, (arm_addr)SHADOW_TRAMPOLINE) != 0)
	{
		return -1;
	}

	return 0;
}

int do_instrumentation(void* image_base_address, void* code_start_address, void* entry_point)
{
	trampoline_size = 0;

	#ifdef BACKWARD_EDGE_PROTECTION
		trampoline_size += (PROLOGUE_COUNT * PROLOGUE_HANDLER_SIZE) + (EPILOGUE_COUNT * EPILOGUE_HANDLER_SIZE) + (SHADOW_TRAMPOLINE_SIZE);
	#endif

	#ifdef FORWARD_EDGE_PROTECTION
		trampoline_size += (CPTRCALL_COUNT * CPTRCALL_HANDLER_SIZE);
	#endif

	if (trampoline_size == 0)
	{
		#ifdef DEBUG_MODE
			debug_log("[~] do_instrumentation: nothing to instrument\n");
		#endif
		return 0;
	}

	trampoline_area = alloc_closest_free_area(code_start_address, (size_t)0, (size_t)MAX_ALLOC_DISTANCE, trampoline_size, PROT_READ | PROT_EXEC | PROT_WRITE);

	if (trampoline_area == NULL)
	{
		#ifdef DEBUG_MODE
			debug_log("[-] do_instrumentation: failed to allocate free memory within acceptable distance from address %p\n", code_start_address);
		#endif
		return -1;
	}

	#ifdef BACKWARD_EDGE_PROTECTION
		PROLOGUE_HANDLERs = (void*)(trampoline_area);
		EPILOGUE_HANDLERs = (void*)(trampoline_area + (PROLOGUE_COUNT * PROLOGUE_HANDLER_SIZE));
		SHADOW_TRAMPOLINE = (void*)(trampoline_area + (PROLOGUE_COUNT * PROLOGUE_HANDLER_SIZE) + (EPILOGUE_COUNT * EPILOGUE_HANDLER_SIZE));
	#endif

	#ifdef FORWARD_EDGE_PROTECTION
		#ifdef BACKWARD_EDGE_PROTECTION
			CPTRCALL_HANDLERs = (void*)(trampoline_area + (PROLOGUE_COUNT * PROLOGUE_HANDLER_SIZE) + (EPILOGUE_COUNT * EPILOGUE_HANDLER_SIZE) + SHADOW_TRAMPOLINE_SIZE);
		#else
			CPTRCALL_HANDLERs = (void*)(trampoline_area);
		#endif		
	#endif

	#ifdef BACKWARD_EDGE_PROTECTION
		if(instrument_shadowstack_initializer(image_base_address, entry_point) != 0)
		{
			#ifdef DEBUG_MODE
				debug_log("[-] do_instrumentation: failed to set up shadowstack initialization\n");
			#endif
			return -1;
		}

		if(instrument_prologues(image_base_address) != 0)
		{
			#ifdef DEBUG_MODE
				debug_log("[-] do_instrumentation: failed to instrument prologues\n");
			#endif
			return -1;
		}
	
		if(instrument_epilogues(image_base_address) != 0)
		{
			#ifdef DEBUG_MODE
				debug_log("[-] do_instrumentation: failed to instrument epilogues\n");
			#endif
			return -1;
		}
	#endif

	#ifdef FORWARD_EDGE_PROTECTION
		if(instrument_code_pointer_calls(image_base_address) != 0)
		{
			#ifdef DEBUG_MODE
				debug_log("[-] do_instrumentation: failed to instrument codepointer calls\n");
			#endif
			return -1;
		}		
	#endif

	#ifdef DEBUG_MODE
		debug_log("[+] Done instrumenting!\n");
	#endif
	
	return 0;
}

void undo_instrumentation()
{
	// TODO: undo all instrumentation here, we can take original instruction from static offset within the handler

	if (trampoline_area)
	{
		munmap(trampoline_area, trampoline_size);
		trampoline_area = (void*)NULL;
	}

	#ifdef BACKWARD_EDGE_PROTECTION
		if (PROG_shadow_stack_bottom)
		{
			free(PROG_shadow_stack_bottom);
			PROG_shadow_stack_bottom = (void*)NULL;
			PROG_shadow_stack_top = (void*)NULL;
		}
	#endif
	return;
}

/*
	Callback function reporting shared object name and base address
	Note that dlpi_addr is not actually the base address but difference between linked-load and actual-load addresses
	for non-PIE ELF main binaries that difference is always 0, for non-prelinked shared libraries it is always the base address (since they are linked to load at 0)

	If we are called on the 'main' object (ie. image of the running process) we extract its base address from its ELF program headers
*/
int walker_callback(struct dl_phdr_info *info, size_t size, void *data)
{
	int j;

	if(info->dlpi_addr == 0)
	{
		// Main object
		for (j = 0; j < info->dlpi_phnum; j++)
		{
			if (info->dlpi_phdr[j].p_type == PT_LOAD)
			{
				// Determine base address from virtual address and relocation address
				PROG_image_base_address = (void*)(info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);

				#ifdef DEBUG_MODE_VERBOSE
					debug_log("[DEBUG] walker_callback: Found program image base address [%p]\n", PROG_image_base_address);
				#endif

				if(parse_elf(PROG_image_base_address, &PROG_code_section_start_address, &PROG_code_section_end_address, &PROG_entry_point, &PROG_main_address, &PROG_stackcookie_address) != 0)
				{
					#ifdef DEBUG_MODE
						debug_log("[-] walker_callback: Failed to properly parse ELF, exiting...\n");
					#endif

					exit(-1);
				}
				
				if(do_instrumentation(PROG_image_base_address, PROG_code_section_start_address, PROG_entry_point) != 0)
				{
					#ifdef DEBUG_MODE
						debug_log("[-] walker_callback: Failed to finish instrumentation, exiting...\n");		
					#endif

					exit(-1);
				}

      			return 0;
			}
		}
	}
	else
	{
		#ifdef DEBUG_MODE_VERBOSE
			debug_log("[DEBUG] walker_callback: Loaded object [%s] @ [%p]\n", info->dlpi_name, (void*)info->dlpi_addr);
		#endif
	}
	return 0;
}

/*
	Constructor and Destructor for load-time activation
*/

// Called when the library is loaded and before dlopen() returns
void on_load(void)
{
	notify_msg("[*] Initializing Runtime Protection Module (RPM)...\n");

	dl_iterate_phdr(walker_callback, NULL);

	notify_msg("[+] Runtime Protection Module (RPM) installed!\n");
  	return;
}

// Called when the library is unloaded and before dlclose() returns
void on_unload(void)
{
	notify_msg("[*] Removing Runtime Protection Module (RPM)...\n");

	undo_instrumentation();

	notify_msg("[+] Uninstalled Runtime Protection Module (RPM)!\n");
    return;
}