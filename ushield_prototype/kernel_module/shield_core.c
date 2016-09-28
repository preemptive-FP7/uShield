/*
uShield - Kernel Protection Module (KPM)
(c) Jos Wetzels, Wouter Bokslag

This code implements the kernel protection module (KPM) of ushield.

grep sys_call_table /boot/System.map
cat /proc/kallsyms | grep sys_call_table
c000f708 T sys_call_table

insmod ./shield_core.ko
lsmod | grep "shield_core"
dmesg | tail -1
modinfo ./shield_core.ko
rmmod shield_core.ko
dmesg | tail -1

*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/syscalls.h>
#include <linux/version.h> 
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <asm/current.h>
#include <asm/errno.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <asm/cacheflush.h>
#include <asm/ptrace.h>
#include <asm/stacktrace.h>
#include <asm/processor.h>

#define DEBUG_MODE

#ifdef DEBUG_MODE
	//#define DEBUG_MODE_TECHNICAL
	//#define DEBUG_MODE_VERBOSE
	//#define DEBUG_MODE_VERBOSE2
#endif

#define SYSCALL_TABLE_ADDR 0xc000f708

// Policy measures (log, restart, kill)
#define DETECT_MEASURE "log"

// Feature enabling
#define BACKWARD_EDGE_PROTECTION
#define ENABLE_PATH_SANDBOXING
#define ENABLE_DEPTH_ALERT
//#define MULTI_THREAD_TEST
//#define SUPPRESS_ALERTS
#define FULL_FP_COMPLIANCE

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

#define MAX_SYSCALL_WHITELIST 313 // maximum number of syscalls
#define MAX_PATH_WHITELIST 5 // maximum number of whitelisted paths for application

#define MAX_TRAMPOLINE_GADGET_SIZE 5 // maximum trampoline gadget size in instructions
#define TRAMPOLINE_THRESHOLD 1 // maximum trampoline gadget threshold

#define MAX_STACKFRAMEWALK_DEPTH 2048 // maximum depth of stackframe walk to prevent crafted self-referential payloads causing infinite loops in algorithm

/*
	ARM specific types and constants
*/
typedef uint32_t arm_memword;
typedef uint32_t arm_addr;
typedef uint32_t arm_ins;
typedef uint16_t thumb_ins;

#define ARM_POINTER_SIZE (sizeof(arm_memword))
#define ARM_INSTRUCTION_SIZE (sizeof(arm_ins))
#define THUMB_INSTRUCTION_SIZE (sizeof(thumb_ins))

/*
	ARM calling convention stack offsets
*/
#define RETADDR_OFFSET 0
#define SAVEDFP_OFFSET (-ARM_POINTER_SIZE)

#define PC_OFFSET (-(ARM_POINTER_SIZE * 1))
#define SP_OFFSET (-(ARM_POINTER_SIZE * 2))
#define FP_OFFSET (-(ARM_POINTER_SIZE * 3))

/*
	Decoding bitmasks and opcodes via https://cs107e.github.io/readings/armisa.pdf and http://vision.gel.ulaval.ca/~jflalonde/cours/1001/h15/docs/ARM_v7.pdf
*/

/*
Data Processing instruction format:
	[Cond 31..28] [00 27..26] [I 25] [OpCode 24..21] [S 20] [Rn 19..16] [Rd 15..12] [Operand 2 11..0]

	Opcodes:
		0000 = AND - Rd:= Op1 AND Op2
		0001 = EOR - Rd:= Op1 EOR Op2
		0010 = SUB - Rd:= Op1 - Op2
		0011 = RSB - Rd:= Op2 - Op1
		0100 = ADD - Rd:= Op1 + Op2
		0101 = ADC - Rd:= Op1 + Op2 + C
		0110 = SBC - Rd:= Op1 - Op2 + C
		0111 = RSC - Rd:= Op2 - Op1 + C
		1000 = TST - set condition codes on Op1 AND Op2
		1001 = TEQ - set condition codes on Op1 EOR Op2
		1010 = CMP - set condition codes on Op1 - Op2
		1011 = CMN - set condition codes on Op1 + Op2
		1100 = ORR - Rd:= Op1 OR Op2
		1101 = MOV - Rd:= Op2
		1110 = BIC - Rd:= Op1 AND NOT Op2
		1111 = MVN - Rd:= NOT Op2

	SUB/ADD SP
		Mask checks whether bits 27..26 are 00, I = 1 (operand 2 is immediate value), opcode = 0010 (SUB) or 0100 (ADD), Rd = R13 (SP)

		00001111111000001111000000000000
		SUB SP
			00000010010000001101000000000000
		ADD SP
			00000010100000001101000000000000

	SUB/ADD SP, SP
		Mask checks whether bits 27..26 are 00, I = 1 (operand 2 is immediate value), opcode = 0010 (SUB) or 0100 (ADD), Rd = R13 (SP) and Rn = R13 (SP)

		00001111111011111111000000000000
		SUB SP, SP
			00000010010011011101000000000000
		ADD SP, SP
			00000010100011011101000000000000

	SUB/ADD SP, Rx
		Mask checks whether bits 27..26 are 00, opcode = 0010 (SUB) or 0100 (ADD), Rd = R13 (SP), I = 0

		00001111111000001111000000000000
		SUB SP, Rx
			00000000010000001101000000000000
		ADD SP, Rx
			00000000100000001101000000000000

	Imm argument mask
		[Rotate 11..8] [Imm 7..0]

		Rotate mask
			111100000000
		Imm mask
			000011111111

		The immediate operand rotate field is a 4 bit unsigned integer which specifies a shift operation on the 8 bit immediate value. This value is zero extended to 32 bits, and then
		subject to a rotate right by twice the value in the rotate field. This enables many common constants to be generated, for example all powers of 2.

		(imm >> (2 * (rot >> 8)))
*/

#define ARM_MOD_SP_MASK 0xFE0F000
#define ARM_SUB_SP 0x240D000
#define ARM_ADD_SP 0x280D000

#define ARM_MOD_SP_SP_MASK 0xFEFF000
#define ARM_SUB_SP_SP 0x24DD000
#define ARM_ADD_SP_SP 0x28DD000

#define ARM_MOD_SP_RX_MASK 0xFE0F000
#define ARM_SUB_SP_RX 0x40D000
#define ARM_ADD_SP_RX 0x80D000

#define ARG_ROT_MASK 0xF00
#define ARG_IMM_MASK 0xFF

/*
Block Data Transfer instruction format:
	[Cond 31..28] [100 27..25] [P U S W L 24..20] [Rn 19..16] [Register list 15..00]

	L (20): 0 = store to memory, 1 = load from memory
	Register list: each bit in 16-bit register list corresponds to a register

	Mask checks whether bits 27..25 are 100, bit 20 is 0, base register Rn = R15 (SP)


	Mask: 00001110000100000000000000000000
	Expected val: 00001000000000000000000000000000

	For LR check we check if register list contains R14 (LR) by check whether bit 14 is set

	Mask: 00001110000100000100000000000000
	Expected val: 00001000000000000100000000000000

	To extract the registers we take

	Mask: 1111111111111111
*/

#define STMFD_SP_MASK 0xE100000
#define ARM_STMFD_SP 0x8000000

#define STMFD_SP_LR_MASK 0xE104000
#define ARM_STMFD_SP_LR 0x8004000

#define ARG_REGLIST_MASK 0xFFFF
#define ARG_REGLIST_UP_TO_LR_MASK 0x8000

/*
Branch(-with-Link)-and-Exchange (indirect) instruction format:
	[Cond 31..28] [0001 27..24] [0010 23..20] [1111 19..16] [1111 15..12] [1111 11..8] [0001 7..4] [Rn 3..0]

	Mask check full range of bits 27..4	

	00001111111111111111111111110000

Covers:
	BX Rx
	BLX Rx
*/

#define ARM_IB_MASK 0x0ffffff0

#define ARM_BLX 0x012fff30
#define ARM_BX 0x012fff10

/*
Branch / Branch-with-Link(-and-Exchange) (direct) instruction format:
	[Cond 31..28] [101 27..25] [L 24] [offset 23..0]

	L (24): 0 = branch, 1 = branch-with-link

	Mask checks whether bits 27..25 are 101 and bit 24 is 1

	00001111000000000000000000000000

Covers:
	B imm
	BL imm
	BLX imm
*/

#define ARM_DB_MASK 0x0f000000
#define ARM_BL 0x0b000000
#define ARM_B 0x0a000000

#define ARM_BL_ADDR_MASK 0x00ffffff

/*
Data Processing instruction format:
	[Cond 31..28] [00 27..26] [I 25] [OpCode 24..21] [S 20] [Rn 19..16] [Rd 15..12] [Operand 2 11..0]

	Opcodes:
		0000 = AND - Rd:= Op1 AND Op2
		0001 = EOR - Rd:= Op1 EOR Op2
		0010 = SUB - Rd:= Op1 - Op2
		0011 = RSB - Rd:= Op2 - Op1
		0100 = ADD - Rd:= Op1 + Op2
		0101 = ADC - Rd:= Op1 + Op2 + C
		0110 = SBC - Rd:= Op1 - Op2 + C
		0111 = RSC - Rd:= Op2 - Op1 + C
		1000 = TST - set condition codes on Op1 AND Op2
		1001 = TEQ - set condition codes on Op1 EOR Op2
		1010 = CMP - set condition codes on Op1 - Op2
		1011 = CMN - set condition codes on Op1 + Op2
		1100 = ORR - Rd:= Op1 OR Op2
		1101 = MOV - Rd:= Op2
		1110 = BIC - Rd:= Op1 AND NOT Op2
		1111 = MVN - Rd:= NOT Op2

	Mask checks whether bits 27..26 are 00 and Rd = R15 (PC)

	00001100000000001111000000000000
*/
#define ARM_DATA_PC_MASK 0xC00F000
#define ARM_DATA_PC 0xF000

/*
Single Data Transfer instruction format:
	[Cond 31..28] [01 27..26] [I P U B W L 25..20] [Rn 19..16] [Rd 15..12] [Offset 11..0]

	L (20): 0 = store to memory, 1 = load from memory

	Mask checks whether bits 27..26 are 01, bit 20 is 1 and Rd = R15 (PC)

	00001100000100001111000000000000
*/
#define ARM_LDR_PC_MASK 0xC10F000
#define ARM_LDR_PC 0x410F000

/*
Block Data Transfer instruction format:
	[Cond 31..28] [100 27..25] [P U S W L 24..20] [Rn 19..16] [Register list 15..00]

	L (20): 0 = store to memory, 1 = load from memory
	Register list: each bit in 16-bit register list corresponds to a register

	Mask checks whether bits 27..25 are 100, bit 20 is 1 and register list bit 15 is 1

	00001110000100001000000000000000
*/
#define ARM_LDM_PC_MASK 0xE108000
#define ARM_LDM_PC 0x8108000

/*
	Return codes
*/
#define UNPROTECTED_APP -1
#define SECURITY_OK 0
#define SECURITY_VIOLATION 1

#define SANDBOX_OK 0
#define SANDBOX_VIOLATION 1

#define SANDBOX_PATH_OK 0
#define SANDBOX_PATH_VIOLATION 1

#define HEURISTICS_OK 0
#define HEURISTICS_VIOLATION 1

#define MEMPROT_OK 0
#define MEMPROT_VIOLATION 1

/*
	Alert codes
*/
#define MISC_ALERT 1
#define MEMPROT_ALERT 2
#define HEURISTICS_PIVOT_ALERT 3
#define HEURISTICS_RET_ALERT 4
#define HEURISTICS_RET_ALERT2 5
#define HEURISTICS_RET_ALERT3 6
#define HEURISTICS_SF_ALERT 7
#define SYSCALL_SANDBOX_ALERT 8
#define PATH_SANDBOX_ALERT 9
#define WALK_DEPTH_ALERT 10
#define HEURISTICS_FP_ALERT 11

/*
	Integrity Walker types
*/
#define FP_BASED_WALKER 1
#define UNWIND_BASED_WALKER 2

/*
	Module data
*/
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Jos Wetzels, Wouter Bokslag");
MODULE_DESCRIPTION("Shield_Core protection module prototype");

/*
	Globals
*/
void **sys_call_table;

typedef struct protected_app
{
  char* name;
  int integrity_walker_type;
  int has_syscall_sandbox;
  int syscall_whitelist[MAX_SYSCALL_WHITELIST];
  int syscall_whitelist_count;
  int has_path_sandbox;
  char* path_whitelist[MAX_PATH_WHITELIST];
  int path_whitelist_count;
} protected_app;

#define PROTECTED_APP_COUNT 1

/*
	Protected apps with their whitelists
*/
const protected_app protected_apps[PROTECTED_APP_COUNT] = {
	{ "dummyserver", FP_BASED_WALKER, 0, {}, 0, 0, {}, 0 }

};

/*
	Hooked syscall prototypes
*/
int (*orig_sys_open)(const char *filename, int flags, int mode);

int (*orig_sys_mprotect)(void *addr, size_t len, int prot);
void* (*orig_sys_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);

int (*orig_sys_ioctl)(unsigned int fd, unsigned int cmd, unsigned long arg);

int (*orig_sys_execve)(const char *filename, char *const argv[], char *const envp[]);
int (*orig_sys_exit)(int status);
int (*orig_sys_kill)(int pid, int sig);

unsigned long (*orig_sys_mremap)(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags);

int (*orig_sys_connect)(int fd, struct sockaddr *uservaddr, int addrlen);
int (*orig_sys_shutdown)(int fd, int how);

int (*orig_sys_rename)(const char * oldname, const char * newname);
int (*orig_sys_mkdir)(const char * pathname, int mode);
int (*orig_sys_rmdir)(const char * pathname);
int (*orig_sys_creat)(const char * pathname, int mode);
int (*orig_sys_link)(const char * oldname, const char * newname);
int (*orig_sys_unlink)(const char * pathname);
int (*orig_sys_symlink)(const char * oldname, const char * newname);

int (*orig_sys_chmod)(const char * filename, mode_t mode);
int (*orig_sys_chown)(const char * filename, uid_t user, gid_t group);
int (*orig_sys_lchown)(const char * filename, uid_t user, gid_t group);

int (*orig_sys_ptrace)(long request, long pid, long addr, long data);

int (*orig_sys_setuid)(uid_t uid);
int (*orig_sys_setgid)(gid_t gid);

int (*orig_sys_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
int (*orig_sys_chroot)(const char * filename);
int (*orig_sys_mount)(char * dev_name, char * dir_name, char * type, unsigned long new_flags, void * data);
int (*orig_sys_umount)(char * name, int flags);
int (*orig_sys_reboot)(int magic1, int magic2, int cmd, void * arg);


/*
	General functions
*/

/*
	Virtual memory mapping identification code taken from Linux Kernel /proc/<pid>/maps generation code:
	https://github.com/torvalds/linux/blob/master/fs/proc/task_mmu.c
*/

// Get VMA where address lies
struct vm_area_struct *get_vma(arm_addr addr)
{
	struct vm_area_struct *vma = current->active_mm->mmap;

	while(vma)
	{
		if ((addr >= vma->vm_start) && (addr < vma->vm_end))
		{
			return vma;
		}
		vma = vma->vm_next;	
	}
	return NULL;
}

// Check if address lies in a given VMA
int in_vma(arm_addr addr, struct vm_area_struct *vma)
{
	if (vma == NULL)
	{
		return 0;
	}
	else
	{
		return ((addr >= vma->vm_start) && (addr < vma->vm_end));
	}
}

// Fetch stack vma for current process
struct vm_area_struct* get_stack_vma(void)
{
	// since there is no end_stack address in mm_struct we walk all vmas to see if it belongs to stack vma
	struct mm_struct *mm = current->active_mm;
	struct vm_area_struct *vma = mm->mmap;

	while(vma)
	{
		if ((vma->vm_start <= mm->start_stack) && (vma->vm_end >= mm->start_stack))
		{
			return vma;
		}
		vma = vma->vm_next;	
	}

	return NULL;
}

// Check if address range lies on heap
int is_heap(arm_addr addr)
{
	struct mm_struct *mm = current->active_mm;
	return ((addr >= mm->start_brk) && (addr <= mm->brk));
}

// Check if address range lies on stack
int is_stack(arm_addr addr)
{
	return in_vma(addr, get_stack_vma());
}

// Checks whether address range falls on stack or heap
int is_stack_or_heap(arm_addr addr)
{
	return (is_stack(addr) || is_heap(addr));
}

int get_memprot(struct vm_area_struct *vma)
{
	int old_prot = 0;

	if (!vma)
		return old_prot;

	// get VMA memory protections (convert from VM_ to PROT_)
	old_prot = 0;

	if (vma->vm_flags & VM_READ)
	{
		old_prot |= PROT_READ;
	}
	if (vma->vm_flags & VM_WRITE)
	{
		old_prot |= PROT_WRITE;
	}
	if (vma->vm_flags & VM_EXEC)
	{
		old_prot |= PROT_EXEC;
	}
	return old_prot;
}

// Checks whether requested memory protections are allowed
int allowed_prots(arm_addr addr, size_t len, int new_prot)
{
	/*
		Enumerate all VMAs the region [addr, addr+len] belongs to and check whether their old protection flags allow for new changes
	*/
	arm_addr cur_addr = addr;
	int old_prot = 0;

	// We check all VMAs covered by address + len range
	while (cur_addr < (arm_addr)(addr + len))
	{
		struct vm_area_struct *vma = get_vma(cur_addr);
		if (!vma)
			break;

		old_prot = get_memprot(vma);
		if (old_prot == 0)
			break;

		#ifdef DEBUG_MODE_VERBOSE2
			printk("[DEBUG] allowed_prots(%s) -> Addr: %x Len: %d oP: %x nP: %x SoH: %d\n", current->group_leader->comm, cur_addr, len, old_prot, new_prot, is_stack_or_heap(cur_addr));
		#endif

		/*
		TODO:
			add	(!(old_prot & PROT_EXEC) && (new_prot & PROT_EXEC)) || (new_prot & (PROT_EXEC|PROT_WRITE))
			but ignore ELF-loading initialization mprotect and mmap calls here
		*/

		if ((is_stack_or_heap(cur_addr) && (new_prot & PROT_EXEC) && (!(new_prot & PROT_GROWSDOWN))))
		{
			return MEMPROT_VIOLATION;
		}

		cur_addr = vma->vm_end;
	}

	return MEMPROT_OK;
}

int get_current_protected_app(protected_app* current_app)
{
	int i;
	int l = strlen(current->group_leader->comm);

	for (i = 0; i < PROTECTED_APP_COUNT; i++)
	{
		if (!strncmp(current->group_leader->comm, protected_apps[i].name, l))
		{			
			memcpy(current_app, &protected_apps[i], sizeof(protected_app));
			return 0;
		}
	}

	return -1;
}

// Checks (very naively) whether path falls within calling process' sandbox bounds
int check_path_sandbox(const char* pathname)
{
	int j;
	protected_app current_app;

	if(get_current_protected_app(&current_app) == 0)
	{
		if (current_app.has_path_sandbox)
		{
			#ifdef DEBUG_MODE_VERBOSE
				printk(KERN_INFO "[DEBUG] Checking path sandbox for '%s' on (%s)\n", pathname, current_app.name);
			#endif

			for (j = 0; j < current_app.path_whitelist_count; j++)
			{
				#ifdef DEBUG_MODE_VERBOSE
					printk(KERN_INFO "[>] (%s)\n", current_app.path_whitelist[j]);
				#endif

				if (!strncmp(pathname, current_app.path_whitelist[j], strlen(current_app.path_whitelist[j])))
				{
					return SANDBOX_PATH_OK;
				}
			}		
			return SANDBOX_PATH_VIOLATION;
		}
		else
		{
			return SANDBOX_PATH_OK;
		}
	}
	else
	{
		return UNPROTECTED_APP;
	}
}

// Checks whether calling process is among protected apps and if so, whether this syscall is allowed by the sandbox or not
int check_syscall_sandbox(protected_app current_app, int syscall_no)
{
	int j;

	// Check whether the application is sandboxed
	if (current_app.has_syscall_sandbox)
	{
		#ifdef DEBUG_MODE_VERBOSE
			printk(KERN_INFO "[DEBUG] Checking syscall sandbox for syscall #%d on (%s)\n", syscall_no, current_app.name);
		#endif

		// If so, check whether syscall is within sandbox bounds
		for (j = 0; j < current_app.syscall_whitelist_count; j++)
		{
			if (syscall_no == current_app.syscall_whitelist[j])
			{
				return SANDBOX_OK;
			}
		}
		return SANDBOX_VIOLATION;
	}
	else
	{
		return SANDBOX_OK;
	}
}

// Dump program state
void state_dump(void)
{
	int i;
	struct pt_regs *regs = task_pt_regs(current);

	printk(KERN_INFO "[>] comm (%s) pid (%d)\n", current->group_leader->comm, current->pid);
	printk(KERN_INFO "[>] Registers: \n");

	printk(KERN_INFO "[>] PC: %lx, LR: %lx, SP: %lx, FP: %lx, IP: %lx, CPSR: %lx\n", regs->ARM_pc, regs->ARM_lr, regs->ARM_sp, regs->ARM_fp, regs->ARM_ip, regs->ARM_cpsr);
	for (i = 0; i < 11; i++)
	{
		printk(KERN_INFO "[>] r%d: %lx", i, regs->uregs[i]);
	}

	printk(KERN_INFO "\n");
	return;
}

// Detection measure routine
void detection_measure(int alert_code, int syscall_no)
{
	#ifndef SUPPRESS_ALERTS
		char* msgs[] = {"SECURITY_OK (should never occur)", "Unspecified (misc.)", "Memory protection violation", "Heuristics (stack pivot detected)", "Heuristics (suspicious return address)", "Heuristics (trampoline return address)", "Heuristics (suspicious syscall LR value)", "Heuristics (suspicious stackframe-chain layout)", "Syscall sandbox violation", "Path sandbox violation", "Max. stackframe integrity walk depth exceeded", "Heuristics (corrupted framepointer)"};

		struct timeval time;
		unsigned long local_time;
		struct rtc_time tm;

		do_gettimeofday(&time);
		local_time = (u32)(time.tv_sec - (sys_tz.tz_minuteswest * 60));
		rtc_time_to_tm(local_time, &tm);

		printk(KERN_INFO "[!] ..:: [SHIELD_CORE ALERT] ::..\n");

		if (alert_code == SYSCALL_SANDBOX_ALERT)
		{
			printk(KERN_INFO "[!] [%04d %02d %02d  %02d:%02d:%02d %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s (syscall #%d not in whitelist)]\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, current->pid, current->group_leader->comm, DETECT_MEASURE, msgs[alert_code], syscall_no);
		}
		else
		{
			printk(KERN_INFO "[!] [%04d %02d %02d  %02d:%02d:%02d %s CEF:%d | %d | %d | %d | %d | %s | %d | dvchost=%s dvcpid=%d deviceProcessName=%s outcome=%s message=%s]\n", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, CEF_TOOL_IP, CEF_VERSION, CEF_TOOL_ID, CEF_DEVICE_NUM, CEF_TOOL_VERSION, CEF_EVENT_ID, CEF_EVENT_NAME, CEF_SEVERITY_LEVEL, CEF_DVC_HOST, current->pid, current->group_leader->comm, DETECT_MEASURE, msgs[alert_code]);
		}

		#ifdef DEBUG_MODE_TECHNICAL
			printk(KERN_INFO "[DEBUG] Technical information: \n");
			printk(KERN_INFO "[>] Trigger syscall #: %d\n", syscall_no);
			state_dump();
		#endif
	#endif
	return;
}

/*
	Determine bl destination address for ARM branch instruction
*/
arm_addr calc_bl_dst_ARM(arm_addr ins_addr, arm_addr offset)
{
	// if 24-bit integer sign bit is set we treat as negative, else as positive
	if (offset & 0x800000)
	{
		return (arm_addr)(ins_addr - ((0xfffffe - offset) * 4));
	}
	else
	{
		return (arm_addr)(ins_addr + ((offset * 4) + 8));	
	}
}

/*
	Check if instruction is indirect branch-with-link-and-exchange (BLX) ARM instruction
*/
int is_indirect_blx_ARM(arm_ins ins)
{
	return ((ins & ARM_IB_MASK) == ARM_BLX);
}

/*
	Check if instruction is indirect branch-and-exchange (BX) ARM instruction
*/
int is_indirect_bx_ARM(arm_ins ins)
{
	return ((ins & ARM_IB_MASK) == ARM_BX);
}

/*
	Check if instruction is direct branch-with-link (BL) ARM instruction
*/
int is_direct_bl_ARM(arm_ins ins)
{
	return ((ins & ARM_DB_MASK) == ARM_BL);
}

/*
	Check if instruction is direct branch (B) ARM instruction
*/
int is_direct_b_ARM(arm_ins ins)
{
	return ((ins & ARM_DB_MASK) == ARM_B);
}

/*
	Check if instruction is data processing instruction with Rd = PC
*/
int is_pc_data_ARM(arm_ins ins)
{
	return ((ins & ARM_DATA_PC_MASK) == ARM_DATA_PC);
}

/*
	Check if instruction is LDR instruction with Rd = PC
*/
int is_pc_ldr_ARM(arm_ins ins)
{
	return ((ins & ARM_LDR_PC_MASK) == ARM_LDR_PC);
}

/*
	Check if instruction is LDM instruction with PC in <reglist>
*/
int is_pc_ldm_ARM(arm_ins ins)
{
	return ((ins & ARM_LDM_PC_MASK) == ARM_LDM_PC);
}

/*
	Check if instruction is any indirect branch ARM instruction
	We consider as an indirect branch any of the following:
		+ A register-relative branch instruction (BX, BLX)
		+ Any instruction with the PC (R15) as its destination register:
			Data processing:
				MOV, MVN, ADD, SUB, RSB, ADC, SBC, RSC, AND, OR, EOR, BIC
			Register loading:
				LDR, LDM (POP is alias for LDM SP!, <reglist>)
		
*/
int is_indirect_branch_ARM(arm_ins ins)
{
	return (is_indirect_blx_ARM(ins) || is_indirect_bx_ARM(ins) || is_pc_data_ARM(ins) || is_pc_ldr_ARM(ins) || is_pc_ldm_ARM(ins));
}

int fetch_instruction(arm_addr address, arm_ins* pr_ins_ARM)
{
	// Get simple variable from user-space, including address validity check
	return get_user(*pr_ins_ARM, ((arm_ins*)(address)));
}

int fetch_addr_pointer(arm_addr address, arm_addr* memword)
{
	// Get simple variable from user-space, including address validity check
	return get_user(*memword, ((arm_addr*)(address)));
}

/*
	Check whether preceding instruction qualifies as (valid) branch
*/
int branch_preceded(arm_addr address)
{	
	arm_ins pr_ins_ARM;
	
	// Fetch preceding instruction
	int r = fetch_instruction((arm_addr)(address - ARM_INSTRUCTION_SIZE), &pr_ins_ARM);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] branch-preceded: (%x) (%x) (%d)\n", address, pr_ins_ARM, r);
	#endif

	if (r != 0)
	{
		return 0;
	}
	else
	{
		// Check if preceding instruction is ARM mode branch-with-link (either direct or indirect / either with or without exchange)
		return (is_indirect_blx_ARM(pr_ins_ARM) || is_direct_bl_ARM(pr_ins_ARM));
	}
}

/*
	Check if instructions (within certain upper bound) from address onward constitute a (branch-preceded) trampoline gadget
	Trampoline gadgets are defined as any sequence of instructions that contains an an indirect (ie. register-relative)
	branch-with-link instruction (BLX) and terminates in any indirect branch (eg. register-relative branch or PC-setting instruction)
*/
int is_trampoline_gadget(arm_addr start_address)
{
	int dispatch_found;
	arm_addr addr;
	arm_ins ins_ARM;

	dispatch_found = 0;

	for(addr = start_address; addr <= (start_address + (MAX_TRAMPOLINE_GADGET_SIZE*ARM_INSTRUCTION_SIZE)); addr += ARM_INSTRUCTION_SIZE)
	{
		// Fetch instruction at addr
		int r = fetch_instruction(addr, &ins_ARM);

		if (r != 0)
			break;

		// Once we find a suitable dispatcher (BLX Rm) any indirect branch (including another BLX Rm) qualifies as gadget terminator
		if ((dispatch_found == 0) && is_indirect_blx_ARM(ins_ARM))
		{
			// Indirect branch-with-link found, possible trampoline gadget
			dispatch_found = 1;
			continue;
		}
		if ((dispatch_found == 1) && is_indirect_branch_ARM(ins_ARM))
		{
			// Gadget terminator and dispatcher found, detect trampoline gadget
			return 1;
		}
	}
	return 0;
}

/*
	Test if address is valid return address in userspace:
		+ branch-with-link-precededness (+ if it is preceded by a direct branch we check if destination of branch is valid)
		+ not in stack or heap
*/
int valid_ret_address(arm_addr address)
{
	/*
		Return address may never be on stack or heap (technically a superfluous test given the other checks)
	*/
	#ifndef MULTI_THREAD_TEST
		if (is_stack_or_heap(address))
		{
			return 0;
		}
	#endif

	return branch_preceded(address);
}

/*
	Use frame-pointer based stackframe chain walking
*/
int frame_based_walker(struct pt_regs *regs, int trampoline_count_init)
{
	int walk_depth = 0;
	int trampoline_count = trampoline_count_init;

	arm_addr return_address, return_address_pointer, saved_fp_pointer = 0;
	arm_addr frame_pointer = regs->ARM_fp;

	/*
		Walk the stackframe chain
	*/
	while(frame_pointer != 0)
    {
    	if (!is_stack(frame_pointer))
    	{
    		#ifdef DEBUG_MODE_VERBOSE
    			printk(KERN_INFO "[DEBUG] corrupted FP (%x)\n", frame_pointer);
    		#endif

    		#ifdef FULL_FP_COMPLIANCE
    			return HEURISTICS_FP_ALERT;
    		#else
    			break;
    		#endif
    	}

    	if (trampoline_count >= TRAMPOLINE_THRESHOLD)
    	{
    		return HEURISTICS_RET_ALERT2;
    	}

        return_address_pointer = (arm_memword)(frame_pointer + RETADDR_OFFSET);
        saved_fp_pointer = (arm_memword)(frame_pointer + SAVEDFP_OFFSET);

        if(fetch_addr_pointer(return_address_pointer, &return_address) != 0)
        {
        	break;
        }

		#ifdef DEBUG_MODE_VERBOSE
			printk(KERN_INFO "[DEBUG] FP (%x), RET (%x), TPC (%d)\n", frame_pointer, return_address, trampoline_count);
		#endif

        if(!valid_ret_address(return_address))
        {
        	return HEURISTICS_RET_ALERT;
        }

        trampoline_count += is_trampoline_gadget(return_address);

        if(fetch_addr_pointer(saved_fp_pointer, &frame_pointer) != 0)
        {
        	break;
        }

        walk_depth++;

        // Check maximum walk depth, raise alert if enabled
        if (walk_depth > MAX_STACKFRAMEWALK_DEPTH)
        {
        	#ifdef ENABLE_DEPTH_ALERT
        		return WALK_DEPTH_ALERT;
        	#else
        		break;
        	#endif
        }
    }

    return HEURISTICS_OK;
}

// Heuristics checking routine
int check_heuristics(protected_app current_app)
{
	struct pt_regs *regs = task_pt_regs(current);

	arm_addr stack_pointer = regs->ARM_sp;
	arm_addr frame_pointer = regs->ARM_fp;
	arm_addr link_register = regs->ARM_lr;

	/*
		Check whether stack pointer resides in stack (implements stack pivot check)
		Note that this is not supported for multi-threading applications as the multiple stacks per thread resolution
		requires us to obtain addresses for stack area for each thread which we haven't implemented yet for this prototype.
	*/
	#ifndef MULTI_THREAD_TEST
		if (!(is_stack(stack_pointer)))
		{
			return HEURISTICS_PIVOT_ALERT;
		}
	#endif

	/*
		Because of the way ARM calling convention works the LR always has to be set to return point from syscall
		which means that any XOP chain will, upon entering a syscall, need to have the LR point to the next gadget
		Hence we can perform is_valid_ret_address() check on LR (same as with stackframe return address validation):
	*/

	if(!(valid_ret_address(link_register)))
	{
		return HEURISTICS_RET_ALERT3;
	}

	/*
		Perform stackframe walking and validation
	*/

	#ifndef MULTI_THREAD_TEST
		#ifdef FULL_FP_COMPLIANCE
			if (!(is_stack(frame_pointer) || (frame_pointer == ((arm_addr)1))))
			{	
				return HEURISTICS_SF_ALERT;
			}
		#endif

		#ifdef BACKWARD_EDGE_PROTECTION
			switch(current_app.integrity_walker_type)
			{
				case FP_BASED_WALKER:
				{
					return frame_based_walker(regs, is_trampoline_gadget(link_register));
				}break;

				case UNWIND_BASED_WALKER:
				{
					#ifdef DEBUG_MODE_VERBOSE
						printk(KERN_INFO "[DEBUG] UNWIND_BASED_WALKER not implemented in prototype...\n");
					#endif	
				}break;

				default:
				{
					return MISC_ALERT;
				}break;
			}

			#ifdef DEBUG_MODE_VERBOSE
				printk(KERN_INFO "[DEBUG] Finished strackframe integrity walk...\n");
			#endif
		#endif

	#endif

	return HEURISTICS_OK;
}

// Security check wrapper, contains heuristics and sandbox check
int security_check(int syscall_no)
{
	protected_app current_app;

	if(get_current_protected_app(&current_app) != 0)
	{
		return UNPROTECTED_APP;
	}

	switch(check_syscall_sandbox(current_app, syscall_no))
	{
		case SANDBOX_VIOLATION:
		{
			detection_measure(SYSCALL_SANDBOX_ALERT, syscall_no);
			return SECURITY_VIOLATION;
		}break;

		case SANDBOX_OK:
		{
			int ret = check_heuristics(current_app);
			if (ret != HEURISTICS_OK)
			{
				detection_measure(ret, syscall_no);
				return SECURITY_VIOLATION;
			}
			return SECURITY_OK;
		}break;

		default:
		{
			detection_measure(MISC_ALERT, syscall_no);
			return SECURITY_VIOLATION;
		}break;
	}
}

/*
	syscall hooks
*/
int hook_sys_mprotect(void *addr, size_t len, int prot)
{
    int ret;

    // only enforce memory protection policies for protected apps
    if(security_check(__NR_mprotect) != UNPROTECTED_APP)
    {
	    if(allowed_prots((arm_addr)addr, len, prot) != MEMPROT_OK)
	    {    	
			detection_measure(MEMPROT_ALERT, __NR_mprotect);
	    }
    }

    #ifdef DEBUG_MODE_VERBOSE2
    	printk(KERN_INFO "[DEBUG] '%s' -> mprotect(%p, %d, %x)\n", current->comm, addr, len, prot);
    #endif

   	ret = orig_sys_mprotect(addr, len, prot);
    return ret;
}

void* hook_sys_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
{
    void* ret;

    // only enforce memory protection policies for protected apps
    if(security_check(__NR_mmap) != UNPROTECTED_APP)
    {
	    if(allowed_prots((arm_addr)addr, length, prot) != MEMPROT_OK)
	    {
	    	detection_measure(MEMPROT_ALERT, __NR_mmap);
	    }
    }

    #ifdef DEBUG_MODE_VERBOSE2
    	printk(KERN_INFO "[DEBUG] '%s' -> mmap(%p, %d, %x, %x, %x, %x)\n", current->comm, addr, length, prot, flags, fd, (unsigned int)offset);
    #endif

    ret = orig_sys_mmap(addr, length, prot, flags, fd, offset);    
    return ret;
}

int hook_sys_open(const char *filename, int flags, int mode) 
{
	int ret;

	security_check(__NR_open);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(filename) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_open);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> open(%s, %x, %x)\n", current->comm, filename, flags, mode);
	#endif

	ret = orig_sys_open(filename, flags, mode);
	return ret;
}

int hook_sys_execve(const char *filename, char *const argv[], char *const envp[])
{
	int ret;

	security_check(__NR_execve);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(filename) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_execve);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> execve(%s, ...)\n", current->comm, filename);
	#endif

	ret = orig_sys_execve(filename, argv, envp);
	return ret;
}

int hook_sys_exit(int status)
{
	int ret;

	security_check(__NR_exit);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> exit(%d)\n", current->comm, status);
	#endif

	ret = orig_sys_exit(status);
	return ret;
}

int hook_sys_kill(int pid, int sig)
{
	int ret;

	security_check(__NR_kill);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> kill(%d, %d)\n", current->comm, pid, sig);
	#endif

	ret = orig_sys_kill(pid, sig);
	return ret;
}

int hook_sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
	int ret;

	security_check(__NR_ioctl);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> ioctl(%d, %x, %lx)\n", current->comm, fd, cmd, arg);
	#endif

	ret = orig_sys_ioctl(fd, cmd, arg);
	return ret;
}

unsigned long hook_sys_mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags)
{
	unsigned long ret;

	security_check(__NR_mremap);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> mremap(%lx, %lx, %lx, %lx)\n", current->comm, addr, old_len, new_len, flags);
	#endif

	ret = orig_sys_mremap(addr, old_len, new_len, flags);
	return ret;
}

int hook_sys_connect(int fd, struct sockaddr *uservaddr, int addrlen)
{
	int ret;

	security_check(__NR_connect);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> connect(%d, ...)\n", current->comm, fd);
	#endif

	ret = orig_sys_connect(fd, uservaddr, addrlen);
	return ret;
}

int hook_sys_shutdown(int fd, int how)
{
	int ret;

	security_check(__NR_shutdown);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> shutdown(%d, %d)\n", current->comm, fd, how);
	#endif

	ret = orig_sys_shutdown(fd, how);
	return ret;
}

int hook_sys_rename(const char * oldname, const char * newname)
{
	int ret;

	security_check(__NR_rename);

	#ifdef ENABLE_PATH_SANDBOXING
		if ((check_path_sandbox(oldname) == SANDBOX_PATH_VIOLATION) || (check_path_sandbox(newname) == SANDBOX_PATH_VIOLATION))
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_rename);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> rename(%s, %s)\n", current->comm, oldname, newname);
	#endif

	ret = orig_sys_rename(oldname, newname);
	return ret;
}

int hook_sys_mkdir(const char * pathname, int mode)
{
	int ret;

	security_check(__NR_mkdir);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(pathname) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_mkdir);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> mkdir(%s, %d)\n", current->comm, pathname, mode);
	#endif

	ret = orig_sys_mkdir(pathname, mode);
	return ret;
}

int hook_sys_rmdir(const char * pathname)
{
	int ret;

	security_check(__NR_rmdir);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(pathname) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_rmdir);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> rmdir(%s)\n", current->comm, pathname);
	#endif

	ret = orig_sys_rmdir(pathname);
	return ret;
}

int hook_sys_creat(const char * pathname, int mode)
{
	int ret;

	security_check(__NR_creat);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(pathname) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_creat);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> creat(%s, %d)\n", current->comm, pathname, mode);
	#endif

	ret = orig_sys_creat(pathname, mode);
	return ret;
}

int hook_sys_link(const char * oldname, const char * newname)
{
	int ret;

	security_check(__NR_link);

	#ifdef ENABLE_PATH_SANDBOXING
		if ((check_path_sandbox(oldname) == SANDBOX_PATH_VIOLATION) || (check_path_sandbox(newname) == SANDBOX_PATH_VIOLATION))
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_link);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> link(%s, %s)\n", current->comm, oldname, newname);
	#endif

	ret = orig_sys_link(oldname, newname);
	return ret;
}

int hook_sys_unlink(const char * pathname)
{
	int ret;

	security_check(__NR_unlink);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(pathname) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_unlink);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> unlink(%s)\n", current->comm, pathname);
	#endif

	ret = orig_sys_unlink(pathname);
	return ret;
}

int hook_sys_symlink(const char * oldname, const char * newname)
{
	int ret;

	security_check(__NR_symlink);

	#ifdef ENABLE_PATH_SANDBOXING
		if ((check_path_sandbox(oldname) == SANDBOX_PATH_VIOLATION) || (check_path_sandbox(newname) == SANDBOX_PATH_VIOLATION))
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_symlink);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> symlink(%s, %s)\n", current->comm, oldname, newname);
	#endif

	ret = orig_sys_symlink(oldname, newname);
	return ret;
}

int hook_sys_chmod(const char * filename, mode_t mode)
{
	int ret;

	security_check(__NR_chmod);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(filename) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_chmod);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> chmod(%s, %d)\n", current->comm, filename, mode);
	#endif

	ret = orig_sys_chmod(filename, mode);
	return ret;
}

int hook_sys_chown(const char * filename, uid_t user, gid_t group)
{
	int ret;

	security_check(__NR_chown);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(filename) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_chown);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> chown(%s, %d, %d)\n", current->comm, filename, user, group);
	#endif

	ret = orig_sys_chown(filename, user, group);
	return ret;
}

int hook_sys_lchown(const char * filename, uid_t user, gid_t group)
{
	int ret;

	security_check(__NR_lchown);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(filename) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_lchown);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> lchown(%s, %d, %d)\n", current->comm, filename, user, group);
	#endif

	ret = orig_sys_lchown(filename, user, group);
	return ret;
}

int hook_sys_ptrace(long request, long pid, long addr, long data)
{
	int ret;

	security_check(__NR_ptrace);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> ptrace(%lx, %lx, %lx, %lx)\n", current->comm, request, pid, addr, data);
	#endif

	ret = orig_sys_ptrace(request, pid, addr, data);
	return ret;
}

int hook_sys_setuid(uid_t uid)
{
	int ret;

	security_check(__NR_setuid);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> setuid(%d)\n", current->comm, uid);
	#endif

	ret = orig_sys_setuid(uid);
	return ret;
}

int hook_sys_setgid(gid_t gid)
{
	int ret;

	security_check(__NR_setgid);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> setgid(%d)\n", current->comm, gid);
	#endif

	ret = orig_sys_setgid(gid);
	return ret;
}

int hook_sys_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	int ret;

	security_check(__NR_prctl);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> prctl(%d, %lx, %lx, %lx, %lx)\n", current->comm, option, arg2, arg3, arg4, arg5);
	#endif

	ret = orig_sys_prctl(option, arg2, arg3, arg4, arg5);
	return ret;
}

int hook_sys_chroot(const char * filename)
{
	int ret;

	security_check(__NR_chroot);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(filename) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_chroot);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> chroot(%s)\n", current->comm, filename);
	#endif

	ret = orig_sys_chroot(filename);
	return ret;
}

int hook_sys_mount(char * dev_name, char * dir_name, char * type, unsigned long new_flags, void * data)
{
	int ret;

	security_check(__NR_mount);

	#ifdef ENABLE_PATH_SANDBOXING
		if ((check_path_sandbox(dev_name) == SANDBOX_PATH_VIOLATION) || (check_path_sandbox(dir_name) == SANDBOX_PATH_VIOLATION))
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_mount);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> mount(%s, %s, %s, %lx, %p)\n", current->comm, dev_name, dir_name, type, new_flags, data);
	#endif

	ret = orig_sys_mount(dev_name, dir_name, type, new_flags, data);
	return ret;
}

int hook_sys_umount(char * name, int flags)
{
	int ret;

	security_check(__NR_umount);

	#ifdef ENABLE_PATH_SANDBOXING
		if (check_path_sandbox(name) == SANDBOX_PATH_VIOLATION)
		{
			detection_measure(PATH_SANDBOX_ALERT, __NR_umount);
		}
	#endif

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> umount(%s, %d)\n", current->comm, name, flags);
	#endif

	ret = orig_sys_umount(name, flags);
	return ret;
}

int hook_sys_reboot(int magic1, int magic2, int cmd, void * arg)
{
	int ret;

	security_check(__NR_reboot);

	#ifdef DEBUG_MODE_VERBOSE2
		printk(KERN_INFO "[DEBUG] '%s' -> reboot(%d, %d, %d, %p)\n", current->comm, magic1, magic2, cmd, arg);
	#endif

	ret = orig_sys_reboot(magic1, magic2, cmd, arg);
	return ret;
}

/*
	Initialization routine
*/
static int __init core_init(void)
{
    printk(KERN_INFO "[*] Initializing shield_core...\n");

    // Extract syscall table address for syscall hooking
    sys_call_table = (void**)SYSCALL_TABLE_SYMBOL;

    if (!sys_call_table) 
    {
        printk(KERN_INFO "[-] Could not find sys_call_table symbol...\n"); 
        return -1;
    }

    // Syscall hooking

	orig_sys_mprotect = sys_call_table[__NR_mprotect];
	sys_call_table[__NR_mprotect] = hook_sys_mprotect;

	orig_sys_mmap = sys_call_table[__NR_mmap];
	sys_call_table[__NR_mmap] = hook_sys_mmap;

	orig_sys_open = sys_call_table[__NR_open];
	sys_call_table[__NR_open] = hook_sys_open;

	orig_sys_execve = sys_call_table[__NR_execve];
	sys_call_table[__NR_execve] = hook_sys_execve;

	orig_sys_ioctl = sys_call_table[__NR_ioctl];
	sys_call_table[__NR_ioctl] = hook_sys_ioctl;

	orig_sys_exit = sys_call_table[__NR_exit];
	sys_call_table[__NR_exit] = hook_sys_exit;

	orig_sys_kill = sys_call_table[__NR_kill];
	sys_call_table[__NR_kill] = hook_sys_kill;

	orig_sys_mremap = sys_call_table[__NR_mremap];
	sys_call_table[__NR_mremap] = hook_sys_mremap;

	orig_sys_connect = sys_call_table[__NR_connect];
	sys_call_table[__NR_connect] = hook_sys_connect;

	orig_sys_shutdown = sys_call_table[__NR_shutdown];
	sys_call_table[__NR_shutdown] = hook_sys_shutdown;

	orig_sys_rename = sys_call_table[__NR_rename];
	sys_call_table[__NR_rename] = hook_sys_rename;

	orig_sys_mkdir = sys_call_table[__NR_mkdir];
	sys_call_table[__NR_mkdir] = hook_sys_mkdir;

	orig_sys_rmdir = sys_call_table[__NR_rmdir];
	sys_call_table[__NR_rmdir] = hook_sys_rmdir;

	orig_sys_creat = sys_call_table[__NR_creat];
	sys_call_table[__NR_creat] = hook_sys_creat;

	orig_sys_link = sys_call_table[__NR_link];
	sys_call_table[__NR_link] = hook_sys_link;

	orig_sys_unlink = sys_call_table[__NR_unlink];
	sys_call_table[__NR_unlink] = hook_sys_unlink;

	orig_sys_symlink = sys_call_table[__NR_symlink];
	sys_call_table[__NR_symlink] = hook_sys_symlink;

	orig_sys_chmod = sys_call_table[__NR_chmod];
	sys_call_table[__NR_chmod] = hook_sys_chmod;

	orig_sys_chown = sys_call_table[__NR_chown];
	sys_call_table[__NR_chown] = hook_sys_chown;

	orig_sys_lchown = sys_call_table[__NR_lchown];
	sys_call_table[__NR_lchown] = hook_sys_lchown;

	orig_sys_ptrace = sys_call_table[__NR_ptrace];
	sys_call_table[__NR_ptrace] = hook_sys_ptrace;

	orig_sys_setuid = sys_call_table[__NR_setuid];
	sys_call_table[__NR_setuid] = hook_sys_setuid;

	orig_sys_setgid = sys_call_table[__NR_setgid];
	sys_call_table[__NR_setgid] = hook_sys_setgid;

	orig_sys_prctl = sys_call_table[__NR_prctl];
	sys_call_table[__NR_prctl] = hook_sys_prctl;

	orig_sys_chroot = sys_call_table[__NR_chroot];
	sys_call_table[__NR_chroot] = hook_sys_chroot;

	orig_sys_mount = sys_call_table[__NR_mount];
	sys_call_table[__NR_mount] = hook_sys_mount;

	orig_sys_umount = sys_call_table[__NR_umount];
	sys_call_table[__NR_umount] = hook_sys_umount;

	orig_sys_reboot = sys_call_table[__NR_reboot];
	sys_call_table[__NR_reboot] = hook_sys_reboot;

    printk(KERN_INFO "[+] Installed shield_core!\n");
    return 0;
}

/*
	Cleanup routine
*/
static void __exit core_cleanup(void)
{
    printk(KERN_INFO "[*] Cleaning up shield_core...\n");
    
    // Syscall unhooking

    sys_call_table[__NR_mprotect] = orig_sys_mprotect;
    sys_call_table[__NR_mmap] = orig_sys_mmap;
    sys_call_table[__NR_open] = orig_sys_open;
    sys_call_table[__NR_execve] = orig_sys_execve;
	sys_call_table[__NR_ioctl] = orig_sys_ioctl;
	sys_call_table[__NR_exit] = orig_sys_exit;
	sys_call_table[__NR_kill] = orig_sys_kill;
	sys_call_table[__NR_mremap] = orig_sys_mremap;	
	sys_call_table[__NR_connect] = orig_sys_connect;
	sys_call_table[__NR_shutdown] = orig_sys_shutdown;
	sys_call_table[__NR_rename] = orig_sys_rename;
	sys_call_table[__NR_mkdir] = orig_sys_mkdir;
	sys_call_table[__NR_rmdir] = orig_sys_rmdir;
	sys_call_table[__NR_creat] = orig_sys_creat;
	sys_call_table[__NR_link] = orig_sys_link;
	sys_call_table[__NR_unlink] = orig_sys_unlink;
	sys_call_table[__NR_symlink] = orig_sys_symlink;
	sys_call_table[__NR_chmod] = orig_sys_chmod;
	sys_call_table[__NR_chown] = orig_sys_chown;
	sys_call_table[__NR_lchown] = orig_sys_lchown;
	sys_call_table[__NR_ptrace] = orig_sys_ptrace;
	sys_call_table[__NR_setuid] = orig_sys_setuid;
	sys_call_table[__NR_setgid] = orig_sys_setgid;
	sys_call_table[__NR_prctl] = orig_sys_prctl;
	sys_call_table[__NR_chroot] = orig_sys_chroot;
	sys_call_table[__NR_mount] = orig_sys_mount;
	sys_call_table[__NR_umount] = orig_sys_umount;
	sys_call_table[__NR_reboot] = orig_sys_reboot;

    printk(KERN_INFO "[+] Removed shield_core!\n");
    return;
}

module_init(core_init);
module_exit(core_cleanup);
