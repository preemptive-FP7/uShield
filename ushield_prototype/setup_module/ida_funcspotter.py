#!/usr/bin/env python

"""
uShield Setup Module FuncSpotter (SMFS) - IDAPython version
(c) Jos Wetzels & Wouter Bokslag

Identifies function instrumentation points for uShield Runtime Protection Module (RPM)
"""


from idautils import *
from idaapi import *

# We consider a callsite suitable iff it is a codepointer call, ie. a register-relative branch of the form BLX Rx
def extract_cptr_instrumentation_points(func_ea):
	func_blacklist = ['__libc_csu_init', '__libc_csu_fini', '_init', 'frame_dummy', '__do_global_dtors_aux']

	if (GetFunctionName(func_ea) in func_blacklist):
		return []

	cptr_points = []

	# Iterate over all calls within function
	ins_addrs = list(FuncItems(func_ea))
	for ins_address in ins_addrs:
		if (is_call_insn(ins_address)):
			# Has to be of form BLX Rx
			if ((GetMnem(ins_address) == 'BLX') and (GetOpnd(ins_address, 0)[0] == 'R')):
				cptr_points.append(ins_address)

	return cptr_points

def is_valid_epilogue(epilogue_ins):
	if ((GetMnem(epilogue_ins) == 'LDM') and (GetOpnd(epilogue_ins, 0) == 'SP!') and ('PC' in GetOpnd(epilogue_ins, 1))):
		return True

	return False

# We consider a function suitable iff it a) is returning b) has properly-formatted prologues and epilogues
# Properly formated prologues have push {..., lr} as their first instruction while properly formatted epilogues are validated by is_valid_epilogue_block
# This is not a limitation of our approach so much as of our current prototype implementation
def extract_shadow_instrumentation_points(func_ea, prologue_size_threshold):
	func_blacklist = ['__libc_csu_init', '__libc_csu_fini', '_init', 'frame_dummy', '__do_global_dtors_aux']

	if (GetFunctionName(func_ea) in func_blacklist):
		return False, 0, []

	prologue_point = 0
	epilogue_points = []

	func_flags = GetFunctionFlags(func_ea)

	if ((func_flags & FUNC_NORET) or (func_flags & FUNC_LIB)):
		return False, 0, []

	ins_addrs = list(FuncItems(func_ea))

	# First push {..., lr} we encounter within prologue size threshold is the prologue instrumentation point
	for ins_address in ins_addrs[0: prologue_size_threshold]:
		# We require form STM.. SP!, {..., lr}
		if ((GetMnem(ins_address) == 'STM') and (GetOpnd(ins_address, 0) == 'SP!') and ('LR' in GetOpnd(ins_address, 1))):
			prologue_point = ins_address
			break

	if (prologue_point == 0):
		return False, 0, []

	# There can be multiple epilogues for a single function, all have to be valid for a function to be considered suitable
	# Unlike with angr we don't have pre-identified epilogues derived from intra-function codeflow so we'll identify them ourselves
	# through walking the function's disassembly

	for ins_address in ins_addrs:
		if is_valid_epilogue(ins_address):
			epilogue_points.append(ins_address)

	# Need at least one valid epilogue
	if (len(epilogue_points) == 0):
		return False, 0, []

	return True, prologue_point, epilogue_points

# Main harvesting function
def harvest_functions(image_base, prologue_size_threshold):
	print "[*] Identifying functions for harvest..."

	prologue_instrumentation_points = []
	epilogue_instrumentation_points = []
	cptr_instrumentation_points = []

	ea = BeginEA()
	for func_ea in Functions(SegStart(ea), SegEnd(ea)):
		# Determine if function is suitable and if so extract prologue / epilogue instrumentation points
		r, prologue_point, epilogue_points = extract_shadow_instrumentation_points(func_ea, prologue_size_threshold)

		if (r):
			# Points are relative to the base
			prologue_point -= image_base
			epilogue_points = [(x - image_base) for x in epilogue_points]

			print "[+] Harvested function '%s': prologue point %s, epilogue points [%s]" % (GetFunctionName(func_ea), hex(prologue_point).strip('L'), ','.join([hex(x).strip('L') for x in epilogue_points]))

			prologue_instrumentation_points.append(prologue_point)
			epilogue_instrumentation_points += epilogue_points

		# Determine if function is suitable and if so extract cptr instrumentation points
		cptr_points = extract_cptr_instrumentation_points(func_ea)
		if (len(cptr_points) > 0):
			cptr_points = [(x - image_base) for x in cptr_points]

			print "[+] Harvested function '%s': codepointer points [%s]" % (GetFunctionName(func_ea), ','.join([hex(x).strip('L') for x in cptr_points]))
			cptr_instrumentation_points += cptr_points

	return prologue_instrumentation_points, epilogue_instrumentation_points, cptr_instrumentation_points

# Top routine
def do_harvest(prologue_size_threshold):
	print "[*] uShield FuncSpotter\n(c) Jos Wetzels & Wouter Bokslag"

	image_base = get_imagebase()

	if (image_base == 0):
		print "[-] Invalid ELF.image_base..."
		return

	print "[+] ELF.image_base: 0x%x" % image_base

	# Harvest prologue, epilogue and codepointer call points from all suitable functions	
	return harvest_functions(image_base, prologue_size_threshold)

def generate_ushield_rpm_config_file(filename, prologue_points, epilogue_points, cptr_points):
	print "[*] Generating uShield RPM config file..."

	prologue_count = len(prologue_points)
	epilogue_count = len(epilogue_points)
	cptrcall_count = len(cptr_points)

	prologue_points_str = ','.join([hex(x).strip('L') for x in prologue_points])
	epilogue_points_str = ','.join([hex(x).strip('L') for x in epilogue_points])
	cptrcall_points_str = ','.join([hex(x).strip('L') for x in cptr_points])

	config_data = """/*
	Hard-coded target addresses in lieu of configuration file parsing
*/

#define PROLOGUE_COUNT %d
#define EPILOGUE_COUNT %d
#define CPTRCALL_COUNT %d

arm_addr prologues[PROLOGUE_COUNT] = {%s};
arm_addr epilogues[EPILOGUE_COUNT] = {%s};
arm_addr cptrcalls[CPTRCALL_COUNT] = {%s};""" % (prologue_count, epilogue_count, cptrcall_count, prologue_points_str, epilogue_points_str, cptrcall_points_str)

	open(filename, 'wb').write(config_data)

	print "[+] Done!"
	return

prologue_size_threshold = 10
store_dir = "./"
filename = "protect_config_" + get_root_filename() + ".h"
p, e, c = do_harvest(prologue_size_threshold)
generate_ushield_rpm_config_file(store_dir + filename, p, e, c)