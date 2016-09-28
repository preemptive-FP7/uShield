#!/usr/bin/env python

"""
BaselineCheck
(c) Jos Wetzels, Wouter Bokslag

This script checks whether the system it's executed on conforms to the established minimum security baseline and/or whether a target application conforms to it.
Code partially inspired by Tobias Klein's checksec.sh (http://www.trapkit.de/tools/checksec.html) and Dhiru Kholia's python port (https://github.com/kholia/checksec)
"""

import re
import argparse

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.common.py3compat import bytes2str
from elftools.elf.constants import P_FLAGS
from elftools.elf.dynamic import DynamicSection

STACK_CHK = set(["__stack_chk_fail", "__stack_smash_handler"])

# Check CPU NX support
def cpu_nx_check():
	return ((' nx ' in open('/proc/cpuinfo').read()) or ('ARMv6' in open('/proc/cpuinfo').read()))

# Check Kernel ASLR support
def kernel_aslr_check():
	# PaX ASLR check
	ps = re.findall('PaX:.*R', open('/proc/1/status').read())
	if (ps):
		return True
	# kernel.randomize_va_space check
	else:
		rvs = int(open('/proc/sys/kernel/randomize_va_space').read())
		if(rvs == 2):
			return True
		else:
			# randomize_va_space = 1 is insufficient (doesn't randomize heap)
			return False

# Check system baseline
def check_system_baseline(baseline):
	return not(False in [x() for x in baseline])

# Check app NX protection
def app_nx_check(elffile):
	pflags = P_FLAGS()
	if elffile.num_segments() == 0:
		return False

	found = False
	for segment in elffile.iter_segments():
		if re.search('GNU_STACK', str(segment['p_type'])):
			found = True
			if segment['p_flags'] & pflags.PF_X:
				return False
	if found:
		return True
	return False

# Check app stack cookie protection
def stack_cookies_check(elffile):
	for section in elffile.iter_sections():
		if not isinstance(section, SymbolTableSection):
			continue
		if section['sh_entsize'] == 0:
			continue
		for _, symbol in enumerate(section.iter_symbols()):
			if bytes2str(symbol.name) in STACK_CHK:
				return True
	return False

# Check app full relro protection
def full_relro_check(elffile):
	if elffile.num_segments() == 0:
		return False

	have_relro = False
	for segment in elffile.iter_segments():
		if re.search('GNU_RELRO', str(segment['p_type'])):
			have_relro = True
			break

	for section in elffile.iter_sections():
		if not isinstance(section, DynamicSection):
			continue

		for tag in section.iter_tags():
			if tag.entry.d_tag == 'DT_BIND_NOW':
				return have_relro # (have_relro && have_bindnow)

	return False

# Check app baseline
def check_app_baseline(elffile, baseline):
	return not(False in [x(elffile) for x in baseline])

# Command-line argument parsing functionality
class arg_parser(argparse.ArgumentParser):
    def error(self, message):
        print "[-]Error: %s\n" % message
        self.print_help()
        exit()

# Command-line argument parser
def get_arg_parser():
	header = ""

	parser = arg_parser(description=header)	
	parser.add_argument('--file', dest='filename_check', help='filename to check')
	parser.add_argument('--system', dest='system_check', help='check system', action='store_true')

	return parser

system_baseline = [kernel_aslr_check, cpu_nx_check]
app_baseline = [app_nx_check, stack_cookies_check, full_relro_check]

parser = get_arg_parser()
args = parser.parse_args()

if (args.system_check):
	if (check_system_baseline(system_baseline)):
		print "[+] System status: OK"
	else:
		print "[-] System status: Minimum Security Baseline not met"

if (args.filename_check):
	filename = args.filename_check
	with open(filename, 'rb') as f:
		elffile = ELFFile(f)
		if(check_app_baseline(elffile, app_baseline)):
			print "[+] '%s' status: OK" % args.filename_check
		else:
			print "[+] '%s' status: Minimum Security Baseline not met" % args.filename_check