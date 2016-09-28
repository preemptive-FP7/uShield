# Setup Module (SM): Installation & Usage Guide

----------

# Setup Module Baseline Check (SMBC): Intro

The Setup Module Basline Check (SMBC) serves to implement the following elements of our protection proposal:

* *kernel security baseline check*: Whether the current system's kernel meets our minimum security baseline.

* *application security baseline check*: Whether the target application meets our minimum security baseline.

Any kernel and (protected) applications that seek to make use of our solution should pass the SMBC.

## Installation & Usage

### Pre-Reqs

Make sure [pyelftools](https://github.com/eliben/pyelftools) is installed, eg. through [pwntools](pwntools.readthedocs.org/en/2.1.3/) or via `sudo pip install pyelftools`.

### Usage

In order to check kernel compliance run `python baselinecheck.py --system` and in order to check application compliance run `python baselinecheck.py --file target_application`.

# Setup Module FuncSpotter (SMFS): Intro

The Setup Module FuncSpotter (SMFS) serves to implement the following elements of our protection proposal:

* *Function prologue & epilogue instrumentation point identification*: Identifies functions in target binary, extracts prologues & epilogues and finds their instrumentation points.

* *Codepointer call instrumentation point identification*: Identifies codepointer calls within functions in target binary, extracts the call branch instrumentation points.

## Installation & Usage

### Pre-Reqs

Make sure to have IDA Pro 6.8 or newer installed. When installing IDA Pro make sure to install IDAPython as well and also make sure there is no other Python installation on the machine in question as these might cause conflicts.

### Usage

In order to run the SMFS on a target binary, load the binary into IDA and wait for its auto-analysis engine to finish. Now go to **File -> Script File -> select ida_funcspotter.py** and wait for it to finish running. You can see the output reporting harvesting results in the IDAPython console. A configuration file will have been auto-generated with the name `protect_config_<binary_name>.h` in the directory the loaded binary resides. The configuration file will look as follows:

```c
/*
	Hard-coded target addresses in lieu of configuration file parsing
*/

#define PROLOGUE_COUNT 5
#define EPILOGUE_COUNT 5
#define CPTRCALL_COUNT 2

arm_addr prologues[PROLOGUE_COUNT] = {0x600,0x64c,0x698,0x6e4,0x768};
arm_addr epilogues[EPILOGUE_COUNT] = {0x640,0x68c,0x6d8,0x760,0x7d0};
arm_addr cptrcalls[CPTRCALL_COUNT] = {0x724,0x794};
```