# Kernel Protection Module (KPM): Installation & Usage Guide

----------

# Intro

The Kernel Protection Module (KPM) serves to implement the following elements of our protection proposal:

* *Sandbox mechanism*: Syscall and path sandbox checking
* *Memory protection mechanism*: Memory protection policy validation
* *Heuristics*: Stack pivot checking and stackframe integrity validation

It effectively implements our 'basic' level of protection.

The KPM logs its alerts to the kmesg kernel information log pseudo-file which can be viewed using the `dmesg` command.

# Pre-Reqs

## Distro

Follow the distro setup steps in the environment setup guide.

# Installing and using the KPM

## Configuring the KPM

The first step of configuring the KPM is adding the correct syscall table address manually as the corresponding symbol is no longer exported by modern kernels and our prototype does not have a routine for automatic detection. Execute the following:

```bash
sudo cat /proc/kallsyms | grep sys_call_table
c000f708 T sys_call_table
```

Then in `shield_core.c` set the following variable to the adequate value:

```c
#define SYSCALL_TABLE_ADDR 0xc000f708
```

Next we configure whether we want some features turned on or off:

```c
#define DEBUG_MODE

#ifdef DEBUG_MODE
	//#define DEBUG_MODE_TECHNICAL
	//#define DEBUG_MODE_VERBOSE
	//#define DEBUG_MODE_VERBOSE2
#endif

#define BACKWARD_EDGE_PROTECTION
#define ENABLE_PATH_SANDBOXING
#define ENABLE_DEPTH_ALERT
//#define MULTI_THREAD_TEST
//#define SUPPRESS_ALERTS
//#define FULL_FP_COMPLIANCE
```

In the above `DEBUG_MODE` specifies whether we get any kind of debug logging with `DEBUG_MODE_VERBOSE` and `DEBUG_MODE_VERBOSE2` being verbose and very verbose logging respectively and `DEBUG_MODE_TECHNICAL` enabling technical debug logging (including a program state dump) for every raised alert. `BACKWARD_EDGE_PROTECTION` specifies whether we want to enable the stackframe integrity walker's backward-edge CFI protection. `ENABLE_PATH_SANDBOXING` determines whether we enable the path sandboxing feature and `ENABLE_DEPTH_ALERT` determines whether we treat stackframe integrity walks which exceed maximum depth `MAX_STACKFRAMEWALK_DEPTH` as alerts.

The experimental option `MULTI_THREAD_TEST` allows for partial application (eg. the memory protection, sandboxing and pivot-detection parts) of the module to multi-threaded applications but is disabled by default. Similarly the `FULL_FP_COMPLIANCE` option is to be enabled only when all protected applications and their loaded libraries on the system the module is being run on are compliant with the framepointer-preservation option. If this is not the case (either because the system is a test system for overhead testing or the protected applications are configured to use unwinding-based or dataflow-based framewalking) the option should be disabled in order to avoid false positives.

The final option is `SUPPRESS_ALERTS` which suppresses the alerting function and should only be enabled during overhead testing as writing to output incurs overhead not corresponding to the actual detection algorithm. Similarly all debugging should be disabled for overhead testing.

Now we configure the KPM's event-logging parameters:

```c
#define DETECT_MEASURE "log"

#define CEF_TOOL_IP "192.168.0.102"
#define CEF_DVC_HOST "rpi"
#define CEF_DEVICE_NUM DEV_PLC
```

Here `CEF_TOOL_IP` and `CEF_DVC_HOST` are hardcoded rather than dynamically fetched because, again, our prototype serves demonstration purposes. The `CEF_DEVICE_NUM` value can be set to the type of ICS device we are protecting. The `DETECT_MEASURE` value determines the measure the KPM takes upon detecting an attack. Currently we only support logging.

## Heuristics thresholds configuration

There are two heuristics treshold values that can be freely configured:

```c
#define MAX_TRAMPOLINE_GADGET_SIZE
#define TRAMPOLINE_THRESHOLD
```

The `MAX_TRAMPOLINE_GADGET_SIZE` value indicates the maximum trampoline gadget size in instructions and the `TRAMPOLINE_THRESHOLD` value indicates the maximum trampoline gadget count threshold. Currently these values are set to rather arbitrary values considering the determination of suitable values (that is, the lowest values for which there are no false positives) is left to the future work of writing the academic paper. The current values are demonstration values.

## Adding an application to the protection mechanisms

In order to add an application to the KPM's protection list one adds it as an entry to the `protected_apps` array. Make sure to set the `PROTECTED_APP_COUNT` constant accordingly:

```c
#define PROTECTED_APP_COUNT 2

const protected_app protected_apps[PROTECTED_APP_COUNT] = {
	{ "stack_buffer_overflow_1", FP_BASED_WALKER, 1, { __NR_mprotect, __NR_mmap, __NR_open }, 4, 0, {}, 0 },
	{ "framewalk", FP_BASED_WALKER, 1, { __NR_mprotect, __NR_mmap, __NR_open }, 4, 1, {"/"}, 1 }
};
```

The format of each entry is as follows:

```c
{ "process_name", integrity_walker_type, has_syscall_sandbox, {whitelisted_syscall_0, whitelisted_syscall_1}, syscall_whitelist_count, has_path_sandbox, {whitelisted_path_0}, path_whitelist_count}
```

Figuring out the whitelisted syscalls and paths is currently a manual effort in the absence of the accompanying setup module but should be trivial (for example running `strace target_app`) for the demonstration and testing applications we use. Do note that if one wants to test all heuristics it might be opportune to simply turn of sandboxing for that application (by setting `has_syscall_sandbox = 0` and `has_path_sandbox = 0`) to see whether protections other than the sandbox catch the attack.

For integrity walking only the FP_BASED_WALKER option is supported in the prototype. For overhead testing we recommend lines like these where sandboxing is disabled:

```c
{ "redis-server", FP_BASED_WALKER, 0, {}, 0, 0, {}, 0 }
```

## Building the KPM

Building the KPM is as simple as cd'ing to the appropriate directory and running `make`. If things don't work out check these resources: [1](http://stackoverflow.com/questions/20167411/how-to-compile-a-kernel-module-for-raspberry-pi), [2](https://www.grendelman.net/wp/compiling-kernel-modules-for-raspbian-raspberry-pi/), [3](http://elinux.org/Raspberry_Pi_Kernel_Compilation#Build_modules_for_the_running_kernel)

## Starting the KPM

After it is built the KPM is started/loaded as follows:

```bash
sudo insmod ./shield_core.ko
```

Its insertion can be verified as follows:

```bash
lsmod | grep "shield_core"
modinfo ./shield_core.ko
```

The KPM can be stopped/unloaded as follows:

```bash
sudo rmmod ./shield_core.ko
```

## Testing the KPM

When testing the KPM its output, whether debugging-related (if enabled) or alerts, is logged to the kernel message log which can be inspected as follows:

```bash
sudo dmesg | tail -n 20
```

As an example, consider running `uaf_exploit.py` against the UAF-vulnerable service included with the EET. The KPM will detect the attack with the following output:

```bash
$ sudo dmesg | tail -n 20
[ 5060.444931] [*] Initializing shield_core...
[ 5060.445053] [+] Installed shield_core!
[ 5068.959806] [!] ..:: [SHIELD_CORE ALERT] ::..
[ 5068.959905] [!] [2016 03 14  00:36:23 192.168.0.102 CEF:0 | 5 | 1 | 1 | 1 | Exploitation of memory corruption vulnerability | 7 | dvchost=rpi dvcpid=4916 deviceProcessName=use_after_free outcome=log message=Heuristics (stack pivot detected)]
[ 5068.959930] [!] ..:: [SHIELD_CORE ALERT] ::..
[ 5068.959959] [!] [2016 03 14  00:36:23 192.168.0.102 CEF:0 | 5 | 1 | 1 | 1 | Exploitation of memory corruption vulnerability | 7 | dvchost=rpi dvcpid=4916 deviceProcessName=use_after_free outcome=log message=Memory protection violation]
[ 5068.960051] [!] ..:: [SHIELD_CORE ALERT] ::..
[ 5068.960090] [!] [2016 03 14  00:36:23 192.168.0.102 CEF:0 | 5 | 1 | 1 | 1 | Exploitation of memory corruption vulnerability | 7 | dvchost=rpi dvcpid=4916 deviceProcessName=use_after_free outcome=log message=Heuristics (stack pivot detected)]
```

Note that every trigger gets logged even if there are multiple ones for the same process. This helps strengthen any correlation-based detection which could weigh alert-events differently per heuristic trigger according to eg. potential impact or false positive likelihoods.