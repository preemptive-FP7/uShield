# Framepointer-Compliance: A few notes

----------

# Intro

Our primary and preferred approach for performing the stackframe integrity walk in our Kernel Protection Module (KPM) is by using the stackframe pointer (FP) and walking the stackframe chain upwards by dereferencing the linked list formed by it. In order for this to be possible, however, target applications and the libraries they load have to be compiled with framepointer support.

# Making applications 'framepointer-compliant'

Any application can be compiled to be 'framepointer-compliant' by simply using the "-fno-omit-frame-pointer" flag in GCC. When building an application from source using makefiles the CFLAGS/CXXFLAGS compiler flags have to be set as follows:

```bash
make CFLAGS='-fno-omit-frame-pointer' CXXFLAGS='-fno-omit-frame-pointer'
```

And one has to make sure these flags propagate through to any libraries compiled into the application as well (this is the case in eg. the Redis source). In order to guarantee FP-compliance the entire system has to be built with the '-fno-omit-frame-pointer' flag enabled.