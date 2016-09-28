# Embedded exploitation environment: Setup Guide

----------

# Getting the distro

The EET was developed on a [Raspberry Pi 1 Model B](https://www.raspberrypi.org/products/model-b/) and is intended to run on [Raspbian Jessie Lite (version February 2016, 2016-02-26, kernel 4.1)](https://downloads.raspberrypi.org/raspbian_lite/images/raspbian_lite-2016-02-09/2016-02-09-raspbian-jessie-lite.zip) (md5: 784b9ddd392fb735f37a04061a8fd240). The raspbian image was written to an SD card using [Win32DiskImager](https://sourceforge.net/projects/win32diskimager/).

# First-boot configuration

Upon first boot go through the following steps:

```bash
apt-get update
apt-get install nano sudo rpi-update raspi-config usbutils dosfstools -y
apt-get remove initramfs-tools -y
```

Start `raspi-config` and choose option 7 (overclock) and set to `Moderate 800 MHz` for Pi 1 B+ and later then go to option 1 (expand fs) and choose OK and reboot.

Proceed to update to the latest firmware by executing `rpi-update` and rebooting

# rpi-source

We need to obtain the kernel source as follows so we can build kernel modules:

```bash
rpi-source
sudo wget https://raw.githubusercontent.com/notro/rpi-source/master/rpi-source -O /usr/bin/rpi-source && sudo chmod +x /usr/bin/rpi-source && /usr/bin/rpi-source -q --tag-update
rpi-source --skip-gcc
sudo apt-get install build-essential
```

# Finalizing

Make sure your environment checks result in the following:

```bash
$ uname -a
Linux raspberrypi 4.1.17+ #838 Tue Feb 9 12:57:10 GMT 2016 armv6l GNU/Linux
$ gcc --version
gcc (Raspbian 4.9.2-10) 4.9.2
Copyright (C) 2014 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
```