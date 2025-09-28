+++
title = "mobilehackinglab: Ai Accelerator kernel challenge writeup"
date = "2025-08-31T19:57:56+05:30"
author = "IamAlch3mist"
authorTwitter = "" #do not include @
cover = ""
tags = ["mobilehackinglab", "android-kernel", "exploit-development"]
keywords = ["", ""]
description = ""
showFullContent = false
readingTime = true
hideComments = false
color = "purple" #color from the theme settings
draft = true
+++

**The whole secret lies in confusing the enemy, so that he cannot fathom our real intent** - Sun Tzu 

# Introduction 

I came across the post from mobilehackinglab an android kernel exploitation challenge and unsolved at defcon, (challenge accepted) having solved the previous challenge, but at the time the challenge dropped I'm touching grass in a remote location almost for a week so I couldn't spend time on the challenge, until 3 later I came home and endup solving it.  

[image from mobile hacking lab linkedin post]

AI slop free article 😄 

These are the files in the given archive along with some instructions. 

[image 1]



```
# INSTRUCTIONS.md

The challenge source code is located at ./kernel/drivers/char/ai/

A debug environment has been provided to develop your exploit.

Kernel hashes and config files for both remote and debug environment is also provided.

NOTE: selinux is NOT turned on in the debug kernel, but it is available in the remote corellium device

Debug environment creds
- mhl:hacker
- root:toor

Copy files into debug env using scp
- `scp -P10023 'exploit' 'mhl@localhost:/home/mhl/exploit'`

On remote flag file is located at /data/local/tmp/root/flag.txt
```

As mentioned in the instructions at kernel/drivers/char/ai we can find the kernel driver but the Makefile at char have the following line. The driver is compiled as an intree module within the kernel.  

```Makefile
obj-y += ai/
```

# Vulnerability Analysis ai_accel driver

```c
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/anon_inodes.h>
#include <linux/random.h>

#define DEVICE_NAME "ai_accel"
#define CLASS_NAME "ai_accel"

#define MAX_JOBS 0x50
#define MAX_BATCH_SIZE 1024
#define MAX_INPUT_SIZE 0x1000

#define CREATE_JOB   0X1337001
#define RUN_JOB      0X1337002
#define GET_FEEDBACK 0X1337003
#define STOP_JOB     0x1337004

#define READY 1
#define DONE  2

struct ai_job {
  uint32_t accel_id;
  uint32_t model_type;
  uint32_t batch_size;
  uint32_t input_length;
  void* buffer;
  struct task_struct *kthread;
  int32_t status;
} __packed;

struct ai_job_params {
  uint32_t model_type;
  uint32_t batch_size;

  uint32_t accel_id;
  void* buffer;
  uint32_t length;
};

static struct ai_job *jobs[MAX_JOBS];

static int major;
static struct class* mhc_class = NULL;
static struct device* mhc_device = NULL;

static long mhc_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    long ret = -1;
    char user_buffer[0x500];
    struct ai_job *job = 0;
    struct ai_job_params* params = (struct ai_job_params*)&user_buffer;


    if (copy_from_user(params, (void*)arg, sizeof(struct ai_job_params)))
      goto leave;

    if (params->accel_id >= MAX_JOBS)
        goto leave;

    switch (cmd) {
      case CREATE_JOB: {
        if (jobs[params->accel_id]) {
          printk(KERN_ERR "ai accel: Job is busy\n");
          goto leave;
        }

        if (params->batch_size == 0 || params->batch_size > MAX_BATCH_SIZE)
          goto leave;

        job = (struct ai_job*)kmalloc(sizeof(struct ai_job), GFP_KERNEL_ACCOUNT);
        if (job == 0)
          goto leave;

        job->accel_id = params->accel_id;
        job->model_type = params->model_type;
        job->batch_size = params->batch_size;
        job->kthread = (void*)current;
        job->buffer = NULL;
        job->status = READY;

        jobs[job->accel_id] = job;
        ret = job->accel_id;

        break;
      }
      case RUN_JOB: {
        if (!jobs[params->accel_id]) {
          printk(KERN_ERR "ai accel: Job doesn't exist\n");
          goto leave;
        }

        if (params->length == 0 || params->length > MAX_INPUT_SIZE) {
          printk(KERN_INFO "params->length %d\n", params->length);
          goto leave;
        }

        job = jobs[params->accel_id];
        job->input_length = params->length;

        if (!job->buffer)
          job->buffer = kmalloc(job->input_length, GFP_KERNEL_ACCOUNT);

        if (params->buffer) {
          if (copy_from_user(job->buffer, params->buffer, job->input_length)) {
            kfree(job->buffer);
            goto leave;
          }

          job->status = DONE;
          goto leave;
        }

        // The run job operation is "under development"

        break;
      }
      case GET_FEEDBACK: {
        if (!jobs[params->accel_id]) {
          printk(KERN_ERR "ai accel: Job doesn't exist\n");
          goto leave;
        }

        job = jobs[params->accel_id];

        if (params->length > MAX_INPUT_SIZE) {
          goto leave;
        }

        if (copy_to_user(params->buffer, job->buffer, params->length)) {
          printk(KERN_ERR "ai accel: Copy failed\n");
        }

        break;
      }
      case STOP_JOB: {
        if (!jobs[params->accel_id]) {
          printk(KERN_ERR "ai accel: Job doesn't exist\n");
          goto leave;
        }

        job = jobs[params->accel_id];

        if (job->buffer)
          kfree(job->buffer);
        kfree(job);
        break;
      }
      default:
        printk(KERN_ERR "ai accel: Invalid command\n");
    }

leave:
    return ret;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = mhc_ioctl,
};


static const struct proc_ops proc_fops = {
    .proc_ioctl = mhc_ioctl,
};


static int __init mhc_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    if (major < 0) {
        printk(KERN_ALERT "[mhc] Failed to register char device\n");
        return major;
    }

    mhc_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(mhc_class)) {
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "[mhc] Failed to create class\n");
        return PTR_ERR(mhc_class);
    }


    mhc_device = device_create(mhc_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    if (IS_ERR(mhc_device)) {
        class_destroy(mhc_class);
        unregister_chrdev(major, DEVICE_NAME);
        printk(KERN_ALERT "[mhc] Failed to create device\n");
        return PTR_ERR(mhc_device);
    }


    printk(KERN_INFO "[mhc] Module loaded: /dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit mhc_exit(void) {
    device_destroy(mhc_class, MKDEV(major, 0));
    class_unregister(mhc_class);
    class_destroy(mhc_class);
    unregister_chrdev(major, DEVICE_NAME);

    printk(KERN_INFO "[mhc] Module unloaded\n");
}

module_init(mhc_init);
module_exit(mhc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Hack the Kernel");
MODULE_DESCRIPTION("Hack All the Kernels");
```

A heap note in kernel noice. 

`mhc_init` function creates the entry in /proc as /proc/ai_accel with with the `mhc_ioctl` callback for unlocked_ioctl.  

mhl_ioctl have a case statement of `CREATE_JOB` which creates an object of type ai_job in heap memory, the object have a member kthread which looks intresting it is set to [current](https://elixir.bootlin.com/linux/v5.15.41/source/arch/arm64/include/asm/current.h#L24) which returns the task_struct of the userland process calling it. Another member called buffer a void pointer set to null. Each time ai_job object gets allocated the pointer is stored in jobs array  with the array length being 80 and the line prevents oob access. 

```
if (params->accel_id >= MAX_JOBS)
```

# BUG 1: heap OOB write at RUN_JOB 
`RUN_JOB` allocates memory in heap and the pointer is set to buffer member in the ai_job object which is allocated in `CREATE_JOB` case. There is no overflow at this stage from copy_from_user since the right amount of data is copied to the heap :)  the input_length is attacker controlled but no inter bugs to trick it into a heap overflow. Then copies the user supplied data into the heap buffer. 

At line 4 the buffer member of ai_job object is checked for value if it's null then it allocates the memory using kmalloc with the attacker controlled length. If we call RUN_JOB once again with the same acel_id but with different length member the condition fails and writes OOB in heap at line 7 because it uses the existing allocation with the length we supplied in our second call which is larger than than the allocation. At exploitation phase we look into it with more detail. 


```c
1.        job = jobs[params->accel_id];
2.        job->input_length = params->length;
3.
4.        if (!job->buffer)
5.          job->buffer = kmalloc(job->input_length, GFP_KERNEL_ACCOUNT);

6.        if (params->buffer) {
7.          if (copy_from_user(job->buffer, params->buffer, job->input_length)) {
8.            kfree(job->buffer);
9.            goto leave;
10.          }
```

We can make arbitrary size of allocations under 4096 bytes now you know where this going. 

# BUG 2: heap OOB read at GET_FEEDBACK

`GET_FEEDBACK` case is much simpler it copies the data from the heap memory allocated at RUN_JOB case, buffer member contains the data we copied at RUN_JOB. The length member is attacker controlled and only check is greater than MAX_INPUT_SIZE which is 4096 bytes. If the allocation at RUN_JOB is smaller than 4096 bytes by using GET_FEEDBACK we get OOB read. 

```c
        if (params->length > MAX_INPUT_SIZE) {
        
        if (copy_to_user(params->buffer, job->buffer, params->length)) 
```

# BUG 3: use-after-free at STOP_JOB
The UAF is straight forward, the ai_obj object allocated at CREATE_JOB and memory allocated at RUN_JOB is being freed but didn't set to null ended up as an dangling pointer. We can use the freed memory at RUN_JOB and GET_FEEDBACK case leads to UAF. Only condition we require to tigger is the buffer member in RUN_JOB needs to be allocated. 

```c
        job = jobs[params->accel_id];

        if (job->buffer)
                kfree(job->buffer);
        kfree(job);

        break;
```

# BUG 4: double free at STOP_JOB
If we call STOP_JOB again it frees the memory again which turns into double free, right now it can only cause a DOS. 
```c
        kfree(job->buffer);
        kfree(job);
```

# POC or Get The Fuck Off  

There are different ways to exploit this driver, I originally solved by combining the UAF and OOB R/W to acheive AAR/W primitive and overwrite cred data structure. 


I modified the cpu field from cortex-a55 to cortex-a53 in the provided run.sh script, the qemu version I'm using (with some custom instrumentation - which is a toppic for a different blog) doesn't have support for a55 cpu and I don't wan't to compile new one just for this challenge so I patched the script. (Later I tested with my work computer with A55 cpu, my exploit worked without changing anything)

```bash
qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a53 \
  -nographic -smp 2 \
  -hda ./rootfs.ext2 \
  -kernel ./kernel/arch/arm64/boot/Image \
  -append "console=ttyAMA0 root=/dev/vda nokaslr quiet" \
  -m 2048 \
  -net user,hostfwd=tcp::10023-:22 -net nic \
  -s
```

The start script is very generic it starts an emulated instance of the kernel with a minimal file system, there is no SMAP, SMEP, KASLR or PAC mitigation to deal with. 

A simple poc which calls CREATE_JOB and allocates ai_job object.  
```

```
