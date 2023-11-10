- [Introduction](#introduction)
- [安全教程](#安全教程)
- [安全论坛|博客](#安全论坛博客)
- [漏洞分析](#漏洞分析)
  - [网络设备漏洞分析](#网络设备漏洞分析)
  - [摄像头漏洞分析](#摄像头漏洞分析)
  - [智能家居漏洞分析](#智能家居漏洞分析)
  - [嵌入式/物联网设备漏洞分析](#嵌入式物联网设备漏洞分析)
- [固件分析](#固件分析)
- [无线电安全](#无线电安全)
- [硬件安全](#硬件安全)
- [模糊测试](#模糊测试)
- [工具使用](#工具使用)
- [安全论文](#安全论文)
- [会议](#会议)
  - [国内会议](#国内会议)
  - [国外会议](#国外会议)
- [CTF](#ctf)
- [安全报道](#安全报道)
- [开源安全项目](#开源安全项目)
- [车联网安全](#车联网安全)
- [漏洞情报库](#漏洞情报库)
- [其他](#其他)


# Introduction

收集一些与IoT安全有关的安全文章、教程、资料等url资源，供大家一起学习!

- 旧的文章项目地址：https://github.com/H4lo/IOT_Articles_Collection

# 安全教程
[Preface - heap-exploitation](https://heap-exploitation.dhavalkapil.com/)
- 摘要: 这本书的第一部分详细描述了堆内部的情况，简洁明了。第二部分涵盖了一些最著名的攻击。假设读者对这个主题不熟悉。对于有经验的读者来说，这本书可能适合快速复习。

https://mp.weixin.qq.com/s/L3bkD7nuZdDdBQ7DJ4Q-ew

https://mp.weixin.qq.com/s/jZd5BpAmwFZOZuNjc4-oqA

https://mp.weixin.qq.com/s/jZd5BpAmwFZOZuNjc4-oqA

[About the book - A Noob's Guide To ARM Exploitation](https://ad2001.gitbook.io/a-noobs-guide-to-arm-exploitation/)

[Introduction · Reverse Engineering](https://0xinfection.github.io/reversing/)

[使用Binary Ninja进行IoT设备漏洞挖掘](https://dawnslab.jd.com/binaryninja1-zh-cn/)

https://forum.defcon.org/node/241835, https://github.com/infobyte/cve-2022-27255

https://mp.weixin.qq.com/s/JT_HCfSS7bpgutk3v2ApNQ

https://mp.weixin.qq.com/s/7cdt5lCmU5ufucUasaKVZA

https://www.s3.eurecom.fr/docs/usenixsec22_arbiter.pdf

[Parsing JSON is a Minefield](https://seriot.ch/projects/parsing_json.html)

https://www.4hou.com/search-post?keywords=深入考察JSON在互操作性方面的安全漏洞，

https://github.com/KathanP19/HowToHunt

# 安全论坛|博客
[Quarkslab's blog](https://blog.quarkslab.com/index.html)

[CTF导航 | 分享CTF、IOT、ICS、Car相关内容](https://www.ctfiot.com/)

https://xz.aliyun.com/

[unSafe.sh - 不安全](https://unsafe.sh/)

[talos](https://blog.talosintelligence.com/)

[ssd-disclosure](https://ssd-disclosure.com/advisories-archive/)

[nccgroup](https://research.nccgroup.com/)

[UFA-通用固件分析
[Zyxel firmware extraction and password analysis - hn security](https://security.humanativaspa.it/zyxel-firmware-extraction-and-password-analysis/)
系统](https://ufa.360.net/home)

[unblob - extract everything!](https://unblob.org/)

[2022看雪安全开发者峰会 - Hack Inn](https://www.hackinn.com/index.php/archives/808/)

[IOTsec-Zone 安全社区](https://iotsec-zone.com/article?id=314)

[CYS4 | Blog](https://blog.cys4.com/)

[Cymetrics Tech Blog](https://tech-blog.cymetrics.io/en/)

[Page non trouvÃ©e](https://www.synacktiv.com/publications%3Ffield_tags_target_id%3D3.html)

[James Kettle Research Overview](https://skeletonscribe.net/)

[Flatt Security Blog](https://blog.flatt.tech/)

[安全客 - 安全资讯平台](http://anquanke.com)

# 漏洞分析
## 网络设备漏洞分析
https://github.com/ea/lytro_unlock
- 摘要: 根据新的背景信息，我们可以对原始摘要进行完善。

这个项目涉及到对Lytro光场相机进行逆向工程，并创建一个Python库，以解锁官方软件中不可用的额外功能。这些功能包括远程相机控制、实时视图流传输、调试控制台和自定义代码执行。Lytro相机虽然作为商业产品不成功，但其具有高倍数光学变焦等有趣的技术。目标是为潜在的创新用途提供对相机的完全软件控制。相机可以在eBay上以折扣价购买，并且使用该库不需要进行任何物理修改。然而，这样做有砖机和失去保修的风险。该项目受到了一个关于技术项目缺陷和失败的Twitter讨论串的启发。作者的目标是为Lytro相机实现类似网络摄像头的功能，如软件控制的变焦和对焦、按需拍照，以及可能的固件修改和实时视图/视频流传输。摘要还提供了相机硬件和固件分析的概述，包括发现了一个命令解释器代码，通过USB或WiFi可以访问广泛的命令和功能。此外，作者成功解锁了被锁定的串行控制台，通过计算并发送基于相机序列号的预期哈希值。作者进一步探索了相机的功能，包括WiFi设置、实时视图参数、手动控制和通过固件的命令shell执行命令。该项目提供了一个全面的命令列表及其描述，其中一些命令尚未完全实现。通过WiFi解锁相机的能力消除了对物理修改的需求，并允许探索内置shell。新的背景提供了一个可以通过Python库访问的其他命令和功能的列表，例如涂抹控制、减少暗斑点、ANR配置、播放命令以及不同相机功能的各种测试和配置。该项目还包括一个连接到相机的WiFi的shell脚本，解锁相机，并允许发送命令和接收输出。该项目展示了不同的功能，如镜头控制、变焦控制和拍照。它还提供了启用实时视图流传输的示例。相机的固件似乎支持Lua脚本，这是该项目的未来目标。总的来说，这个项目提供了一种经济实惠的方式来尝试光场相机，并欢迎他人的贡献和想法。


[Cisco IOS XE CVE-2023-20198: Deep Dive and POC – Horizon3.ai](https://www.horizon3.ai/cisco-ios-xe-cve-2023-20198-deep-dive-and-poc/)
- 摘要: 这篇文章是对之前一篇文章的跟进，探讨了影响思科IOS XE的CVE-2023-20273和CVE-2023-20198的补丁，并确定了攻击者可能利用这些漏洞的一些途径。通过SECUINFRA FALCON TEAM的蜜罐，我们对这些漏洞有了更深入的了解。文章介绍了一个绕过认证的示例请求，以及如何利用该漏洞创建一个具有最高权限的用户。文章指出思科修复这个漏洞的方法有些不寻常，他们本应该修复路径解析漏洞，而不是添加一个新的头部。这让我们怀疑是否还有其他可以通过这种方法访问的隐藏端点。

https://mp.weixin.qq.com/s/zJJHFjmLqCtcbahJYfoyaw

[Rooting Xiaomi WiFi Routers](https://blog.thalium.re/posts/rooting-xiaomi-wifi-routers/)

[Yet More Unauth Remote Command Execution Vulns in Firewalls - Sangfor Edition](https://labs.watchtowr.com/yet-more-unauth-remote-command-execution-vulns-in-firewalls-sangfor-edition/)

[记一次全设备通杀未授权 RCE 的挖掘经历](https://paper.seebug.org/2071/#poc)

[NETGEAR Routers: A Playground for Hackers? | NCC Group Research Blog | Making the world safer and more secure](https://research.nccgroup.com/2023/05/15/netgear-routers-a-playground-for-hackers/)

[Analysis of Pre-Auth RCE in Sophos Web Appliance (CVE-2023-1671) - Blog - VulnCheck](https://vulncheck.com/blog/cve-2023-1671-analysis)

[Zero Day Initiative — CVE-2022-29844: A Classic Buffer Overflow on the Western Digital My Cloud Pro Series PR4100](https://www.zerodayinitiative.com/blog/2023/4/19/cve-2022-29844-a-classic-buffer-overflow-on-the-western-digital-my-cloud-pro-series-pr4100)

[奇安信攻防社区-CVE-2023-25690 Apache HTTP Server 请求走私漏洞 分析与利用](https://forum.butian.net/share/2180)

[奇安信攻防社区-CVE-2023-25690 Apache HTTP Server 请求走私漏洞 分析与利用](https://forum.butian.net/share/2180)

[Vulnerability Spotlight: Netgear Orbi router vulnerable to arbitrary command execution](https://blog.talosintelligence.com/vulnerability-spotlight-netgear-orbi-router-vulnerable-to-arbitrary-command-execution/)

[Debugging D-Link: Emulating firmware and hacking hardware](https://www.greynoise.io/blog/debugging-d-link-emulating-firmware-and-hacking-hardware)

https://mp.weixin.qq.com/s/Hayfe1gxRl_Clk7L8DIEZg

https://mp.weixin.qq.com/s/2joZwexIdVdgc5NL8W3J-A

[Puckungfu: A NETGEAR WAN Command Injection – NCC Group Research](https://research.nccgroup.com/2022/12/22/puckungfu-a-netgear-wan-command-injection/)

https://mp.weixin.qq.com/s/_CQ9jp6-a7wAcImjg8SouQ

https://mp.weixin.qq.com/s/_CQ9jp6-a7wAcImjg8SouQ

[Citrix CVE-2022-27518 漏洞分析](https://paper.seebug.org/2049/)

[Analyzing an Old Netatalk dsi_writeinit Buffer Overflow Vulnerability in NETGEAR Router | cq674350529's blog](https://cq674350529.github.io/2023/02/10/Analyzing-an-Old-Netatalk-dsi-writeinit-Buffer-Overflow-Vulnerability-in-NETGEAR-Router/)

[Patch diff an old vulnerability in Synology NAS | cq674350529's blog](https://cq674350529.github.io/2023/01/06/Patch-diff-an-old-vulnerability-in-Synology-NAS)

[Patch diff an old vulnerability in Synology NAS | cq674350529's blog](https://cq674350529.github.io/2023/01/06/Patch-diff-an-old-vulnerability-in-Synology-NAS)

[Analyzing an Old Netatalk dsi_writeinit Buffer Overflow Vulnerability in NETGEAR Router | cq674350529's blog](https://cq674350529.github.io/2023/02/10/Analyzing-an-Old-Netatalk-dsi-writeinit-Buffer-Overflow-Vulnerability-in-NETGEAR-Router/)

[Analyzing an Old Netatalk dsi_writeinit Buffer Overflow Vulnerability in NETGEAR Router | cq674350529's blog](https://cq674350529.github.io/2023/02/10/Analyzing-an-Old-Netatalk-dsi-writeinit-Buffer-Overflow-Vulnerability-in-NETGEAR-Router/)

[Netgear Nighthawk r7000p upnpd Buffer Overflow Remote Code Execution Vulnerability](https://hdwsec.fr/blog/20230201-netgear/)

[RCE in Avaya Aura Device Services – Assetnote](https://blog.assetnote.io/2023/02/01/rce-in-avaya-aura/)

[CVE-2023-22374: F5 BIG-IP Format String Vulnerability | Rapid7 Blog](https://www.rapid7.com/blog/post/2023/02/01/cve-2023-22374-f5-big-ip-format-string-vulnerability/)

https://mp.weixin.qq.com/s/ie6ydNvxkFjJxmrpOTkcUA

[CVE-2023-0669 | AttackerKB](https://attackerkb.com/topics/mg883Nbeva/cve-2023-0669)

[Vulnerability Spotlight: Asus router access, information disclosure, denial of service vulnerabilities discovered](https://blog.talosintelligence.com/vulnerability-spotlight-asus-router-access-information-disclosure-denial-of-service-vulnerabilities-discovered)

https://mp.weixin.qq.com/s/js8Pg9xmkqRm0A0TF7pVXQ

https://github.com/scarvell/advisories/blob/main/2022_netcomm_nf20mesh_unauth_rce.md

https://github.com/scarvell/advisories/blob/main/2022_netcomm_nf20mesh_unauth_rce.md

[directory-ttraversal-vulnerability-in-huawei-hg255s-products](https://infosecwriteups.com/directory-ttraversal-vulnerability-in-huawei-hg255s-products-dce941a1d015)

[CVE-2022-45313: Mikrotik RouterOs flaw can lead to execute arbitrary code](https://securityonline.info/cve-2022-45313-mikrotik-routeros-flaw-can-lead-to-execute-arbitrary-code/)

[Cool vulns don't live long - Netgear and Pwn2Own](https://www.synacktiv.com/publications/cool-vulns-dont-live-long-netgear-and-pwn2own.html)

[The Last Breath of Our Netgear RAX30 Bugs - A Tragic Tale before Pwn2Own Toronto 2022 | STAR Labs](https://starlabs.sg/blog/2022/12-the-last-breath-of-our-netgear-rax30-bugs-a-tragic-tale-before-pwn2own-toronto-2022/)

[Horde Webmail - Remote Code Execution via Email](https://blog.sonarsource.com/horde-webmail-rce-via-email/)

[Unauthenticated Remote Code Execution in a Wide Range of DrayTek Vigor Routers](https://www.trellix.com/en-us/about/newsroom/stories/threat-labs/rce-in-dratyek-routers.html)

https://mp.weixin.qq.com/s/p5JH8elwd0ze4f8h8xTgiA

[Blind exploits to rule WatchGuard firewalls](https://www.ambionics.io/blog/hacking-watchguard-firewalls)

[pfBlockerNG Unauth RCE Vulnerability - IHTeam Security Blog](https://www.ihteam.net/advisory/pfblockerng-unauth-rce-vulnerability/)

https://infosecwriteups.com/complete-take-over-of-cisco-unified-communications-manager-due-consecutively-misconfigurations-2a1b5ce8bd9a

https://mp.weixin.qq.com/s/efrcXS_uiXp0LzUaaEJ-MA

[Netgear Nighthawk r7000p aws_json Unauthenticated Double Stack Overflow Vulnerability](https://hdwsec.fr/blog/20221109-netgear/)

[Relyze Software Limited - Advanced Software Analysis: CVE-2022-27643 - NETGEAR R6700v3 upnpd Buffer Overflow Remote Code Execution Vulnerability](https://blog.relyze.com/2022/03/cve-2022-27643-netgear-r6700v3-upnpd.html)

[From Patch To Exploit: CVE-2021-35029](https://blog.cys4.com/exploit/reverse-engineering/2022/04/18/From-Patch-To-Exploit_CVE-2021-35029.html)


[SSD Advisory – NETGEAR DGND3700v2 PreAuth Root Access - SSD Secure Disclosure](https://ssd-disclosure.com/ssd-advisory-netgear-dgnd3700v2-preauth-root-access/)

[Reverse Engineering a Netgear Nday | StarkeBlog](https://nstarke.github.io/netgear/nday/2022/03/13/reverse-engineering-a-netgear-nday.html)

https://mp.weixin.qq.com/s/tUikU0U-FCo33kWsmHTCIQ

## 摄像头漏洞分析
[Exploiting: Buffer overflow in Xiongmai DVRs | ret2.me](https://blog.ret2.me/post/2022-01-26-exploiting-xiongmai-dvrs/)

https://mp.weixin.qq.com/s/K-Zu1M5JVhzT_xb7rb1l0Q

[A journey into IoT - Unknown Chinese alarm - Part 1 - Discover components and ports - hn security](https://security.humanativaspa.it/a-journey-into-iot-unknown-chinese-alarm-part-1-discover-components-and-ports/)

## 智能家居漏洞分析
[Pulling MikroTik into the Limelight — Margin Research](https://margin.re/2022/06/pulling-mikrotik-into-the-limelight/)
- 摘要: 这篇博客提供了关于逆向工程MikroTik路由器的概述，并介绍了研究过程中创建的工具。它涵盖了RouterOS操作系统、绕过签名验证、MikroTik的专有消息协议和认证过程等主题。该文章旨在更新关于MikroTik的公开可用知识，并提供有关其内部工作原理的速成课程，包括消息路由和多播和广播功能的使用。文章还讨论了使用工具跟踪内部RouterOS消息并可视化它们的方法。此外，文章还深入探讨了MikroTik路由器的认证方案，探索了椭圆曲线Diffie-Hellman（ECDH）和椭圆曲线安全远程协议（EC-SRP）等加密协议。分析了MikroTik对EC-SRP的IEEE提交草案的实现的差异，突出了MikroTik所做的修改。文章最后提到了实现Winbox和MAC Telnet协议的工具的可用性，并提供了有关EC-SRP协议和MikroTik的投影空间计算的进一步细节。文章还讨论了使用精心制作的消息和ROP链在RouterOS v6设备上实现权限提升到超级管理员和远程代码执行（RCE）的过程。文章最后强调了记录和分享关于MikroTik和RouterOS的知识的重要性，以鼓励进一步的研究和探索。

https://downrightnifty.me/blog/2022/12/26/hacking-google-home.html

https://mp.weixin.qq.com/s/WkXbI5lHM2LYnSCMuQAdbA

https://mp.weixin.qq.com/s/4fdD3eEg7aql6_cY81hHOA

[nday exploit: netgear orbi unauthenticated command injection (CVE-2020-27861) | hyprblog](https://blog.coffinsec.com//research/2022/07/02/orbi-nday-exploit-cve-2020-27861.html)

## 嵌入式/物联网设备漏洞分析
[Your printer is not your printer ! - Hacking Printers at Pwn2Own Part II | DEVCORE](https://devco.re/blog/2023/11/06/your-printer-is-not-your-printer-hacking-printers-pwn2own-part2-en/)
- 摘要: 根据提供的新背景信息，我们可以对原始摘要进行完善。

研究人员在Pwn2Own Toronto 2022比赛中发现了佳能打印机的Pre-auth RCE漏洞，并与另一个团队发生了关于惠普漏洞的冲突。佳能漏洞涉及mDNS协议中的堆栈溢出，而惠普漏洞则是NetBIOS中的堆溢出。研究人员成功利用这些漏洞运行了shellcode，并控制了打印机。在佳能打印机漏洞中，研究人员发现佳能实现的NetBIOS守护程序在解析NetBIOS数据包时存在堆溢出，使他们能够覆盖nb_info结构并控制打印机。此外，研究人员还发现了惠普Color LaserJet Pro M479fdw打印机的slangapp组件中的堆栈溢出漏洞。通过利用这个漏洞，他们能够覆盖函数指针并执行任意代码，最终控制了打印机。佳能打印机的漏洞是通过解析未检查长度的pathinfo触发的，导致堆栈溢出。研究人员通过构造一个请求到/Scan/Jobs/并覆盖返回地址来利用这个漏洞。然而，这个漏洞与另一个团队的发现发生了冲突。打印机安全问题仍然容易被忽视，正如在Pwn2Own比赛中能够入侵打印机的团队数量不断增加所证明的那样。建议物联网设备的用户禁用不必要的服务，正确设置防火墙，并实施适当的访问控制以减轻攻击风险。

[Your printer is not your printer ! - Hacking Printers at Pwn2Own Part I | DEVCORE 戴夫寇爾](https://devco.re/blog/2023/10/05/your-printer-is-not-your-printer-hacking-printers-pwn2own-part1/)

[chonked pt.1: MiniDLNA 1.3.2 HTTP Chunk Parsing Heap Overflow (CVE-2023-33476) Root Cause Analysis | hyprblog](https://blog.coffinsec.com/0day/2023/05/31/minidlna-heap-overflow-rca.html)

[chonked pt.1: MiniDLNA 1.3.2 HTTP Chunk Parsing Heap Overflow (CVE-2023-33476) Root Cause Analysis | hyprblog](https://blog.coffinsec.com/0day/2023/05/31/minidlna-heap-overflow-rca.html)

[chonked pt.1: MiniDLNA 1.3.2 HTTP Chunk Parsing Heap Overflow (CVE-2023-33476) Root Cause Analysis | hyprblog](https://blog.coffinsec.com/0day/2023/05/31/minidlna-heap-overflow-rca.html)

[The printer goes brrrrr, again!](https://www.synacktiv.com/publications/the-printer-goes-brrrrr-again)

https://mp.weixin.qq.com/s/UwsQH9nr1D4FzK2lhy_W2A

https://mp.weixin.qq.com/s/W2yAcmXh4vrE9pOh02H9Gg

[IOTsec-Zoneç©èç½å®å¨ç¤¾åº](https://iotsec-zone.com/article?id=362)

[CVE-2022-24942 Heap-based buffer overflow in Silicon Labs Gecko SDK](https://bugprove.com/knowledge-hub/cve-2022-24942-heap-based-buffer-overflow-in-silicon-labs-gecko-sdk/)

[Researcher drops Lexmark RCE zero-day rather than sell vuln ‘for peanuts’ | The Daily Swig](https://portswigger.net/daily-swig/researcher-drops-lexmark-rce-zero-day-rather-than-sell-vuln-for-peanuts)

[考勤机安全分析报告 - FreeBuf网络安全行业门户](https://www.freebuf.com/articles/paper/354674.html)

https://github.com/blasty/lexmark

https://mp.weixin.qq.com/s/emvk8liLb4MmWpE9L_MkZA

[KUKA KR C4 | CISA](https://www.cisa.gov/uscert/ics/advisories/icsa-21-208-01)

[Technical Advisory – Multiple Vulnerabilities in U-Boot (CVE-2022-30790, CVE-2022-30552) – NCC Group Research](https://research.nccgroup.com/2022/06/03/technical-advisory-multiple-vulnerabilities-in-u-boot-cve-2022-30790-cve-2022-30552/)

https://mp.weixin.qq.com/s/n_HBOWlHtS9sE7shGpDwxw

[Zero Day Initiative — Announcing Pwn2Own Toronto 2022 and Introducing the SOHO Smashup!](https://www.zerodayinitiative.com/blog/2022/8/29/announcing-pwn2own-toronto-2022-and-introducing-the-soho-smashup)

https://mp.weixin.qq.com/s/xVU8o5NcbFYmy0yPJfiwVQ


# 固件分析
https://mp.weixin.qq.com/s/EPcqFkzmZs8-Sk5iHFHHPA
- 摘要: 摘要为空

https://mp.weixin.qq.com/s/CfflBzV0a9Glf96JkgbBmg
- 摘要: 这篇文章主要讲述了作者尝试刷机摄像头的经历。作者首先尝试使用32G的SD卡刷机，但失败了。然后作者尝试使用TFTP服务器来拯救摄像头，成功了。最后作者介绍了如何修改固件并重新刷入设备。

https://voidstarsec.com/blog/uart-uboot-and-usb
- 摘要: This post is part of the Intro to Embedded RE series and focuses on UART, UBoot, and USB using the Arcade 1UP Marvel countertop cabinet as a target. The post explores the hardware of the cabinet and identifies the main components. It also discusses the connectors on the motherboard and examines unused test pads and vias on the PCB. The post provides an overview of UART and its protocol, and demonstrates how to decode UART traffic using Pulseview. It then explains how to configure the Raspberry Pi to interface with the UART on the cabinet. The post also covers the process of imaging the partitions and investigating the bootloader. Additionally, it discusses the UBoot console and its commands, as well as the environment variables that can be configured in UBoot. The post further delves into the rksfc commands, which are RockChip's SPI SFC (serial flash controller) interface tool, and provides information about the SPI flash and its partitions. It also explores the USB commands and how they can be used to read and write data from the SPI flash. The post concludes by introducing the Depthcharge utility, which can be used to automate UBoot interactions and perform flash reads and writes. The post then goes on to explain how to implement flash reads and writes using UBoot commands and how to enumerate and set up the USB port. It also demonstrates how to dump the flash using the Depthcharge utility. Finally, the post discusses the contents of the extracted flash and the next steps in the reverse engineering process. The post also covers how to analyze unknown UART traffic and connect to a serial port using screen with a Raspberry Pi. After connecting to the serial port, the UBoot console could be accessed by pressing Ctrl-C. The post includes information on writing a depthcharge script to extract each SPI flash partition to an external flash drive. The next post will focus on an in-depth look at the UBoot binary, creating and modifying memory maps using Ghidra, and attempting to flash a custom kernel to the device. The post provides links to the scripts and tools used and invites readers to reach out with questions or comments.

[Hacking Brightway scooters: A case study – RoboCoffee](https://robocoffee.de/?p=436)

[RTSP协议分析 - IOTsec-Zone](https://www.iotsec-zone.com/article/418)

[Rooting Xiaomi WiFi Routers](https://blog.thalium.re/posts/rooting-xiaomi-wifi-routers/)

https://mp.weixin.qq.com/s/X6l_OfFZM6gPoZgL9n2QgA

https://mp.weixin.qq.com/s/BwQ7Ld7cxF9gxxnzxpp6xg

[DJI Mavic 3 Drone Firmware Analysis](https://www.nozominetworks.com/blog/dji-mavic-3-drone-research-part-1-firmware-analysis/)

https://mp.weixin.qq.com/s/RUQKvzoWPks5Y2x6Ou7jCw

[2020补天杯复盘：小米小爱音箱 后渗透利用公开 | Clang裁缝店](https://xuanxuanblingbling.github.io/iot/2022/09/16/mi/)

[一种获取 FortiOS 权限的方法 | CataLpa's Home](https://wzt.ac.cn/2023/02/23/fortios_padding/)

[Firmware key extraction by gaining EL3 - The Cave](https://blog.xilokar.info/firmware-key-extraction-by-gaining-el3.html?s=09)

[ Zeus WPI | Reverse engineering an e-ink display ](https://zeus.ugent.be/blog/22-23/reverse_engineering_epaper/)

[Analyzing an Old Netatalk dsi_writeinit Buffer Overflow Vulnerability in NETGEAR Router | cq674350529's blog](https://cq674350529.github.io/2023/02/10/Analyzing-an-Old-Netatalk-dsi-writeinit-Buffer-Overflow-Vulnerability-in-NETGEAR-Router)

[Dmitry.GR: Projects](https://dmitry.gr/?r=05.Projects)

[Reverse Engineering BLE Devices — Reverse Engineering BLE Devices  documentation](https://reverse-engineering-ble-devices.readthedocs.io/en/latest/)

https://mp.weixin.qq.com/s/16V1JLcLaakCcMHjzOBbRA

[LinkSys EA6100 AC1200 - Part 1 - PCB reversing](https://0x434b.dev/linksys-ea6100_pt1/)

[DualShock4 Reverse Engineering - Part 1](https://blog.the.al/2023/01/01/ds4-reverse-engineering.html)

https://www.shielder.com/blog/2022/03/reversing-embedded-device-bootloader-u-boot-p.2/

[Shielder - Reversing embedded device bootloader (U-Boot) - p.1](https://www.shielder.com/blog/2022/03/reversing-embedded-device-bootloader-u-boot-p.1/)

[Zyxel firmware extraction and password analysis - hn security](https://security.humanativaspa.it/zyxel-firmware-extraction-and-password-analysis/)

https://mp.weixin.qq.com/s/HwU7rgjhoCsJR0XQAoyHvw

[对某webvpn系统加解密分析 - 先知社区](https://xz.aliyun.com/t/11007)

http://xdxd.love/2015/08/24/逆向路由器固件之解包/

# 无线电安全
[BleedingTooth: Linux Bluetooth Zero-Click Remote Code Execution | security-research](https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html)
- 摘要: BleedingTooth是Linux蓝牙子系统中的一组零点击漏洞，可以允许未经身份验证的远程攻击者在短距离内以内核特权执行任意代码。这些漏洞包括一个基于堆的缓冲区溢出漏洞（CVE-2020-24490），可以通过向蓝牙5芯片发送大型广告报告来触发。此漏洞仅在具有蓝牙5芯片的设备上触发，并且只有在受害者正在主动扫描广告数据时才能触发。此外，还存在另外两个漏洞：BadChoice涉及基于堆栈的信息泄漏（CVE-2020-12352），BadKarma是基于堆的类型混淆漏洞（CVE-2020-12351）。这些漏洞构成了严重的安全风险，并可被利用以控制受害者的设备。BadKarma漏洞可以与BadVibes和BadChoice漏洞链接，以实现远程代码执行。用于通信的A2MP通道可以重新配置以绕过BadKarma漏洞并直接调用A2MP接收处理程序。通过将所需的通道模式封装在L2CAP_CONF_UNACCEPT配置响应中，可以实现此重新配置。可以通过操纵struct sock对象和sk_filter()子程序进一步利用漏洞，以控制struct amp_mgr对象并最终执行任意代码。可以使用堆喷射技术来塑造堆并实现受控的越界读取，从而允许对内存地址进行操纵。BadChoice漏洞可用于泄漏内存布局并帮助控制具有已知地址的内存块。通过在之前发送L2CAP_CONF_RSP并尝试将A2MP通道重新配置为L2CAP_MODE_ERTM，可以泄漏偏移量为0x110的struct l2cap_chan对象的地址。该对象的大小为792字节，并在kmalloc-1024 slab中分配。可以通过销毁A2MP通道来释放struct l2cap_chan对象，从而允许与Use-After-Free攻击相同的策略。该技术涉及泄漏struct l2cap_chan对象的地址，通过销毁A2MP通道释放对象，重新连接A2MP通道，并使用堆原语向kmalloc-1024 slab喷射，以可能重新获取以前的struct l2cap_chan对象的地址。该技术可用于控制struct l2cap_chan对象。可以进一步利用这些漏洞来通过控制内存块、泄漏.text段指针和构建ROP链来实现远程代码执行。可以利用对sk_filter字段的控制来将其指向有效载荷并实现RIP控制。该利用还可以执行代码重用攻击，如ROP/JOP，以实现内核堆栈枢轴和执行任意命令。该漏洞的利用的概念验证可在GitHub上找到。漏洞的发现和披露时间表以及研究人员对改进Linux内核安全性的贡献也提供了。

https://mp.weixin.qq.com/s/16V1JLcLaakCcMHjzOBbRA

https://www.nozominetworks.com/downloads/US/Nozomi-Networks-WP-UWB-Real-Time-Locating-Systems.pdf

[Hacking Bluetooth to Brew Coffee from GitHub Actions: Part 1 - Bluetooth Investigation | grack](https://grack.com/blog/2022/12/01/hacking-bluetooth-to-brew-coffee-on-github-actions-part-1)

# 硬件安全
[Intro to Embedded RE Part 1: Tools and Series Overview](https://voidstarsec.com/blog/intro-to-embedded-part-1)
- 摘要: 这篇博客提供了逆向工程嵌入式系统所需的工具概述。它涵盖了硬件和软件工具，包括树莓派、逻辑分析仪、万用表、电源、面包板和焊接铁。文章还提到了其他工具，如硅垫、显微镜、FTDI扩展板、示波器、ChipWhisperer、Ghidra、Binwalk、Kaitai Struct和Pulseview/SigRok。该系列将涵盖构建Ghidra开发环境、UART发现和固件提取、理解Ghidra中的内存映射和地址空间、通过SPI和USB进行固件提取、用于固件分析的Kaitai Struct、I2C和并行闪存提取、PCode仿真以及JTAG概述和应用等主题。系列中的每篇文章都有特定的重点，并提供概述、目标、工具、硬件/软件拆解、结论和资源。文章还包含一个指向GitHub存储库的链接，用于访问与每个目标相关的材料。该系列旨在为对学习逆向工程嵌入式系统感兴趣的硬件和软件工程师提供一条路线图。

https://mp.weixin.qq.com/s/HMMa44u-FtSRPxQ1R-73jw

https://mp.weixin.qq.com/s/TsDWgCABWGCUMVUUK3f05A

[Reverse engineering an EV charger](https://www.mnemonic.io/no/resources/blog/reverse-engineering-an-ev-charger/)

[I'm Building a Self-Destructing USB Drive - Interrupt Labs Blog](https://interruptlabs.ca/2022/07/29/I-m-Building-a-Self-Destructing-USB-Drive/)

https://martinschwarzl.at/media/files/thesis_main.pdf

[PCIe DMA Attack against a secured Jetson Nano (CVE-2022-21819) – The Good Penguin](https://www.thegoodpenguin.co.uk/blog/pcie-dma-attack-against-a-secured-jetson-nano-cve-2022-21819/)

https://raelize.com/upload/research/2017/2017_BlueHat-v17_KERNELFAULT-R00ting-the-Unexploitable-using-Hardware-Fault-Injection_CM_NT.pdf

[PS5 Hack: Keys incoming for the mysterious CP Box? - Wololo.net](https://wololo.net/2023/01/29/ps5-hack-keys-incoming-for-the-mysterious-cp-box/)

[A journey into IoT – Chip identification, BUSSide, and I2C - hn security](https://security.humanativaspa.it/a-journey-into-iot-chip-identification-busside-and-i2c/)

https://mp.weixin.qq.com/s/XxzANNCKwvVmrq2eOihyTw

[Data exfiltration using a COVID-bit attack | Kaspersky official blog](https://www.kaspersky.co.uk/blog/covid-bit-attack/25340/?reseller=gb_kdaily-social_acq_ona_smm__all_b2c_some_sma_______)

https://mp.weixin.qq.com/s/oDMF3uVyJ_XR8h2rPakU3Q

[pfBlockerNG Unauth RCE Vulnerability - IHTeam Security Blog](https://www.ihteam.net/advisory/pfblockerng-unauth-rce-vulnerability/)

https://mp.weixin.qq.com/s/K0SXMVVdmkAdZyrNnCorBw

https://ryancor.medium.com/hardware-trojans-under-a-microscope-bf542acbcc29

https://mp.weixin.qq.com/s/G-Aas9ZFjEfUN6gj2hwusw

# 模糊测试
[How I fuzz and hack APIs?](https://rashahacks.com/how-i-fuzz-and-hack-api/)


# 工具使用
https://chat.openai.com/chat

https://mp.weixin.qq.com/s/DZ2Nd5sIjWOuAGwLzBEQGQ

https://mp.weixin.qq.com/s/sBM-I6-ojYuJ9KyfXl87hg
# 安全论文
https://mp.weixin.qq.com/s/Q2OfKSDsv3-4zdlW3tkgxg

https://mp.weixin.qq.com/s/orbT6HuK6cLN3A2-gcA0Ng
# 会议
## 国内会议
## 国外会议
[WordPress › Error](https://conference.hitb.org/hitbsecconf2022sin/materials/D2 COMMSEC - Cracking Kyocera Printers - Yue Liu, Minghang Shen )

[Page not found - HITBSecConf2023 - Amsterdam](https://conference.hitb.org/hitbsecconf2023ams/materials/D1T1 - Your Not So Home Office - Soho Hacking at Pwn2Own - McCaulay Hudson )

[The DEF CON® Media Server - Archives of the conferences](https://media.defcon.org/?C=N)

https://i.blackhat.com/USA-22/Thursday/US-22-Baines-Do-Not-Trust-The-ASA-Trojans.pdf

https://github.com/binarly-io/Research_Publications/blob/main/OffensiveCon_2022/UEFI Firmware Vulns Past, Present and Future.pdf


# CTF
https://www.reddit.com/r/ReverseEngineering/comments/101iozj/reverse_engineering_and_exploiting_an_iot_bug/

# 安全报道
[Ping bug potentially allows remote hack of FreeBSD systemsSecurity Affairs](https://securityaffairs.co/wordpress/139300/hacking/cve-2022-23093-freebsd-systems-flaw.html)

https://mp.weixin.qq.com/s/Y-_1SEHSDBgWEEOD0dJu6g

https://mp.weixin.qq.com/s/GoYc5SA7cbNIrf2iRMKKSw

https://mp.weixin.qq.com/s/tUikU0U-FCo33kWsmHTCIQ

# 开源安全项目
https://github.com/romainthomas/reverse-engineering-workshop

https://github.com/Accenture/VulFi

https://github.com/shijin0925/IOT/blob/master/TOTOLINK A3100R/8.md

https://github.com/aaronsvk/CVE-2022-30075

https://github.com/airbus-seclab/AutoResolv

https://github.com/PortSwigger/http-request-smuggler

https://github.com/Le0nsec/SecCrawler

https://github.com/pedrib/PoC/blob/master/advisories/Cisco/DCNMPwn.md

https://github.com/wudipjq/my_vuln/tree/main/ARRIS

https://github.com/Cossack9989/Vulns/tree/master/IoT

# 车联网安全
[IOTsec-Zoneç©èç½å®å¨ç¤¾åº](https://iotsec-zone.com/article?id=369)

[IOTsec-Zoneç©èç½å®å¨ç¤¾åº](https://iotsec-zone.com/article?id=369)

https://mp.weixin.qq.com/s/LzrqCOq6BjPC6s3SjNvXcw

[Web Hackers vs. The Auto Industry: Critical Vulnerabilities in Ferrari, BMW, Rolls Royce, Porsche, and More | Sam Curry](https://samcurry.net/web-hackers-vs-the-auto-industry/)

https://mp.weixin.qq.com/s/O1EfTtvmAc0e2H6DFlElYA

https://mp.weixin.qq.com/s/pFf7hvan2Z9VOxGyuwIvmg

[Bug in Honda, Nissan, Toyota Cars App Let Hackers Start The Car Remotely](https://cybersecuritynews.com/vulnerability-in-honda-nissan-toyota-cars-app/)

https://mp.weixin.qq.com/s/bx-Rtw1kkSb56iiaUpcqNQ

https://mp.weixin.qq.com/s/0grR0FRCMoWvsGJAGLTfUg


# 漏洞情报库
[💀 Sploitus | Exploit  漏洞情报库 Hacktool Search Engine](https://sploitus.com/)


National Vulnerability Database（NVD）：https://nvd.nist.gov/

Symantec：https://www.symantec.com/security-center/vulnerability-management

Microsoft：https://technet.microsoft.com/en-us/security/

Tenable：https://www.tenable.com/

Rapid7：https://www.rapid7.com/

Zerodium：https://zerodium.com/

Bugtraq：https://www.securityfocus.com/vulnerabilities

vulmon: https://vulmon.com/vulnerabilitydetails?qid=CVE-2022-1040

synk vulndb：https://snyk.io/vuln/search?q=log4j&type=any

# 其他
https://media.defcon.org/DEF CON 30/DEF CON 30 presentations/Daniel (dozer) Jensen - Hunting Bugs in The Tropics V1.0.pdf

https://github.com/horizon3ai/CVE-2022-39952

https://mp.weixin.qq.com/s/ZpIreydFhKbaGtWjKK6wog

https://github.com/infobyte/cve-2022-27255/blob/main/DEFCON/slides.pdf

https://mp.weixin.qq.com/s/xVU8o5NcbFYmy0yPJfiwVQ

[Hardware 其他
https://media.defcon.org/DEF CON 30/DEF CON 30 presentations/Daniel (dozer) Jensen - Hunting Bugs in The Tropics V1.0.pdf

https://github.com/horizon3ai/CVE-2022-39952

https://mp.weixin.qq.com/s/ZpIreydFhKbaGtWjKK6wog

https://github.com/infobyte/cve-2022-27255/blob/main/DEFCON/slides.pdf

https://mp.weixin.qq.com/s/xVU8o5NcbFYmy0yPJfiwVQ
 Embedded Systems: A little early effort in security can return a huge payoff – NCC Group Research](https://research.nccgroup.com/2022/02/22/hardware-embedded-systems-a-little-early-effort-in-security-can-return-a-huge-payoff/)

https://mp.weixin.qq.com/s/5LHUJjp2uceVFcX_RuxeSQ

