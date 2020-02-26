# SIEM

Simple Powershell script that parses sysmon for events and prints interesting ones. 

Install sysmon with the config. (I forked from https://github.com/SwiftOnSecurity/sysmon-config and made some changes.)

Run powershell script. Optionaly redirect stdout to a file. 

## Sample Output

Windows 7 Browsing http://example.com:8080 which is hosting [adobe_flash_hacking_team_uaf](https://www.rapid7.com/db/modules/exploit/multi/browser/adobe_flash_hacking_team_uaf) that phones home on port 80.

Followed with the attacker: credential dumping, installing persistence, launching a new shell, listing drivers, and encrypting a file.

```
alert='Process Creation',message=[C:\Windows\Explorer.EXE started "C:\Program Files (x86)\Internet Explorer\iexplore.exe"  (1868)]
alert='Process Creation',message=["C:\Program Files (x86)\Internet Explorer\iexplore.exe"  started "C:\Program Files\Internet Explorer\IEXPLORE.EXE"  (2740)]
alert='Process Creation',message=["C:\Program Files\Internet Explorer\IEXPLORE.EXE"  started "C:\Program Files (x86)\Internet Explorer\IEXPLORE.EXE" SCODEF:2740 CREDAT:275457 /prefetch:2 (2052)]
alert='Network Connection',message=[C:\Program Files (x86)\Internet Explorer\iexplore.exe connected to 1.0.0.12:8080 (example.com)]
alert='Network Connection',message=[C:\Program Files (x86)\Internet Explorer\iexplore.exe connected to 1.0.0.12:8080 (example.com)]
alert='Network Connection',message=[C:\Program Files (x86)\Internet Explorer\iexplore.exe connected to 1.0.0.12:80 (example.com)]
alert='Network Connection',message=[C:\Program Files (x86)\Internet Explorer\iexplore.exe connected to 1.0.0.12:80 (example.com)]
alert='Process Creation',message=[C:\Windows\system32\services.exe started cmd.exe /c echo lynwmd > \\.\pipe\lynwmd (1492)]
alert='Process Injection',message=[C:\Program Files (x86)\Internet Explorer\iexplore.exe injected code into C:\Windows\explorer.exe]
alert='Process Creation',message=[C:\Windows\system32\services.exe started cmd.exe /c echo ucflij > \\.\pipe\ucflij (2776)]
alert='Mimikatz Detected',message=[C:\Windows\Explorer.EXE was granted 0x1010 access to C:\Windows\system32\lsass.exe]
alert='Process Creation',message=[C:\Windows\Explorer.EXE started cmd /c C:\runme.bat (2424)]
alert='Process Creation',message=[cmd /c C:\runme.bat started at  \\2.0.0.10 00:00 C:\launch.bat (2008)]
alert='Process Creation',message=[cmd /c C:\runme.bat started schtasks  /run /s 2.0.0.10 /tn At1 (2548)]
alert='Process Creation',message=[taskeng.exe {AC746BE6-3559-48AE-9D24-6355E3103843} S-1-5-18:NT AUTHORITY\System:Service: started C:\Windows\SYSTEM32\cmd.exe /c "C:\launch.bat" (2836)]
alert='Process Creation',message=[C:\Windows\SYSTEM32\cmd.exe /c "C:\launch.bat" started C:\met.exe (1604)]
alert='Process Creation',message=[cmd /c C:\runme.bat started driverquery  /FO list /v  (2096)]
alert='Process Creation',message=[C:\met.exe started "C:\Program Files\7-zip\7z.exe" a -pabc123 C:\test.7z C:\windows\notepad.exe (296)]
```
