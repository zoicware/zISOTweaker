@(set "0=%~f0"^)#) & chcp 65001 >nul 2>&1 & powershell -nop -ExecutionPolicy Bypass -c "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; Unblock-File $env:0; iex([io.file]::ReadAllText($env:0, [System.Text.Encoding]::UTF8))" & exit /b


#allow ps1 scripts to run
if ((Get-Item -Path 'Registry::HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Force).Property -notcontains 'ExecutionPolicy' -or (Get-Item -Path 'Registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -Force).Property -notcontains 'ExecutionPolicy' ) {
    Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null
    Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null
    try{
    if (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' -ErrorAction Stop) {
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'EnableScripts' /t REG_DWORD /d '1' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
    }
    }catch{}
    
}
else {
    if ((Get-ItemPropertyValue -path 'registry::HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -name 'ExecutionPolicy') -ne 'Bypass' -or (Get-ItemPropertyValue -path 'registry::HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' -name 'ExecutionPolicy') -ne 'Bypass') {
        Reg.exe add 'HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null
        Reg.exe add 'HKLM\SOFTWARE\Wow6432Node\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Bypass' /f *>$null
        try{
        if (Get-ItemPropertyValue -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'ExecutionPolicy' -ErrorAction Stop) {
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'EnableScripts' /t REG_DWORD /d '1' /f >$null
        Reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell' /v 'ExecutionPolicy' /t REG_SZ /d 'Unrestricted' /f >$null
        }   
        }catch{}
    }

}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$functionsDir = $(Split-Path $env:0 -Parent) + '\functions'

if (Test-Path "$functionsDir\zISOTweaker.ps1") {
    $banner = @'
    
    ███████╗██╗███████╗ ██████╗     ████████╗██╗    ██╗███████╗ █████╗ ██╗  ██╗███████╗██████╗ 
    ╚══███╔╝██║██╔════╝██╔═══██╗    ╚══██╔══╝██║    ██║██╔════╝██╔══██╗██║ ██╔╝██╔════╝██╔══██╗
      ███╔╝ ██║███████╗██║   ██║       ██║   ██║ █╗ ██║█████╗  ███████║█████╔╝ █████╗  ██████╔╝
     ███╔╝  ██║╚════██║██║   ██║       ██║   ██║███╗██║██╔══╝  ██╔══██║██╔═██╗ ██╔══╝  ██╔══██╗
    ███████╗██║███████║╚██████╔╝       ██║   ╚███╔███╔╝███████╗██║  ██║██║  ██╗███████╗██║  ██║
    ╚══════╝╚═╝╚══════╝ ╚═════╝        ╚═╝    ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                                                                                  
                        ▄▄▄▄▄▄▄ ISO Image Optimization & Modification Tool ▄▄▄▄▄▄▄
'@
Write-Host $banner -ForegroundColor DarkBlue 
    &"$functionsDir\zISOTweaker.ps1"
}
else {
    Write-Host "zISOTweaker.ps1 NOT Found in $functionsDir" -f Red
}

