function Run-Trusted([String]$command) {

    try {
        Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
    }
    catch {
        taskkill /im trustedinstaller.exe /f >$null
    }
    #get bin path to revert later
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='TrustedInstaller'"
    $DefaultBinPath = $service.PathName
    #make sure path is valid and the correct location
    $trustedInstallerPath = "$env:SystemRoot\servicing\TrustedInstaller.exe"
    if ($DefaultBinPath -ne $trustedInstallerPath) {
        $DefaultBinPath = $trustedInstallerPath
    }
    #convert command to base64 to avoid errors with spaces
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
    $base64Command = [Convert]::ToBase64String($bytes)
    #change bin to command
    sc.exe config TrustedInstaller binPath= "cmd.exe /c powershell.exe -encodedcommand $base64Command" | Out-Null
    #run the command
    sc.exe start TrustedInstaller | Out-Null
    #set bin back to default
    sc.exe config TrustedInstaller binpath= "`"$DefaultBinPath`"" | Out-Null
    try {
        Stop-Service -Name TrustedInstaller -Force -ErrorAction Stop -WarningAction Stop
    }
    catch {
        taskkill /im trustedinstaller.exe /f >$null
    }
    
}
Export-ModuleMember -Function Run-Trusted

function Get-FileFromWeb {
    param (
        # Parameter help description
        [Parameter(Mandatory)]
        [string]$URL,
  
        # Parameter help description
        [Parameter(Mandatory)]
        [string]$File 
    )
    Begin {
        function Show-Progress {
            param (
                # Enter total value
                [Parameter(Mandatory)]
                [Single]$TotalValue,
        
                # Enter current value
                [Parameter(Mandatory)]
                [Single]$CurrentValue,
        
                # Enter custom progresstext
                [Parameter(Mandatory)]
                [string]$ProgressText,
        
                # Enter value suffix
                [Parameter()]
                [string]$ValueSuffix,
        
                # Enter bar lengh suffix
                [Parameter()]
                [int]$BarSize = 40,

                # show complete bar
                [Parameter()]
                [switch]$Complete
            )
            
            # calc %
            $percent = $CurrentValue / $TotalValue
            $percentComplete = $percent * 100
            if ($ValueSuffix) {
                $ValueSuffix = " $ValueSuffix" # add space in front
            }
            if ($psISE) {
                Write-Progress "$ProgressText $CurrentValue$ValueSuffix of $TotalValue$ValueSuffix" -id 0 -percentComplete $percentComplete            
            }
            else {
                # build progressbar with string function
                $curBarSize = $BarSize * $percent
                $progbar = ''
                $progbar = $progbar.PadRight($curBarSize, [char]9608)
                $progbar = $progbar.PadRight($BarSize, [char]9617)
        
                if (!$Complete.IsPresent) {
                    Write-Host -NoNewLine "`r$ProgressText $progbar [ $($CurrentValue.ToString('#.###').PadLeft($TotalValue.ToString('#.###').Length))$ValueSuffix / $($TotalValue.ToString('#.###'))$ValueSuffix ] $($percentComplete.ToString('##0.00').PadLeft(6)) % complete"
                }
                else {
                    Write-Host -NoNewLine "`r$ProgressText $progbar [ $($TotalValue.ToString('#.###').PadLeft($TotalValue.ToString('#.###').Length))$ValueSuffix / $($TotalValue.ToString('#.###'))$ValueSuffix ] $($percentComplete.ToString('##0.00').PadLeft(6)) % complete"                    
                }                
            }   
        }
    }
    Process {
        try {
            $storeEAP = $ErrorActionPreference
            $ErrorActionPreference = 'Stop'
        
            # invoke request
            $request = [System.Net.HttpWebRequest]::Create($URL)
            $response = $request.GetResponse()
  
            if ($response.StatusCode -eq 401 -or $response.StatusCode -eq 403 -or $response.StatusCode -eq 404) {
                throw "Remote file either doesn't exist, is unauthorized, or is forbidden for '$URL'."
            }
  
            if ($File -match '^\.\\') {
                $File = Join-Path (Get-Location -PSProvider 'FileSystem') ($File -Split '^\.')[1]
            }
            
            if ($File -and !(Split-Path $File)) {
                $File = Join-Path (Get-Location -PSProvider 'FileSystem') $File
            }

            if ($File) {
                $fileDirectory = $([System.IO.Path]::GetDirectoryName($File))
                if (!(Test-Path($fileDirectory))) {
                    [System.IO.Directory]::CreateDirectory($fileDirectory) | Out-Null
                }
            }

            [long]$fullSize = $response.ContentLength
            $fullSizeMB = $fullSize / 1024 / 1024
  
            # define buffer
            [byte[]]$buffer = new-object byte[] 1048576
            [long]$total = [long]$count = 0
  
            # create reader / writer
            $reader = $response.GetResponseStream()
            $writer = new-object System.IO.FileStream $File, 'Create'
  
            # start download
            $finalBarCount = 0 #show final bar only one time
            do {
          
                $count = $reader.Read($buffer, 0, $buffer.Length)
          
                $writer.Write($buffer, 0, $count)
              
                $total += $count
                $totalMB = $total / 1024 / 1024
          
                if ($fullSize -gt 0) {
                    Show-Progress -TotalValue $fullSizeMB -CurrentValue $totalMB -ProgressText "Downloading $($File.Name)" -ValueSuffix 'MB'
                }

                if ($total -eq $fullSize -and $count -eq 0 -and $finalBarCount -eq 0) {
                    Show-Progress -TotalValue $fullSizeMB -CurrentValue $totalMB -ProgressText "Downloading $($File.Name)" -ValueSuffix 'MB' -Complete
                    $finalBarCount++
                }

            } while ($count -gt 0)
        }
  
        catch {
        
            $ExeptionMsg = $_.Exception.Message
            Write-Host "Download breaks with error : $ExeptionMsg"
        }
  
        finally {
            # cleanup
            if ($reader) { $reader.Close() }
            if ($writer) { $writer.Flush(); $writer.Close() }
        
            $ErrorActionPreference = $storeEAP
            [GC]::Collect()
        }    
    }
}
Export-ModuleMember -Function Get-FileFromWeb


function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Warning', 'Output', 'Error')]
        $Type
    )
  
  
    if ($Type -eq 'Warning') {
        Write-Host "[WARNING] $Message" -ForegroundColor DarkYellow
    }
    elseif ($Type -eq 'Output') {
        Write-Host "[+] $Message" -ForegroundColor Green
    }
    else {
        Write-Host "[ERROR] $Message" -ForegroundColor Red
    }
  
}
Export-ModuleMember -Function Write-Status


function Remove-ItemForce {
    param($path)

    $isDir = $fase
    if (Test-Path "$path" -PathType Container) {
        $isDir = $true
    }

    try {
        if ($isDir) {
            Remove-Item "$path" -Force -Recurse -ErrorAction Stop
        }
        else {
            Remove-Item "$path" -Force -ErrorAction Stop
        } 
    }
    catch {
        #need to takeown since admin priv failed
        if ($isDir) {
            takeown /f "$path" /r /d Y *>$null
            icacls "$path" /grant *S-1-5-32-544:F /t *>$null
            Remove-Item "$path" -Force -Recurse -ErrorAction SilentlyContinue
        }
        else {
            takeown /f "$path" *>$null
            icacls "$path" /grant *S-1-5-32-544:F /t *>$null
            Remove-Item "$path" -Force -ErrorAction SilentlyContinue
        }
        
    }
    #try with trusted installer
    if (Test-Path "$path" -ErrorAction Ignore) {
        $command = "Remove-Item '$path' -Force -Recurse"
        Run-Trusted -command $command
        Start-Sleep 1
    }

    if (Test-Path "$path" -ErrorAction Ignore) {
        Write-Status -Message "Unable to Remove [$path]" -Type Output
    }
    else {
        Write-Status -Message "Removed [$path] Successfully" -Type Output
    }
}
Export-ModuleMember -Function Remove-ItemForce


<#
function Get-ISOFeatures {
    param(
        [string]$scratchDir
    )

    try {
        #using the powershell wrapper function seems to take longer so to get enabled features additional code is needed
        #$features = Get-WindowsOptionalFeature -Path "$scratchDir" -ErrorAction Stop
        $features = dism /english /image="$scratchDir" /get-features 
        $enabledFeatures = @()
        foreach ($line in $features) {
            if ($line -like 'Feature Name*') {
                $previousFeatureName = ($line -split ':')[1].Trim()
            }
            elseif ($line -like 'State*' -and $null -ne $previousFeatureName) {
                if (($line -split ':')[1].Trim() -eq 'Enabled') {
                    $enabledFeatures += $previousFeatureName
                }
                else {
                    $previousFeatureName = $null
                }
            }
        }
        return $enabledFeatures
    }
    catch {
        Write-Status 'get-features Failed!' Error
        return 0
    }
   
}
Export-ModuleMember -Function Get-ISOFeatures
#>




function Show-ModernFilePicker {
    param(
        [ValidateSet('Folder', 'File')]
        $Mode,
        [string]$fileType

    )

    if ($Mode -eq 'Folder') {
        $Title = 'Select Folder'
        $modeOption = $false
        $Filter = "Folders|`n"
    }
    else {
        $Title = 'Select File'
        $modeOption = $true
        if ($fileType) {
            $Filter = "$fileType Files (*.$fileType) | *.$fileType|All files (*.*)|*.*"
        }
        else {
            $Filter = 'All Files (*.*)|*.*'
        }
    }
    #modern file dialog
    #modified code from: https://gist.github.com/IMJLA/1d570aa2bb5c30215c222e7a5e5078fd
    $AssemblyFullName = 'System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
    $Assembly = [System.Reflection.Assembly]::Load($AssemblyFullName)
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.AddExtension = $modeOption
    $OpenFileDialog.CheckFileExists = $modeOption
    $OpenFileDialog.DereferenceLinks = $true
    $OpenFileDialog.Filter = $Filter
    $OpenFileDialog.Multiselect = $false
    $OpenFileDialog.Title = $Title
    $OpenFileDialog.InitialDirectory = [Environment]::GetFolderPath('Desktop')

    $OpenFileDialogType = $OpenFileDialog.GetType()
    $FileDialogInterfaceType = $Assembly.GetType('System.Windows.Forms.FileDialogNative+IFileDialog')
    $IFileDialog = $OpenFileDialogType.GetMethod('CreateVistaDialog', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($OpenFileDialog, $null)
    $null = $OpenFileDialogType.GetMethod('OnBeforeVistaDialog', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($OpenFileDialog, $IFileDialog)
    if ($Mode -eq 'Folder') {
        [uint32]$PickFoldersOption = $Assembly.GetType('System.Windows.Forms.FileDialogNative+FOS').GetField('FOS_PICKFOLDERS').GetValue($null)
        $FolderOptions = $OpenFileDialogType.GetMethod('get_Options', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($OpenFileDialog, $null) -bor $PickFoldersOption
        $null = $FileDialogInterfaceType.GetMethod('SetOptions', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($IFileDialog, $FolderOptions)
    }
  
  

    $VistaDialogEvent = [System.Activator]::CreateInstance($AssemblyFullName, 'System.Windows.Forms.FileDialog+VistaDialogEvents', $false, 0, $null, $OpenFileDialog, $null, $null).Unwrap()
    [uint32]$AdviceCookie = 0
    $AdvisoryParameters = @($VistaDialogEvent, $AdviceCookie)
    $AdviseResult = $FileDialogInterfaceType.GetMethod('Advise', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($IFileDialog, $AdvisoryParameters)
    $AdviceCookie = $AdvisoryParameters[1]
    $Result = $FileDialogInterfaceType.GetMethod('Show', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($IFileDialog, [System.IntPtr]::Zero)
    $null = $FileDialogInterfaceType.GetMethod('Unadvise', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($IFileDialog, $AdviceCookie)
    if ($Result -eq [System.Windows.Forms.DialogResult]::OK) {
        $FileDialogInterfaceType.GetMethod('GetResult', @('NonPublic', 'Public', 'Static', 'Instance')).Invoke($IFileDialog, $null)
    }

    return $OpenFileDialog.FileName
}
Export-ModuleMember -Function Show-ModernFilePicker



function install-adk {

    $testP = Test-Path -Path "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\x86\Oscdimg\oscdimg.exe"

    if (!($testP)) {
        Write-Status 'Installing Windows ADK' Output
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri 'https://go.microsoft.com/fwlink/?linkid=2196127' -UseBasicParsing -OutFile "$PSScriptRoot\adksetup.exe"
        &"$PSScriptRoot\adksetup.exe" /quiet /features OptionId.DeploymentTools | Wait-Process 
        Remove-Item -Path "$PSScriptRoot\adksetup.exe" -Force
    }
    else {
        Write-Status 'ADK Installed' Output
        return $true
    }

    #check if adk installed correctly
    $testP = Test-Path -Path "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\x86\Oscdimg\oscdimg.exe" 

    if ($testP) {
        Write-Status 'ADK Installed' Output
        return $true
    }
    else {
        Write-Status 'ADK Not Found or Failed to Install' Error
        return $false
    }

}
Export-ModuleMember -Function install-adk



function remove-Defender([String]$edition, [String]$removeDir) {

    Write-Status "Removing Defender from $edition..." Output

    $featureList = dism /english /image:$removeDir /Get-Features | Select-String -Pattern 'Feature Name : ' -CaseSensitive -SimpleMatch
    $featureList = $featureList -split 'Feature Name : ' | Where-Object { $_ }
    foreach ($feature in $featureList) {
        if ($feature -like '*Defender*') {
            Write-Status "Removing $feature..." Output
            dism /english /image:$removeDir /Disable-Feature /FeatureName:$feature /Remove /NoRestart

        }

    }

    #uninstall sec center app
    $packages = dism /english /image:$removeDir /get-provisionedappxpackages | Select-String 'PackageName :'
    $packages = $packages -split 'PackageName : ' | Where-Object { $_ }
    foreach ($package in $packages) {
        if ($package -like '*SecHealth*') {
            Write-Status "Removing $package Package..." Output
            #cant remove with dism not sure if it will install or not
            #try to prevent install

            #load registry here instead of using the function to avoid access denied error 
            [GC]::Collect()
            reg load HKLM\OFFLINE_SOFTWARE "$removeDir\Windows\System32\config\SOFTWARE" >$null
            New-Item 'HKLM:\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.SecHealthUI_8wekyb3d8bbwe' -Force | Out-Null
            Remove-Item 'HKLM:\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\*SecHealth*' -Recurse -Force
            Remove-Item 'HKLM:\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\*SecHealth*' -Recurse -Force
            Remove-Item 'HKLM:\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Staged\*SecHealth*' -Recurse -Force
            [GC]::Collect()
            reg unload HKLM\OFFLINE_SOFTWARE >$null
            dism /english /image:$removeDir /set-nonremovableapppolicy /packagefamily:$package /nonremovable:0
            dism /english /image:$removeDir /Remove-ProvisionedAppxPackage /PackageName:$package *>$null
        }

    }

    # dism /english /image:$removeDir /get-packages | Select-String -Pattern 'Package Identity : ' -CaseSensitive -SimpleMatch

    Write-Status 'Removing Defender Files...' Output

    Remove-ItemForce -path "$removeDir\Program Files\Windows Defender"
    Remove-ItemForce -path "$removeDir\Program Files (x86)\Windows Defender"
    Remove-ItemForce -path "$removeDir\Program Files\Windows Defender Advanced Threat Protection"
    Remove-ItemForce -path "$removeDir\ProgramData\Microsoft\Windows Defender"
    Remove-ItemForce -path "$removeDir\ProgramData\Microsoft\Windows Defender Advanced Threat Protection"
    Remove-ItemForce -path "$removeDir\Windows\System32\SecurityHealth*"
    Remove-ItemForce -path "$removeDir\Windows\System32\SecurityCenter*"
    Remove-ItemForce -path "$removeDir\Windows\System32\smartscreen.exe" 
    Remove-ItemForce -path "$removeDir\Windows\System32\CodeIntegrity\CiPolicies\Active\*" 
    Remove-ItemForce -path "$removeDir\Program Files\WindowsApps\Microsoft.SecHealthUI_*"
    

  
}
Export-ModuleMember -Function Remove-Defender


function Remove-BitLocker {
    param(
        [string]$removeDir
    )

    Write-Status 'Stripping Bitlocker...' Output
    $command = "
    Reg add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\BDESVC' /v 'Start' /t REG_DWORD /d '4' /f
    Reg add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\BitLocker' /v 'PreventDeviceEncryption' /t REG_DWORD /d '1' /f
    Reg add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\BitlockerStatus' /v 'BootStatus' /t REG_DWORD /d '0' /f
    Reg add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\BitLocker' /v 'IsBdeDriverPresent' /t REG_DWORD /d '0' /f
    "
    Run-Trusted -command $command
    #remove files
    $bitlockerfiles = @(
        'Windows\BitLockerDiscoveryVolumeContents\BitLockerToGo.exe',
        'Windows\SysWOW64\BitLockerCsp.dll',
        'Windows\System32\BitLockerCsp.dll',
        'Windows\System32\BitLockerWizard.exe',
        'Windows\System32\BitLockerWizardElev.exe',
        'Windows\System32\BitLockerDeviceEncryption.exe',
        'Windows\System32\en-US\BitLockerWizardElev.exe.mui',
        'Windows\System32\en-US\BitLockerWizard.exe.mui'
    )


    foreach ($file in $bitlockerfiles) {
        Remove-ItemForce -Path "$removeDir\$file"
    }
    

}
Export-ModuleMember -Function Remove-BitLocker


function Disable-Mitigations {

    Write-Status 'Disabling Mitigation Options...' Output
    $disableContent = @'
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Control\Session Manager\kernel" /v "MitigationOptions" /t REG_BINARY /d "222222222222222222222222222222222222222222222222" /f
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d "0" /f
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Control\DeviceGuard" /v "HypervisorEnforcedCodeIntegrity" /t REG_DWORD /d "0" /f
Reg add "HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\default\DeviceGuard\RequirePlatformSecurityFeatures" /v "value" /t REG_DWORD /d "0" /f
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d "0" /f
Reg add "HKLM\OFFLINE_SYSTEM\ControlSet001\Control\DeviceGuard\Scenarios\CredentialGuard" /v "Enabled" /t REG_DWORD /d "0" /f
'@ 
    $dPath = New-Item "$env:TEMP\disableMitigations.bat" -Value $disableContent -Force

    $command = "Start-Process `'$($dPath.FullName)`'"
    Run-Trusted -command $command 
    Start-Sleep 1
    Remove-Item $dPath.FullName -Force -ErrorAction SilentlyContinue
}
Export-ModuleMember -Function Disable-Mitigations


function Disable-Defender {
    
    Write-Status -Message 'Applying Disable Defender Registry...' -Type Output
    $regDir = "$PSScriptRoot\DisableDefenderRegistry"
    $files = (Get-ChildItem -Path $regDir).FullName
    foreach ($file in $files) {
        regedit.exe /s "$file"
        #dont think we need trusted installer 

        # $command = "Start-Process regedit.exe -ArgumentList `"/s `"$file`"`""
        # Run-Trusted -command $command
        Start-Sleep 1
    }
    
    
}
Export-ModuleMember -Function Disable-Defender

function Disable-W11Req {

    # TODO:
    # DISABLE REQS FOR BOOT AS WELL
    Write-Status 'Disabling Windows 11 Requirements...' Output
    Reg add 'HKLM\OFFLINE_DEFAULT\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV1' /t REG_DWORD /d 0 /f >$null
    Reg add 'HKLM\OFFLINE_DEFAULT\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV2' /t REG_DWORD /d 0 /f >$null
    Reg add 'HKLM\OFFLINE_NTUSER\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV1' /t REG_DWORD /d 0 /f >$null
    Reg add 'HKLM\OFFLINE_NTUSER\Control Panel\UnsupportedHardwareNotificationCache' /v 'SV2' /t REG_DWORD /d 0 /f >$null
    Reg add 'HKLM\OFFLINE_SYSTEM\Setup\LabConfig' /v 'BypassCPUCheck' /t REG_DWORD /d 1 /f >$null
    Reg add 'HKLM\OFFLINE_SYSTEM\Setup\LabConfig' /v 'BypassRAMCheck' /t REG_DWORD /d 1 /f >$null
    Reg add 'HKLM\OFFLINE_SYSTEM\Setup\LabConfig' /v 'BypassSecureBootCheck' /t REG_DWORD /d 1 /f >$null
    Reg add 'HKLM\OFFLINE_SYSTEM\Setup\LabConfig' /v 'BypassStorageCheck' /t REG_DWORD /d 1 /f >$null
    Reg add 'HKLM\OFFLINE_SYSTEM\Setup\LabConfig' /v 'BypassTPMCheck' /t REG_DWORD /d 1 /f >$null
    Reg add 'HKLM\OFFLINE_SYSTEM\Setup\MoSetup' /v 'AllowUpgradesWithUnsupportedTPMOrCPU' /t REG_DWORD /d 1 /f >$null
}
Export-ModuleMember -Function Disable-W11Req


function Disable-Updates {
   
    Write-Status 'Disabling Windows Updates...' Output
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'WUStatusServer' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'UpdateServiceUrlAlternate' /t REG_SZ /d 'https://DoNotUpdateWindows10.com/' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetProxyBehaviorForUpdateDetection' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetDisableUXWUAccess' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DoNotConnectToWindowsUpdateInternetLocations' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'NoAutoUpdate' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' /v 'UseWUServer' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\UsoSvc' /v 'Start' /t REG_DWORD /d '4' /f  >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\DoSvc' /v 'Start' /t REG_DWORD /d '4' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching' /v 'SearchOrderConfig' /t REG_DWORD /d '1' /f >$null
    #disable store auto store updates too
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\WindowsStore' /v 'AutoDownload' /t REG_DWORD /d '2' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE' /v 'DisableOnline' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\wuauserv' /v 'Start' /t REG_DWORD /d '4' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\WaaSMedicSVC' /v 'Start' /t REG_DWORD /d '4' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\Device Metadata' /v 'PreventDeviceMetadataFromNetwork' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\DriverSearching' /v 'DontPromptForWindowsUpdate' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\DriverSearching' /v 'DontSearchWindowsUpdate' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\DriverSearching' /v 'DriverUpdateWizardWuSearchEnabled' /t REG_DWORD /d '0' /f >$null

    # Reg.exe add 'HKU\S-1-5-20\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings' /v 'DownloadMode' /t REG_DWORD /d '0' /f
}
Export-ModuleMember -Function Disable-Updates


function Sec-UpdatesOnly {
    
    Write-Status 'Enabling Security Updates Only...' Output
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'SetAllowOptionalContent' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdates' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferFeatureUpdatesPeriodInDays' /t REG_DWORD /d '730' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdates' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'DeferQualityUpdatesPeriodInDays' /t REG_DWORD /d '730' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' /v 'ExcludeWUDriversInQualityUpdate' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\Device Metadata' /v 'PreventDeviceMetadataFromNetwork' /t REG_DWORD /d '1' /f >$null
    Reg.exe add  'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\DriverSearching' /v 'DontPromptForWindowsUpdate' /t REG_DWORD /d '1' /f >$null
    Reg.exe add  'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\DriverSearching' /v 'DontSearchWindowsUpdate' /t REG_DWORD /d '1' /f >$null
    Reg.exe add  'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\DriverSearching' /v 'DriverUpdateWizardWuSearchEnabled' /t REG_DWORD /d '0' /f >$null

    $excludedClassifications = @(
        '{e6cf1350-c01b-414d-a61f-263d3d4dd9f9}', # Critical Updates
        '{e0789628-ce08-4437-be74-2495b842f43b}', # Definition Updates
        '{b54e7d24-7add-49f4-88bb-9837d47477fb}', # Feature Packs
        '{68c5b0a3-d1a6-4553-ae49-01d3a7827828}', # Service Packs
        '{b4832bd8-e735-4766-9727-7d0ffa644277}', # Tools
        '{28bc8804-5382-4bae-93aa-13c905f28542}', # Update Rollups
        '{cd5ffd1e-e257-4a05-9d88-c83a7125d4c9}', # Updates
        '{0f1afbec-90ef-4651-9e37-030fedc944c8}', # Non-critical
        '{ebfc1fc5-71a4-4f7b-9aca-3b9a503104a0}', # Drivers
        '{9920c092-3d99-4a1b-865a-673135c5a4fc}'   # Feature Updates
    ) -join ';'
    Set-ItemProperty -Path 'HKLM:\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' -Name 'ExcludeUpdateClassifications' -Value $excludedClassifications -Type String -Force | Out-Null
}
Export-ModuleMember -Function Sec-UpdatesOnly

function Disable-VerUpgrade {
    Write-Status 'Disabling Version Upgrade...' Output
    $buildVer = (Get-ItemProperty 'HKLM:\OFFLINE_SOFTWARE\Microsoft\Windows NT\CurrentVersion').DisplayVersion
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'ProductVersion' /t REG_SZ /d 'Windows 11' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'TargetReleaseVersion' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate' /v 'TargetReleaseVersionInfo' /t REG_SZ /d $buildVer /f >$null
}
Export-ModuleMember -Function Disable-VerUpgrade


function Disable-WindowsAnnoyances {
    param(
        [string]$removeDir
    )
    Write-Status 'Disabling Sponsored Apps...' Output
    reg.exe add 'HKLM\OFFLINE_NTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'OemPreInstalledAppsEnabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'PreInstalledAppsEnabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SilentInstalledAppsEnabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableWindowsConsumerFeatures' /t REG_DWORD /d '1' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'ContentDeliveryAllowed' /t REG_DWORD /d '0' /f >$null
    #reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\current\device\Start' /v 'ConfigureStartPins' /t REG_SZ /d '{"pinnedList": [{}]}' /f >$null
    #reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\current\device\Start' /v 'ConfigureStartPins_ProviderSet' /t REG_DWORD /d '1' /f >$null
    #reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\current\device\Start' /v 'ConfigureStartPins_WinningProvider' /t REG_SZ /d 'B5292708-1619-419B-9923-E5D9F3925E71' /f
    #reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\providers\B5292708-1619-419B-9923-E5D9F3925E71\default\Device\Start' /v 'ConfigureStartPins' /t REG_SZ /d '{"pinnedList": [{}]}' /f
    #reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\providers\B5292708-1619-419B-9923-E5D9F3925E71\default\Device\Start' /v 'ConfigureStartPins_LastWrite' /t REG_DWORD /d '1' /f
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'FeatureManagementEnabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'PreInstalledAppsEverEnabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SoftLandingEnabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContentEnabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-310093Enabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-338388Enabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-338389Enabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-338393Enabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-353694Enabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SubscribedContent-353696Enabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager' /v 'SystemPaneSuggestionsEnabled' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\PushToInstall' /v 'DisablePushToInstall' /t REG_DWORD /d '1' /f >$null
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\MRT' /v 'DontOfferThroughWUAU' /t REG_DWORD /d '1' /f >$null
    reg.exe delete 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions' /f *>$null
    reg.exe delete 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps' /f *>$null
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableConsumerAccountStateContent' /t REG_DWORD /d '1' /f >$null
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableCloudOptimizedContent' /t REG_DWORD /d '1' /f >$null
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests' /v 'value' /t REG_DWORD /d '0' /f >$null
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Dsh' /v 'AllowNewsAndInterests' /t REG_DWORD /d '0' /f >$null
    Reg.exe delete 'HKLM\OFFLINE_Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}' /f >$null
    Reg.exe delete 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' /v 'HubMode' /t REG_DWORD /d '1' /f >$null
    @( 'EdgeUpdate',
        'DevHomeUpdate',
        'OutlookUpdate',
        'CrossDeviceUpdate') | ForEach-Object {
        reg.exe delete "HKLM\OFFLINE_SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\$_" /f *>$null
    }
    #prevent install of new teams and outlook
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Teams' /v 'DisableInstallation' /t REG_DWORD /d '1' /f >$null
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\Windows Mail' /v 'PreventRun' /t REG_DWORD /d '1' /f >$null
    Write-Status 'Disabling Windows Platform Binary Table...' Output
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\Session Manager' /v DisableWpbtExecution /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer' /v 'DisableCoInstallers' /t REG_DWORD /d '1' /f >$null
    Write-Status 'Disabling First Logon Animation...' Output
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Active Setup\Installed Components\CMP_NoFla' /f >$null
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Active Setup\Installed Components\CMP_NoFla' /ve /t REG_SZ /d 'Stop First Logon Animation Process' /f >$null
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Active Setup\Installed Components\CMP_NoFla' /v StubPath /t REG_EXPAND_SZ /d '""%WINDIR%\System32\cmd.exe"" /C ""taskkill /f /im firstlogonanim.exe""' /f >$null
    Write-Status 'Removing Unwanted Tasks..' Output
    $tasksPath = "$removeDir\Windows\System32\Tasks"
    # Application Compatibility Appraiser
    Remove-ItemForce -Path "$tasksPath\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" 
    Remove-ItemForce -Path "$tasksPath\Microsoft\Windows\Customer Experience Improvement Program" 
    Remove-ItemForce -Path "$tasksPath\Microsoft\Windows\Application Experience\ProgramDataUpdater" 
    Remove-ItemForce -Path "$removeDir\Windows\InboxApps"
    Write-Status 'Removing Cross Device Resume...' Output
    Remove-ItemForce -path "$removeDir\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceResume.exe"
    Remove-ItemForce -path "$removeDir\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceResumeView.dll"
    Remove-ItemForce -path "$removeDir\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\CrossDeviceResume"
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\default\Connectivity\DisableCrossDeviceResume' /v 'value' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1387020943' /v 'EnabledState' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1694661260' /v 'EnabledState' /t REG_DWORD /d '1' /f *>$null
    Write-Status 'Disabling User Choice Driver...' Output
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\UCPD' /v 'Start' /t REG_DWORD /d '4' /f >$null
    Write-Status 'Disabling AI Fabric Service...' Output
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\WSAIFabricSvc' /v 'Start' /t REG_DWORD /d '4' /f >$null
    Write-Status 'Disabling Windows Quality and Health Insights Services...' Output
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\whesvc' /v 'Start' /t REG_DWORD /d '4' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\wuqisvc' /v 'Start' /t REG_DWORD /d '4' /f >$null
    #run once key to enable the classic context menu 
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce' /v 'ClassicContext' /t REG_SZ /d 'reg.exe add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /ve /f' /f >$null
    Write-Status 'Removing Internet Explorer...' Output
    Remove-ItemForce -path "$removeDir\Program Files (x86)\Internet Explorer" 
    Remove-ItemForce -path "$removeDir\Program Files\Internet Explorer" 
    Remove-ItemForce -path "$removeDir\Program Files (x86)\Windows Mail" 
    Remove-ItemForce -path "$removeDir\Program Files\Windows Mail" 
    
}
Export-ModuleMember -Function Disable-WindowsAnnoyances


function Remove-Edge {
    param (
        [string]$removeDir
    )
    
    Write-Status 'Removing Edge...' Output
    Remove-ItemForce -Path "$removeDir\Program Files (x86)\Microsoft\Edge*" 
    $edgeSxs = Get-ChildItem -Path "$removeDir\Windows\WinSxS" -Filter '*amd64_microsoft-edge-webview_31bf3856ad364e35*' -Directory -ErrorAction SilentlyContinue
    if ($edgeSxs) { 
        foreach ($path in $edgeSxs) {
            Remove-ItemForce -Path $path.FullName
        }
    }
    Remove-ItemForce -Path "$removeDir\Windows\System32\Microsoft-Edge-Webview" 
    reg.exe delete 'HKLM\OFFLINE_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge' /f *>$null
    reg.exe delete 'HKLM\OFFLINE_SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge Update' /f *>$null
}
Export-ModuleMember -Function Remove-Edge


function Remove-OneDrive {
    param (
        [string]$removeDir
    )
    Write-Status 'Removing OneDrive...' Output
    Remove-ItemForce -Path "$removeDir\Windows\System32\OneDriveSetup.exe" 
    Remove-ItemForce -path "$removeDir\Windows\System32\OneDrive.ico"
    reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\OneDrive' /v 'DisableFileSyncNGSC' /t REG_DWORD /d '1' /f >$null

}
Export-ModuleMember -Function Remove-OneDrive


function Load-Registry {
    param(
        [string]$removeDir
    )

    Write-Status 'Loading Registry...' -Type Output
    [GC]::Collect()
    reg load HKLM\OFFLINE_SOFTWARE "$removeDir\Windows\System32\config\SOFTWARE" >$null
    reg load HKLM\OFFLINE_SYSTEM "$removeDir\Windows\System32\config\SYSTEM" >$null
    reg load HKLM\OFFLINE_NTUSER "$removeDir\Users\Default\ntuser.dat" >$null
    reg load HKLM\OFFLINE_DEFAULT "$removeDir\Windows\System32\config\default" >$null
    reg load HKLM\OFFLINE_COMPONENTS "$removeDir\Windows\System32\config\COMPONENTS" >$null
}
Export-ModuleMember -Function Load-Registry

function Unload-Registry {
    Write-Status 'Unloading Registry...' -Type Output
    [GC]::Collect()
    reg unload HKLM\OFFLINE_SOFTWARE *>$null
    reg unload HKLM\OFFLINE_SYSTEM *>$null
    reg unload HKLM\OFFLINE_NTUSER *>$null
    reg unload HKLM\OFFLINE_DEFAULT *>$null
    reg unload HKLM\OFFLINE_COMPONENTS *>$null
}
Export-ModuleMember -Function Unload-Registry

function Unmount-ISO {
    param (
        [string]$removeDir,
        [string]$edition
    )
    Write-Status 'Compressing WinSXS Folder...' Output
    dism /image:$removeDir /Cleanup-Image /StartComponentCleanup /ResetBase

    Write-Status "Unmounting $edition..." Output
    dism /unmount-image /mountdir:$removeDir /commit
}
Export-ModuleMember -Function Unmount-ISO

function Compress-ISO {
    param (
        [string]$tempDir,
        $index
    )

    Write-Status 'Compressing ISO File...' -Type Output
    Export-WindowsImage -SourceImagePath "$tempDir\sources\install.wim" -SourceIndex $index -DestinationImagePath "$tempDir\sources\install2.wim" -CompressionType 'max'
    Remove-Item "$tempDir\sources\install.wim"
    Rename-Item "$tempDir\sources\install2.wim" -NewName 'install.wim' -Force
}
Export-ModuleMember -Function Compress-ISO


function Create-ISO {
    param (
        [string]$tempDir,
        $index,
        [string]$outPath,
        [string]$isoPath
    )
    
    
    Write-Status 'Creating ISO File in Destination Directory...' -Type Output
    $title = [System.IO.Path]::GetFileNameWithoutExtension($isoPath) 
    $path = "$outPath\$title(Z).iso"
    $oscdimg = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\x86\Oscdimg\oscdimg.exe"
    Start-Process -FilePath $oscdimg -ArgumentList "-m -o -u2 -udfver102 -bootdata:2#p0,e,b$tempDir\boot\etfsboot.com#pEF,e,b$tempDir\efi\microsoft\boot\efisys.bin $tempDir `"$path`"" -NoNewWindow -Wait  
}
Export-ModuleMember -Function Create-ISO


function Remove-Features {
    param (
        [string]$removeDir,
        [array]$featureNames
    )

    foreach ($name in $featureNames) {
        Write-Status "Removing Feature: $name..." Output
        dism /english /image:$removeDir /Disable-Feature /FeatureName:$name /Remove /NoRestart
    }
    
}
Export-ModuleMember -Function Remove-Features


function Remove-OSPackages {
    param(
        [string]$removeDir,
        [array]$osPackages
    )

    foreach ($package in $osPackages) {
        Write-Status "Removing $package..." Output
        try {
            Remove-WindowsPackage -Path $removeDir -PackageName $package -NoRestart -ErrorAction Stop
        }
        catch {}
        
    }
    
}
Export-ModuleMember -Function Remove-OSPackages

function Remove-Capabilities {
    param(
        [string]$removeDir,
        [array]$caps
    )

    foreach ($cap in $caps) {
        Write-Status "Removing $cap..." Output
        try {
            Remove-WindowsCapability -Path $removeDir -Name $cap -ErrorAction Stop
        }
        catch {}
        
    }
    
}
Export-ModuleMember -Function Remove-Capabilities

function Remove-Packages {
    param (
        [string]$removeDir,
        [array]$packages
    )

    foreach ($package in $packages) {
        $name = ($package -split '_')[0]
        $msName = $name + '_8wekyb3d8bbwe'
        Write-Status "Removing Package: $name" Output
        [GC]::Collect()
        reg load HKLM\OFFLINE_SOFTWARE "$removeDir\Windows\System32\config\SOFTWARE" >$null
        New-Item "HKLM:\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\$msName" -Force | Out-Null
        Remove-Item "HKLM:\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\*$name*" -Recurse -Force
        Remove-Item "HKLM:\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications\*$name*" -Recurse -Force
        Remove-Item "HKLM:\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Staged\*$name*" -Recurse -Force
        [GC]::Collect()
        reg unload HKLM\OFFLINE_SOFTWARE >$null
        
        dism /english /image:$removeDir /set-nonremovableapppolicy /packagefamily:$package /nonremovable:0
        dism /english /image:$removeDir /Remove-ProvisionedAppxPackage /PackageName:$package *>$null

        Remove-ItemForce -path "$removeDir\Program Files\WindowsApps\$name*" 
        Remove-ItemForce -path "$removeDir\Windows\SystemApps\$name*"
    }
    
    
}
Export-ModuleMember -Function Remove-Packages

function Strip-WinAI {
    param (
        [string]$removeDir
    )
    
    Write-Status 'Removing Windows AI...' Output
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot' /v 'TurnOffWindowsCopilot' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableAIDataAnalysis' /t REG_DWORD /d '1'/f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'AllowRecallEnablement' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableClickToDo' /t REG_DWORD /d '1'/f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'TurnOffSavingSnapshots' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\WindowsAI' /v 'DisableSettingsAgent' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\Shell\Copilot\BingChat' /v 'IsUserEligible' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\Shell\Copilot' /v 'IsCopilotAvailable' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\Shell\Copilot' /v 'CopilotDisabledReason' /t REG_SZ /d 'FeatureIsDisabled'/f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotCDPPageContext' /t REG_DWORD /d '0' /f *>$null #depreciated shows Unknown policy in edge://policy
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotPageContext' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Edge' /v 'HubsSidebarEnabled' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Edge' /v 'CopilotPageContext' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeEntraCopilotPageContext' /t REG_DWORD /d '0'/f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Edge' /v 'Microsoft365CopilotChatIconEnabled' /t REG_DWORD /d '0' /f *>$null #depreciated shows Unknown policy in edge://policy
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Edge' /v 'EdgeHistoryAISearchEnabled' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Edge' /v 'ComposeInlineEnabled' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Edge' /v 'GenAILocalFoundationalModelSettings' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings' /v 'AutoOpenCopilotLargeScreens' /t REG_DWORD /d '0' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\generativeAI' /v 'Value' /t REG_SZ /d 'Deny' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels' /v 'Value' /t REG_SZ /d 'Deny' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessGenerativeAI' /t REG_DWORD /d '2'/f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\AppPrivacy' /v 'LetAppsAccessSystemAIModels' /t REG_DWORD /d '2' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\1853569164' /v 'EnabledState' /t REG_DWORD /d '1'/f *>$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\4098520719' /v 'EnabledState' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\FeatureManagement\Overrides\8\929719951' /v 'EnabledState' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableImageCreator' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableCocreator' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableGenerativeFill' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableGenerativeErase' /t REG_DWORD /d '1' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint' /v 'DisableRemoveBackground' /t REG_DWORD /d '1' /f *>$null
    Reg.exe delete 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\WSAIFabricSvc' /f *>$null
    Reg.exe delete 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'AIX' /f *>$null
    Reg.exe delete 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'CopilotNudges' /f *>$null
    Reg.exe delete 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Shell\Update\Packages\Components' /v 'AIContext' /f *>$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' /v 'SettingsPageVisibility' /t REG_SZ /d 'hide:aicomponents;' /f >$null
    Reg.exe delete 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Config\MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy' /f >$null
    $resolvedPath = (Get-Item 'HKLM:\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\InboxApplications\MicrosoftWindows.Client.CoreAI*').Name
    Reg.exe delete $resolvedPath /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\MicrosoftWindows.Client.CoreAI_cw5n1h2txyewy' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Copilot_8wekyb3d8bbwe' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Office.ActionsServer_8wekyb3d8bbwe' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\aimgr_8wekyb3d8bbwe' /f >$null

    $arm = ((Get-CimInstance -Class Win32_ComputerSystem).SystemType -match 'ARM64') -or ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64')
    $arch = if ($arm) { 'arm64' } else { 'amd64' }
    $certRegPath = 'HKLM:\OFFLINE_Software\Microsoft\SystemCertificates\ROOT\Certificates\8A334AA8052DD244A647306A76B8178FA215F344'
    New-Item -Path $certRegPath -Force | Out-Null
    
    Unload-Registry
    $ProgressPreference = 'SilentlyContinue'
    try {
        Invoke-WebRequest -Uri "https://github.com/zoicware/RemoveWindowsAI/raw/refs/heads/main/RemoveWindowsAIPackage/$arch/ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" -OutFile "$env:TEMP\ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" -UseBasicParsing -ErrorAction Stop
        Write-Status 'Installing RemoveWindowsAI Package...' Output
        Add-WindowsPackage -Path $removeDir -PackagePath "$env:TEMP\ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" -NoRestart -IgnoreCheck
    }
    catch {
        Write-Status "Unable to Download Package at: https://github.com/zoicware/RemoveWindowsAI/raw/refs/heads/main/RemoveWindowsAIPackage/$arch/ZoicwareRemoveWindowsAI-$($arch)1.0.0.0.cab" Error
        
    }
    
    Disable-WindowsOptionalFeature -Path $removeDir -FeatureName 'Recall' -Remove -NoRestart

    $aipackages = @(
        # 'MicrosoftWindows.Client.Photon'
        'MicrosoftWindows.Client.AIX'
        'MicrosoftWindows.Client.CoPilot'
        'Microsoft.Windows.Ai.Copilot.Provider'
        'Microsoft.Copilot'
        'Microsoft.MicrosoftOfficeHub'
        'MicrosoftWindows.Client.CoreAI'
        'Microsoft.Edge.GameAssist'
        'Microsoft.Office.ActionsServer'
        'aimgr'
        'Microsoft.WritingAssistant'
        #ai component packages installed on copilot+ pcs
        'WindowsWorkload'
        'Voiess'
        'Speion'
        'Livtop'
        'InpApp'
        'Filons'
    )

    Write-Status 'Removing Appx Package Files...' Output
    #-----------------------------------------------------------------------remove files
    $appsPath = "$removeDir\Windows\SystemApps"
    $appsPath2 = "$removeDir\Program Files\WindowsApps"
    $appsPath3 = "$removeDir\ProgramData\Microsoft\Windows\AppRepository"
    $appsPath4 = "$removeDir\Windows\servicing\Packages"
    $appsPath5 = "$removeDir\Windows\System32\CatRoot"
    $appsPath6 = "$removeDir\Windows\SystemApps\SxS"
        
    $pathsSystemApps = (Get-ChildItem -Path $appsPath -Directory -Force).FullName 
    $pathsWindowsApps = (Get-ChildItem -Path $appsPath2 -Directory -Force).FullName 
    $pathsAppRepo = (Get-ChildItem -Path $appsPath3 -Directory -Force -Recurse).FullName 
    $pathsServicing = (Get-ChildItem -Path $appsPath4 -Directory -Force -Recurse).FullName
    $pathsCatRoot = (Get-ChildItem -Path $appsPath5 -Directory -Force -Recurse).FullName 
    $pathsSXS = (Get-ChildItem -Path $appsPath6 -Directory -Force).FullName 

    $packagesPath = @()
    #get full path
    foreach ($package in $aipackages) {
    
        foreach ($path in $pathsSystemApps) {
            if ($path -like "*$package*") {
                $packagesPath += $path
            }
        }
    
        foreach ($path in $pathsWindowsApps) {
            if ($path -like "*$package*") {
                $packagesPath += $path
            }
        }
    
        foreach ($path in $pathsAppRepo) {
            if ($path -like "*$package*") {
                $packagesPath += $path
            }
        }

        foreach ($path in $pathsSXS) {
            if ($path -like "*$package*") {
                $packagesPath += $path
            }
        }
    
    }
    
    #get additional files
    foreach ($path in $pathsServicing) {
        if ($path -like '*UserExperience-AIX*' -or $path -like '*Copilot*' -or $path -like '*UserExperience-Recall*' -or $path -like '*CoreAI*') {
            $packagesPath += $path
        }
    }
    
    foreach ($path in $pathsCatRoot) {
        if ($path -like '*UserExperience-AIX*' -or $path -like '*Copilot*' -or $path -like '*UserExperience-Recall*' -or $path -like '*CoreAI*') {
            $packagesPath += $path
        }
    }
    
        
    foreach ($Path in $packagesPath) {
        Remove-ItemForce -path $path
    }
    
    
    #remove machine learning dlls
    $paths = @(
        "$removeDir\Windows\System32\Windows.AI.MachineLearning.dll"
        "$removeDir\Windows\SysWOW64\Windows.AI.MachineLearning.dll"
        "$removeDir\Windows\System32\Windows.AI.MachineLearning.Preview.dll"
        "$removeDir\Windows\SysWOW64\Windows.AI.MachineLearning.Preview.dll"
        "$removeDir\Windows\System32\SettingsHandlers_Copilot.dll"
        "$removeDir\Windows\System32\SettingsHandlers_A9.dll"
    )
    foreach ($path in $paths) {
        Remove-ItemForce -path $path
    }
    
    #remove package installers in edge dir
    #installs Microsoft.Windows.Ai.Copilot.Provider
    $dir = "$removeDir\Program Files (x86)\Microsoft"
    $folders = @(
        'Edge',
        'EdgeCore',
        'EdgeWebView'
    )
    foreach ($folder in $folders) {
        if ($folder -eq 'EdgeCore') {
            #edge core doesnt have application folder
            $fullPath = (Get-ChildItem -Path "$dir\$folder\*.*.*.*\copilot_provider_msix" -ErrorAction SilentlyContinue).FullName
            
        }
        else {
            $fullPath = (Get-ChildItem -Path "$dir\$folder\Application\*.*.*.*\copilot_provider_msix" -ErrorAction SilentlyContinue).FullName
        }
        if ($fullPath -ne $null) { Remove-Item -Path $fullPath -Recurse -Force -ErrorAction SilentlyContinue }
    }

    Remove-ItemForce -path "$removeDir\Windows\System32\Tasks\Microsoft\Windows\WindowsAI"

}
Export-ModuleMember -Function Strip-WinAI


function Integrate-Net3 {
    param(
        [string]$removeDir,
        [string]$tempDir
    )

    Write-Status 'Getting NetFx 3.5 Status...' Output
    try {
        $netfxState = (Get-WindowsOptionalFeature -Path $removeDir -FeatureName netfx3 -ErrorAction Stop).State
    }
    catch {
        #fall back to dism
        $netfxState = ((dism /english /image:$removeDir /Get-FeatureInfo /FeatureName:NetFx3 | Select-String 'State :') -split ':')[1].trim()
    }
   
    if ($netfxState -ne 'EnablePending') {
        Write-Status 'Enabling NetFx 3.5...' Output
        try {
            Enable-WindowsOptionalFeature -Path $removeDir -FeatureName NetFX3 -All -LimitAccess -Source "$tempDir\sources\sxs" -ErrorAction Stop
        }
        catch {
            dism /Image:$removeDir /Enable-Feature /FeatureName:NetFx3 /All /LimitAccess /Source:"$tempDir\sources\sxs"
        }
    }
    else {
        Write-Status 'NetFx 3.5 Already Enabled on ISO File...' Output
    }
    

}
Export-ModuleMember -Function Integrate-Net3


function Disable-Telemetry {
    param (
        [string]$removeDir
    )

    Write-Status 'Disabling Telemetry...' Output
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'AllowTelemetry' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'DisableGraphRecentItems' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\System' /v 'AllowClipboardHistory' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\System' /v 'AllowCrossDeviceClipboard' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\System' /v 'EnableActivityFeed' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\System' /v 'PublishUserActivities' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\System' /v 'UploadUserActivities' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo' /v 'Enabled' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo' /v 'DisabledByGroupPolicy' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting' /v 'DontSendAdditionalData' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\DataCollection' /v 'AllowDeviceNameInTelemetry' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableCloudOptimizedContent' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\CloudContent' /v 'DisableWindowsConsumerFeatures' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'AllowTelemetry' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' /v 'MaxTelemetryAllowed' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\DiagTrack' /v 'Start' /t REG_DWORD /d '4' /f >$null
    Reg.exe add 'HKLM\OFFLINE_System\ControlSet001\Services\dmwappushservice' /v 'Start' /t REG_DWORD /d '4' /f >$null
    #Reg.exe add 'HKLM\OFFLINE_System\ControlSet001\Control\WMI\Autologger\Diagtrack-Listener' /v 'Start' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_Software\Policies\Microsoft\Biometrics' /v 'Enabled' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\AppV\CEIP' /v 'CEIPEnable' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\SQMClient\Windows' /v 'CEIPEnable' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\DevicePolicy\AllowTelemetry' /v 'DefaultValue' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Windows\CurrentVersion\CPSS\Store\AllowTelemetry' /v 'Value' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_Software\Policies\Microsoft\Windows\DataCollection' /v 'AllowCommercialDataPipeline' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_Software\Policies\Microsoft\Windows\DataCollection' /v 'LimitEnhancedDiagnosticDataWindowsAnalytics' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_Software\Policies\Microsoft\Windows\CloudContent' /v 'DisableTailoredExperiencesWithDiagnosticData' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\Personalization\Settings' /v 'AcceptedPrivacyPolicy' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\current\device\Bluetooth' /v 'AllowAdvertising' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\current\device\System' /v 'AllowExperimentation' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\default\Wifi\AllowAutoConnectToWiFiSenseHotspots' /v 'value' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\PolicyManager\default\Wifi\AllowWiFiHotSpotReporting' /v 'value' /t REG_DWORD /d '0' /f >$null
    #Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config' /v 'AutoConnectAllowedOEM' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\WMDRM' /v 'DisableOnline' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v 'AITEnable' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v 'DisableInventory' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v 'DisablePCA' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v 'DisablePcaRecording' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v 'DisableScriptedDiagnosticLogging' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SOFTWARE\Policies\Microsoft\Windows\AppCompat' /v 'DisableUAR' /t REG_DWORD /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\StorPort' /v 'TelemetryDeviceHealthEnabled' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\StorPort' /v 'TelemetryErrorDataEnabled' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Control\StorPort' /v 'TelemetryPerformanceEnabled' /t REG_DWORD /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\whesvc' /v 'Start' /t REG_DWORD /d '4' /f >$null
    Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\wuqisvc' /v 'Start' /t REG_DWORD /d '4' /f >$null
    Reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\Input\TIPC' /v 'Enabled' /t 'REG_DWORD' /d '0' /f >$null
    Reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitInkCollection' /t 'REG_DWORD' /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\InputPersonalization' /v 'RestrictImplicitTextCollection' /t 'REG_DWORD' /d '1' /f >$null
    Reg.exe add 'HKLM\OFFLINE_NTUSER\Software\Microsoft\InputPersonalization\TrainedDataStore' /v 'HarvestContacts' /t 'REG_DWORD' /d '0' /f >$null
    #Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\CDPSvc' /v 'Start' /t REG_DWORD /d '4' /f >$null
    #Reg.exe add 'HKLM\OFFLINE_SYSTEM\ControlSet001\Services\CDPUserSvc' /v 'Start' /t REG_DWORD /d '4' /f >$null

    #disable all the loggers under diag track
    # $subkeys = Get-ChildItem -Path 'HKLM:\OFFLINE_System\ControlSet001\Control\WMI\Autologger\Diagtrack-Listener'
    # foreach ($subkey in $subkeys) {
    #     Set-ItemProperty -Path "registry::$($subkey.Name)" -Name 'Enabled' -Value 0 -Force
    # }

    <#
    #block telemetry domains https://learn.microsoft.com/en-us/windows/privacy/configure-windows-diagnostic-data-in-your-organization
    #also extracted using https://github.com/zoicware/zScripts/blob/main/Get-TeleDomains.ps1
    $domains = @(
        'v10.events.data.microsoft.com'
        'v10c.events.data.microsoft.com'
        'v10.vortex-win.data.microsoft.com'
        'watson.telemetry.microsoft.com'
        'umwatsonc.events.data.microsoft.com'
        'ceuswatcab01.blob.core.windows.net'
        'ceuswatcab02.blob.core.windows.net'
        'eaus2watcab01.blob.core.windows.net'
        'eaus2watcab02.blob.core.windows.net'
        'weus2watcab01.blob.core.windows.net'
        'weus2watcab02.blob.core.windows.net'
        'oca.telemetry.microsoft.com'
        'oca.microsoft.com'
        'kmwatsonc.events.data.microsoft.com'
        'au.vortex-win.data.microsoft.com'
        'au-v10.events.data.microsoft.com'
        'au-v20.events.data.microsoft.com'
        'eu-v10.events.data.microsoft.com'
        'eu-v20.events.data.microsoft.com'
        'in-v10.events.data.microsoft.com'
        'in-v20.events.data.microsoft.com'
        'jp-v10.events.data.microsoft.com'
        'jp-v20.events.data.microsoft.com'
        'uk.vortex-win.data.microsoft.com'
        'uk-v20.events.data.microsoft.com'
        'us4-v20.events.data.microsoft.com'
        'us5-v20.events.data.microsoft.com'
        'us-v10.events.data.microsoft.com'
        'us-v20.events.data.microsoft.com'
        'v20.events.data.microsoft.com'
    )

    $hostsPath = "$removeDir\Windows\System32\drivers\etc\hosts"

    foreach ($domain in $domains) {
    
        Add-Content $hostsPath -Value "0.0.0.0 $domain" -Force 
        
    }
    #>

}
Export-ModuleMember -Function Disable-Telemetry


function Create-UnmountScript {
    param(
        [string]$outDir
    )

    $fullPath = "$outDir\Reset-ISOMount.cmd"

    $scriptContent = @"
@(set "0=%~f0"^)#) & powershell -nop -ExecutionPolicy Bypass -c "Unblock-File `$env:0; iex([io.file]::ReadAllText(`$env:0))" & exit /b

Write-Host 'Unloading Registry if its still loaded'
[GC]::Collect()
reg unload HKLM\OFFLINE_SOFTWARE >`$null
reg unload HKLM\OFFLINE_SYSTEM >`$null
reg unload HKLM\OFFLINE_NTUSER >`$null
reg unload HKLM\OFFLINE_DEFAULT >`$null
reg unload HKLM\OFFLINE_COMPONENTS >`$null

Write-Host 'Unmounting Image'
dism /english /unmount-image /mountdir:"$outDir\RemoveDir" /discard

Write-Host 'Removing Folders'
Remove-Item "$outDir\RemoveDir" -Recurse -Force
Remove-Item "$outDir\TEMP" -Recurse -Force

pause

"@
    

    Write-Status "Creating Reset ISO Mount Script in [$outDir]" -Type Output
    Write-Status 'Use this script if zISO Tweaker FAILS' -Type Warning
    try {
        Remove-Item $fullPath -Force -ErrorAction SilentlyContinue
    }
    catch {}

    $Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding $False
    [System.IO.File]::WriteAllLines($fullPath, $scriptContent, $Utf8NoBomEncoding)
    
    
}
Export-ModuleMember -Function Create-UnmountScript

function Create-Unattend {
    param (
        [string]$Username,
        [string]$Password,
        [string]$workingDir,
        [bool]$skipOOBE

    )

    try {
        $Password = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("$($Password)Password"))
        $ptValue = 'false'
    }
    catch {
        $Password = ''
        $ptValue = 'true'
    }
    
    if ($skipOOBE) {
        $oobe = 'true'
    }
    else {
        $oobe = 'false'
    }

    if ($Username -eq '') {
        $Username = 'Admin'
    }

  
    $unattendContent = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend"
        xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <settings pass="windowsPE">
        <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <InputLocale>0409:00000409</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-US</UserLocale>
            <SetupUILanguage>
                <UILanguage>en-US</UILanguage>
            </SetupUILanguage>
        </component>
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d 1 /f</Path>
                    <Description>BypassTPMCheck</Description>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>2</Order>
                    <Path>reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d 1 /f</Path>
                    <Description>BypassRAMCheck</Description>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>3</Order>
                    <Path>reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d 1 /f</Path>
                    <Description>BypassSecureBootCheck</Description>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>4</Order>
                    <Path>reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d 1 /f</Path>
                    <Description>BypassCPUCheck</Description>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>5</Order>
                    <Path>reg add "HKLM\SYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d 1 /f</Path>
                    <Description>BypassStorageCheck</Description>
                </RunSynchronousCommand>
            </RunSynchronous>
            <Diagnostics>
                <OptIn>false</OptIn>
            </Diagnostics>
            <DynamicUpdate>
                <Enable>false</Enable>
                <WillShowUI>OnError</WillShowUI>
            </DynamicUpdate>
            <UserData>
                <AcceptEula>true</AcceptEula>
            </UserData>
        </component>
    </settings>
    <settings pass="specialize">
        <component name="Microsoft-Windows-SQMApi" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <CEIPEnabled>0</CEIPEnabled>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <ConfigureChatAutoInstall>false</ConfigureChatAutoInstall>
        </component>
        <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <RunSynchronous>
                <RunSynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <Path>reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>2</Order>
                    <Path>net.exe accounts /maxpwage:UNLIMITED</Path>
                </RunSynchronousCommand>
                <RunSynchronousCommand wcm:action="add">
                    <Order>3</Order>
                    <Path>reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f</Path>
                </RunSynchronousCommand>
            </RunSynchronous>
        </component>
        <component name="Microsoft-Windows-Security-SPP-UX" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <SkipAutoActivation>true</SkipAutoActivation>
        </component>
        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <Identification>
                <JoinWorkgroup>WORKGROUP</JoinWorkgroup>
            </Identification>
        </component>
    </settings>
    <settings pass="oobeSystem">
        <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <InputLocale>0409:00000409</InputLocale>
            <SystemLocale>en-US</SystemLocale>
            <UILanguage>en-US</UILanguage>
            <UILanguageFallback>en-US</UILanguageFallback>
            <UserLocale>en-US</UserLocale>
        </component>
        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
            <TimeZone>Central Standard Time</TimeZone>
            <UserAccounts>
                <LocalAccounts>
                    <LocalAccount wcm:action="add">
                        <Name>$username</Name>
                        <Group>Administrators</Group>
                        <Password>
                            <Value>$password</Value>
                            <PlainText>$ptValue</PlainText>
                        </Password>
                    </LocalAccount>
                </LocalAccounts>
            </UserAccounts>
            <AutoLogon>
                <Username>$username</Username>
                <Enabled>true</Enabled>
                <LogonCount>1</LogonCount>
                <Password>
                    <Value>$password</Value>
                    <PlainText>$ptValue</PlainText>
                </Password>
            </AutoLogon>
            <OOBE>
                <HideEULAPage>$oobe</HideEULAPage>
                <HideOEMRegistrationScreen>$oobe</HideOEMRegistrationScreen>
                <HideOnlineAccountScreens>$oobe</HideOnlineAccountScreens>
                <HideWirelessSetupInOOBE>$oobe</HideWirelessSetupInOOBE>
                <NetworkLocation>Home</NetworkLocation>
                <ProtectYourPC>3</ProtectYourPC>
                <SkipMachineOOBE>$oobe</SkipMachineOOBE>
                <SkipUserOOBE>$oobe</SkipUserOOBE>
            </OOBE>
            <FirstLogonCommands>
                <SynchronousCommand wcm:action="add">
                    <Order>1</Order>
                    <CommandLine>reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoLogonCount /t REG_DWORD /d 0 /f</CommandLine>
                </SynchronousCommand>
                <SynchronousCommand wcm:action="add">
                    <Order>2</Order>
                    <CommandLine>powershell -ExecutionPolicy Bypass -File C:\Windows\FirstRun.ps1</CommandLine>
                </SynchronousCommand>
            </FirstLogonCommands>
        </component>
    </settings>
</unattend>
"@
    $unattendContent | Out-File "$env:temp\unattend.xml" -Force -Encoding utf8

    Write-Status -Message 'Adding Unattend.xml...' -Type Output
    New-Item "$workingDir\Windows\Panther" -ItemType Directory -Force | Out-Null
    New-Item "$workingDir\Windows\System32\Sysprep" -ItemType Directory -Force | Out-Null
    Copy-Item "$env:temp\unattend.xml" "$workingDir\Windows\Panther\unattend.xml" -Force
    Copy-Item "$env:temp\unattend.xml" "$workingDir\Windows\System32\Sysprep\unattend.xml" -Force
}
Export-ModuleMember -Function Create-Unattend


function Download-ISOMassgrave {
    #example Download-ISOMassgrave -outDir "E:\test\25H2.iso"
    param(
        [string]$outDir
    )
    $uri = 'https://github.com/massgravel/massgrave.dev/blob/main/docs/windows_11_links.md'

    $content = (Invoke-WebRequest -Uri $uri).RawContent
    $match = [regex]::Match($content, 'https://software-static\.download\.prss\.microsoft\.com/dbazure/[^\s"]+25h2_ge_release_svc_refresh_CLIENT_CONSUMER_x64FRE_en-us\.iso')

    if ($match.Success) {
        Write-Status 'Downloading Latest Windows 11 ISO...' Output
        Get-FileFromWeb -url $match.Value -File $outDir
        return $outDir
    }
    else {
        Write-Status 'Unable to Extract Download URL...' Error
    }
}
Export-ModuleMember -Function Download-ISOMassgrave

function install-zoicware {
    param(
        [string]$removeDir
    )

    Write-Status 'Installing Zoicware to Desktop...' Output
    $headers = @{
        'User-Agent' = 'PowerShell'
    }
    $apiUrl = 'https://api.github.com/repos/zoicware/ZOICWARE/releases/latest'
    $ProgressPreference = 'SilentlyContinue'
    $response = Invoke-RestMethod -Uri $apiUrl -Method Get -Headers $headers -UseBasicParsing -ErrorAction Stop
    $downloadUrl = $response.assets | Where-Object { $_.name -eq 'zoicwareOS.zip' } | Select-Object -ExpandProperty browser_download_url
    Invoke-WebRequest $downloadUrl -o "$env:TEMP\zoicwareOS.zip"
    Expand-Archive -Path "$env:TEMP\zoicwareOS.zip" -DestinationPath "$env:TEMP\zoicwareOS" -Force
    $desktopDir = "$removeDir\Users\Public\Desktop"
    #New-Item -ItemType Directory -Force -Path $desktopDir | Out-Null
    Move-Item "$env:TEMP\zoicwareOS" -Destination $desktopDir -Force
    Remove-Item -Path "$env:TEMP\zoicwareOS.zip" -Force -ErrorAction SilentlyContinue

}
Export-ModuleMember -Function install-zoicware

function Create-FirstRun {
    param (
        [string]$removeDir
    )

   
    Write-Status 'Creating First Run Script...' Output
    #clean up the unattend.xml since it could contain the user password making it vulnerable
    $scriptContent = @'
    Write-host "--- zISO First Run Script ---" -f Green
    Write-Host "Cleaning Up..." -f Green
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.Suggested" /v Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.StartupApp" /v Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Microsoft.SkyDrive.Desktop" /v Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.AccountHealth" /v Enabled /t REG_DWORD /d 0 /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" /v "EnableAccountNotifications" /t REG_DWORD /d "0" /f
Reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
    Stop-Process -name 'sihost' -force
    Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState\start2.bin" -Force
    $certContent = '-----BEGIN CERTIFICATE-----
4nrhSwH8TRucAIEL3m5RhU5aX0cAW7FJilySr5CE+V40mv9utV7aAZARAABc9u55
LN8F4borYyXEGl8Q5+RZ+qERszeqUhhZXDvcjTF6rgdprauITLqPgMVMbSZbRsLN
/O5uMjSLEr6nWYIwsMJkZMnZyZrhR3PugUhUKOYDqwySCY6/CPkL/Ooz/5j2R2hw
WRGqc7ZsJxDFM1DWofjUiGjDUny+Y8UjowknQVaPYao0PC4bygKEbeZqCqRvSgPa
lSc53OFqCh2FHydzl09fChaos385QvF40EDEgSO8U9/dntAeNULwuuZBi7BkWSIO
mWN1l4e+TZbtSJXwn+EINAJhRHyCSNeku21dsw+cMoLorMKnRmhJMLvE+CCdgNKI
aPo/Krizva1+bMsI8bSkV/CxaCTLXodb/NuBYCsIHY1sTvbwSBRNMPvccw43RJCU
KZRkBLkCVfW24ANbLfHXofHDMLxxFNUpBPSgzGHnueHknECcf6J4HCFBqzvSH1Tj
Q3S6J8tq2yaQ+jFNkxGRMushdXNNiTNjDFYMJNvgRL2lu606PZeypEjvPg7SkGR2
7a42GDSJ8n6HQJXFkOQPJ1mkU4qpA78U+ZAo9ccw8XQPPqE1eG7wzMGihTWfEMVs
K1nsKyEZCLYFmKwYqdIF0somFBXaL/qmEHxwlPCjwRKpwLOue0Y8fgA06xk+DMti
zWahOZNeZ54MN3N14S22D75riYEccVe3CtkDoL+4Oc2MhVdYEVtQcqtKqZ+DmmoI
5BqkECeSHZ4OCguheFckK5Eq5Yf0CKRN+RY2OJ0ZCPUyxQnWdnOi9oBcZsz2NGzY
g8ifO5s5UGscSDMQWUxPJQePDh8nPUittzJ+iplQqJYQ/9p5nKoDukzHHkSwfGms
1GiSYMUZvaze7VSWOHrgZ6dp5qc1SQy0FSacBaEu4ziwx1H7w5NZj+zj2ZbxAZhr
7Wfvt9K1xp58H66U4YT8Su7oq5JGDxuwOEbkltA7PzbFUtq65m4P4LvS4QUIBUqU
0+JRyppVN5HPe11cCPaDdWhcr3LsibWXQ7f0mK8xTtPkOUb5pA2OUIkwNlzmwwS1
Nn69/13u7HmPSyofLck77zGjjqhSV22oHhBSGEr+KagMLZlvt9pnD/3I1R1BqItW
KF3woyb/QizAqScEBsOKj7fmGA7f0KKQkpSpenF1Q/LNdyyOc77wbu2aywLGLN7H
BCdwwjjMQ43FHSQPCA3+5mQDcfhmsFtORnRZWqVKwcKWuUJ7zLEIxlANZ7rDcC30
FKmeUJuKk0Upvhsz7UXzDtNmqYmtg6vY/yPtG5Cc7XXGJxY2QJcbg1uqYI6gKtue
00Mfpjw7XpUMQbIW9rXMA9PSWX6h2ln2TwlbrRikqdQXACZyhtuzSNLK7ifSqw4O
JcZ8JrQ/xePmSd0z6O/MCTiUTFwG0E6WS1XBV1owOYi6jVif1zg75DTbXQGTNRvK
KarodfnpYg3sgTe/8OAI1YSwProuGNNh4hxK+SmljqrYmEj8BNK3MNCyIskCcQ4u
cyoJJHmsNaGFyiKp1543PktIgcs8kpF/SN86/SoB/oI7KECCCKtHNdFV8p9HO3t8
5OsgGUYgvh7Z/Z+P7UGgN1iaYn7El9XopQ/XwK9zc9FBr73+xzE5Hh4aehNVIQdM
Mb+Rfm11R0Jc4WhqBLCC3/uBRzesyKUzPoRJ9IOxCwzeFwGQ202XVlPvklXQwgHx
BfEAWZY1gaX6femNGDkRldzImxF87Sncnt9Y9uQty8u0IY3lLYNcAFoTobZmFkAQ
vuNcXxObmHk3rZNAbRLFsXnWUKGjuK5oP2TyTNlm9fMmnf/E8deez3d8KOXW9YMZ
DkA/iElnxcCKUFpwI+tWqHQ0FT96sgIP/EyhhCq6o/RnNtZvch9zW8sIGD7Lg0cq
SzPYghZuNVYwr90qt7UDekEei4CHTzgWwlSWGGCrP6Oxjk1Fe+KvH4OYwEiDwyRc
l7NRJseqpW1ODv8c3VLnTJJ4o3QPlAO6tOvon7vA1STKtXylbjWARNcWuxT41jtC
CzrAroK2r9bCij4VbwHjmpQnhYbF/hCE1r71Z5eHdWXqpSgIWeS/1avQTStsehwD
2+NGFRXI8mwLBLQN/qi8rqmKPi+fPVBjFoYDyDc35elpdzvqtN/mEp+xDrnAbwXU
yfhkZvyo2+LXFMGFLdYtWTK/+T/4n03OJH1gr6j3zkoosewKTiZeClnK/qfc8YLw
bCdwBm4uHsZ9I14OFCepfHzmXp9nN6a3u0sKi4GZpnAIjSreY4rMK8c+0FNNDLi5
DKuck7+WuGkcRrB/1G9qSdpXqVe86uNojXk9P6TlpXyL/noudwmUhUNTZyOGcmhJ
EBiaNbT2Awx5QNssAlZFuEfvPEAixBz476U8/UPb9ObHbsdcZjXNV89WhfYX04DM
9qcMhCnGq25sJPc5VC6XnNHpFeWhvV/edYESdeEVwxEcExKEAwmEZlGJdxzoAH+K
Y+xAZdgWjPPL5FaYzpXc5erALUfyT+n0UTLcjaR4AKxLnpbRqlNzrWa6xqJN9NwA
+xa38I6EXbQ5Q2kLcK6qbJAbkEL76WiFlkc5mXrGouukDvsjYdxG5Rx6OYxb41Ep
1jEtinaNfXwt/JiDZxuXCMHdKHSH40aZCRlwdAI1C5fqoUkgiDdsxkEq+mGWxMVE
Zd0Ch9zgQLlA6gYlK3gt8+dr1+OSZ0dQdp3ABqb1+0oP8xpozFc2bK3OsJvucpYB
OdmS+rfScY+N0PByGJoKbdNUHIeXv2xdhXnVjM5G3G6nxa3x8WFMJsJs2ma1xRT1
8HKqjX9Ha072PD8Zviu/bWdf5c4RrphVqvzfr9wNRpfmnGOoOcbkRE4QrL5CqrPb
VRujOBMPGAxNlvwq0w1XDOBDawZgK7660yd4MQFZk7iyZgUSXIo3ikleRSmBs+Mt
r+3Og54Cg9QLPHbQQPmiMsu21IJUh0rTgxMVBxNUNbUaPJI1lmbkTcc7HeIk0Wtg
RxwYc8aUn0f/V//c+2ZAlM6xmXmj6jIkOcfkSBd0B5z63N4trypD3m+w34bZkV1I
cQ8h7SaUUqYO5RkjStZbvk2IDFSPUExvqhCstnJf7PZGilbsFPN8lYqcIvDZdaAU
MunNh6f/RnhFwKHXoyWtNI6yK6dm1mhwy+DgPlA2nAevO+FC7Vv98Sl9zaVjaPPy
3BRyQ6kISCL065AKVPEY0ULHqtIyfU5gMvBeUa5+xbU+tUx4ZeP/BdB48/LodyYV
kkgqTafVxCvz4vgmPbnPjm/dlRbVGbyygN0Noq8vo2Ea8Z5zwO32coY2309AC7wv
Pp2wJZn6LKRmzoLWJMFm1A1Oa4RUIkEpA3AAL+5TauxfawpdtTjicoWGQ5gGNwum
+evTnGEpDimE5kUU6uiJ0rotjNpB52I+8qmbgIPkY0Fwwal5Z5yvZJ8eepQjvdZ2
UcdvlTS8oA5YayGi+ASmnJSbsr/v1OOcLmnpwPI+hRgPP+Hwu5rWkOT+SDomF1TO
n/k7NkJ967X0kPx6XtxTPgcG1aKJwZBNQDKDP17/dlZ869W3o6JdgCEvt1nIOPty
lGgvGERC0jCNRJpGml4/py7AtP0WOxrs+YS60sPKMATtiGzp34++dAmHyVEmelhK
apQBuxFl6LQN33+2NNn6L5twI4IQfnm6Cvly9r3VBO0Bi+rpjdftr60scRQM1qw+
9dEz4xL9VEL6wrnyAERLY58wmS9Zp73xXQ1mdDB+yKkGOHeIiA7tCwnNZqClQ8Mf
RnZIAeL1jcqrIsmkQNs4RTuE+ApcnE5DMcvJMgEd1fU3JDRJbaUv+w7kxj4/+G5b
IU2bfh52jUQ5gOftGEFs1LOLj4Bny2XlCiP0L7XLJTKSf0t1zj2ohQWDT5BLo0EV
5rye4hckB4QCiNyiZfavwB6ymStjwnuaS8qwjaRLw4JEeNDjSs/JC0G2ewulUyHt
kEobZO/mQLlhso2lnEaRtK1LyoD1b4IEDbTYmjaWKLR7J64iHKUpiQYPSPxcWyei
o4kcyGw+QvgmxGaKsqSBVGogOV6YuEyoaM0jlfUmi2UmQkju2iY5tzCObNQ41nsL
dKwraDrcjrn4CAKPMMfeUSvYWP559EFfDhDSK6Os6Sbo8R6Zoa7C2NdAicA1jPbt
5ENSrVKf7TOrthvNH9vb1mZC1X2RBmriowa/iT+LEbmQnAkA6Y1tCbpzvrL+cX8K
pUTOAovaiPbab0xzFP7QXc1uK0XA+M1wQ9OF3XGp8PS5QRgSTwMpQXW2iMqihYPv
Hu6U1hhkyfzYZzoJCjVsY2xghJmjKiKEfX0w3RaxfrJkF8ePY9SexnVUNXJ1654/
PQzDKsW58Au9QpIH9VSwKNpv003PksOpobM6G52ouCFOk6HFzSLfnlGZW0yyUQL3
RRyEE2PP0LwQEuk2gxrW8eVy9elqn43S8CG2h2NUtmQULc/IeX63tmCOmOS0emW9
66EljNdMk/e5dTo5XplTJRxRydXcQpgy9bQuntFwPPoo0fXfXlirKsav2rPSWayw
KQK4NxinT+yQh//COeQDYkK01urc2G7SxZ6H0k6uo8xVp9tDCYqHk/lbvukoN0RF
tUI4aLWuKet1O1s1uUAxjd50ELks5iwoqLJ/1bzSmTRMifehP07sbK/N1f4hLae+
jykYgzDWNfNvmPEiz0DwO/rCQTP6x69g+NJaFlmPFwGsKfxP8HqiNWQ6D3irZYcQ
R5Mt2Iwzz2ZWA7B2WLYZWndRCosRVWyPdGhs7gkmLPZ+WWo/Yb7O1kIiWGfVuPNA
MKmgPPjZy8DhZfq5kX20KF6uA0JOZOciXhc0PPAUEy/iQAtzSDYjmJ8HR7l4mYsT
O3Mg3QibMK8MGGa4tEM8OPGktAV5B2J2QOe0f1r3vi3QmM+yukBaabwlJ+dUDQGm
+Ll/1mO5TS+BlWMEAi13cB5bPRsxkzpabxq5kyQwh4vcMuLI0BOIfE2pDKny5jhW
0C4zzv3avYaJh2ts6kvlvTKiSMeXcnK6onKHT89fWQ7Hzr/W8QbR/GnIWBbJMoTc
WcgmW4fO3AC+YlnLVK4kBmnBmsLzLh6M2LOabhxKN8+0Oeoouww7g0HgHkDyt+MS
97po6SETwrdqEFslylLo8+GifFI1bb68H79iEwjXojxQXcD5qqJPxdHsA32eWV0b
qXAVojyAk7kQJfDIK+Y1q9T6KI4ew4t6iauJ8iVJyClnHt8z/4cXdMX37EvJ+2BS
YKHv5OAfS7/9ZpKgILT8NxghgvguLB7G9sWNHntExPtuRLL4/asYFYSAJxUPm7U2
xnp35Zx5jCXesd5OlKNdmhXq519cLl0RGZfH2ZIAEf1hNZqDuKesZ2enykjFlIec
hZsLvEW/pJQnW0+LFz9N3x3vJwxbC7oDgd7A2u0I69Tkdzlc6FFJcfGabT5C3eF2
EAC+toIobJY9hpxdkeukSuxVwin9zuBoUM4X9x/FvgfIE0dKLpzsFyMNlO4taCLc
v1zbgUk2sR91JmbiCbqHglTzQaVMLhPwd8GU55AvYCGMOsSg3p952UkeoxRSeZRp
jQHr4bLN90cqNcrD3h5knmC61nDKf8e+vRZO8CVYR1eb3LsMz12vhTJGaQ4jd0Kz
QyosjcB73wnE9b/rxfG1dRactg7zRU2BfBK/CHpIFJH+XztwMJxn27foSvCY6ktd
uJorJvkGJOgwg0f+oHKDvOTWFO1GSqEZ5BwXKGH0t0udZyXQGgZWvF5s/ojZVcK3
IXz4tKhwrI1ZKnZwL9R2zrpMJ4w6smQgipP0yzzi0ZvsOXRksQJNCn4UPLBhbu+C
eFBbpfe9wJFLD+8F9EY6GlY2W9AKD5/zNUCj6ws8lBn3aRfNPE+Cxy+IKC1NdKLw
eFdOGZr2y1K2IkdefmN9cLZQ/CVXkw8Qw2nOr/ntwuFV/tvJoPW2EOzRmF2XO8mQ
DQv51k5/v4ZE2VL0dIIvj1M+KPw0nSs271QgJanYwK3CpFluK/1ilEi7JKDikT8X
TSz1QZdkum5Y3uC7wc7paXh1rm11nwluCC7jiA==
-----END CERTIFICATE-----
'
New-Item "$env:TEMP\start2.txt" -Value $certContent -Force | Out-Null
certutil.exe -decode "$env:TEMP\start2.txt" "$env:TEMP\start2.bin" >$null
Copy-Item "$env:TEMP\start2.bin" -Destination "$env:USERPROFILE\AppData\Local\Packages\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\LocalState" -Force | Out-Null
Remove-Item "$env:TEMP\start2.txt" -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\start2.bin" -Force -ErrorAction SilentlyContinue
#$OS = Get-CimInstance Win32_OperatingSystem
#if ($OS.BuildNumber -le 26100) {
    reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start' /v 'HideRecommendedSection' /t REG_DWORD /d '1' /f
    reg.exe add 'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Education' /v 'IsEducationEnvironment' /t REG_DWORD /d '1' /f
    reg.exe add 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer' /v 'HideRecommendedSection' /t REG_DWORD /d '1' /f
#}
#else {
    reg.exe add 'HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' /v 'Start_IrisRecommendations' /t REG_DWORD /d '0' /f
#}
Remove-item C:\Windows\Panther\unattend.xml -force
Remove-item C:\Windows\System32\Sysprep\unattend.xml -force
sleep 5
taskkill /im explorer.exe /f
start explorer
sleep 2
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v "FavoritesResolve" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v "Favorites" /f
Reg.exe delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v "FavoritesChanges" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v "FavoritesResolve" /t REG_BINARY /d "330300004c0000000114020000000000c00000000000004683008000200000007a0502220555dc016e2205220555dc0125b37a4d0584da01970100000000000001000000000000000000000000000000a0013a001f80c827341f105c1042aa032ee45287d668260001002600efbe12000000b99ccf100555dc0147a100220555dc017ae503220555dc01140056003100000000006e5bcd0a11005461736b42617200400009000400efbe6e5bcd0a6e5bcd0a2e000000a46401000000020000000000000000000000000000004e7db4005400610073006b00420061007200000016000e013200970100008158c43a200046494c4545587e312e4c4e4b00007c0009000400efbe6e5bcd0a6e5bcd0a2e000000a5640100000002000000000000000000520000000000dbdc9100460069006c00650020004500780070006c006f007200650072002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200320030003600370000001c00220000001e00efbe02005500730065007200500069006e006e006500640000001c00120000002b00efbeabe204220555dc011c00420000001d00efbe02004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004500780070006c006f0072006500720000001c0000009c0000001c000000010000001c0000002d000000000000009b0000001100000003000000a1bc24a41000000000433a5c55736572735c41646d696e5c417070446174615c526f616d696e675c4d6963726f736f66745c496e7465726e6574204578706c6f7265725c517569636b204c61756e63685c557365722050696e6e65645c5461736b4261725c46696c65204578706c6f7265722e6c6e6b000060000000030000a058000000000000006465736b746f702d716568396b376200c0a346a20c619748b8ba44df7253c26abd0f193911c1f011a921080027b5ae6dc0a346a20c619748b8ba44df7253c26abd0f193911c1f011a921080027b5ae6d45000000090000a03900000031535053b1166d44ad8d7048a748402ea43d788c1d000000680000000048000000e6ab4256b74fb24a9387a6c9d5c6522c000000000000000000000000" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v "Favorites" /t REG_BINARY /d "00a40100003a001f80c827341f105c1042aa032ee45287d668260001002600efbe12000000b99ccf100555dc0147a100220555dc017ae503220555dc01140056003100000000006e5bcd0a11005461736b42617200400009000400efbe6e5bcd0a6e5bcd0a2e000000a46401000000020000000000000000000000000000004e7db4005400610073006b004200610072000000160012013200970100008158c43a200046494c4545587e312e4c4e4b00007c0009000400efbe6e5bcd0a6e5bcd0a2e000000a5640100000002000000000000000000520000000000dbdc9100460069006c00650020004500780070006c006f007200650072002e006c006e006b00000040007300680065006c006c00330032002e0064006c006c002c002d003200320030003600370000001c00120000002b00efbeabe204220555dc011c00420000001d00efbe02004d006900630072006f0073006f00660074002e00570069006e0064006f00770073002e004500780070006c006f0072006500720000001c00260000001e00efbe0200530079007300740065006d00500069006e006e006500640000001c000000ff" /f
Reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband" /v "FavoritesChanges" /t REG_DWORD /d "8" /f
taskkill /im explorer.exe /f
start explorer
'@
    New-Item "$removeDir\Windows\FirstRun.ps1" -ItemType File -Force | Out-Null
    Set-Content "$removeDir\Windows\FirstRun.ps1" -Value $scriptContent -Force
    
}
Export-ModuleMember -Function Create-FirstRun

function Mount-Edition {
    param (
        [string]$imagePath,
        [string]$workingDir,
        $index,
        [string]$edition

    )
    
    #check for file explorer open
    $explorerCount = (New-Object -ComObject Shell.Application).Windows().Count
    if ($explorerCount -ne 0) {
        [System.Windows.Forms.MessageBox]::Show('Please Make Sure File Explorer is Closed While Tweaking the ISO File.', 'zISO Tweaker', [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
    $outDir = Split-Path $workingDir -Parent

    Create-UnmountScript -outDir $outDir
    Write-Status -Message "Mounting Edition: $edition" -Type Output 
    Mount-WindowsImage -ImagePath $imagePath -Index $index -Path $workingDir | Out-Null

}
Export-ModuleMember -Function Mount-Edition






function Display-UI {
    
    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Xaml

    $buttonTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="Button">
  <Border Name="border" Background="{TemplateBinding Background}" 
          CornerRadius="4" BorderThickness="{TemplateBinding BorderThickness}" 
          BorderBrush="{TemplateBinding BorderBrush}"
          SnapsToDevicePixels="True">
    <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
  </Border>
  <ControlTemplate.Triggers>
    <Trigger Property="IsMouseOver" Value="True">
      <Setter TargetName="border" Property="Background" Value="#FF1084D8"/>
    </Trigger>
    <Trigger Property="IsPressed" Value="True">
      <Setter TargetName="border" Property="Background" Value="#FF005A9E"/>
    </Trigger>
    <Trigger Property="IsEnabled" Value="False">
      <Setter TargetName="border" Property="Background" Value="#FF2D2D30"/>
      <Setter TargetName="border" Property="Opacity" Value="0.6"/>
    </Trigger>
  </ControlTemplate.Triggers>
</ControlTemplate>
'@

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]$buttonTemplate)
    $buttonControlTemplate = [Windows.Markup.XamlReader]::Load($reader)
    $reader.Close()

    $textBoxTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="TextBox">
  <Border Name="border" Background="{TemplateBinding Background}" 
          CornerRadius="4" BorderThickness="{TemplateBinding BorderThickness}" 
          BorderBrush="{TemplateBinding BorderBrush}"
          SnapsToDevicePixels="True">
    <ScrollViewer Name="PART_ContentHost" Focusable="False" 
                  HorizontalScrollBarVisibility="Hidden" 
                  VerticalScrollBarVisibility="Hidden"
                  Margin="8,6,8,6"/>
  </Border>
  <ControlTemplate.Triggers>
    <Trigger Property="IsMouseOver" Value="True">
      <Setter TargetName="border" Property="BorderBrush" Value="#FF0078D4"/>
    </Trigger>
    <Trigger Property="IsFocused" Value="True">
      <Setter TargetName="border" Property="BorderBrush" Value="#FF0078D4"/>
      <Setter TargetName="border" Property="BorderThickness" Value="2"/>
    </Trigger>
    <Trigger Property="IsEnabled" Value="False">
      <Setter TargetName="border" Property="Opacity" Value="0.6"/>
    </Trigger>
  </ControlTemplate.Triggers>
</ControlTemplate>
'@

    $reader2 = [System.Xml.XmlReader]::Create([System.IO.StringReader]$textBoxTemplate)
    $textBoxControlTemplate = [Windows.Markup.XamlReader]::Load($reader2)
    $reader2.Close()

    $passwordBoxTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" TargetType="PasswordBox">
  <Border Name="border" Background="{TemplateBinding Background}" 
          CornerRadius="4" BorderThickness="{TemplateBinding BorderThickness}" 
          BorderBrush="{TemplateBinding BorderBrush}"
          SnapsToDevicePixels="True">
    <ScrollViewer Name="PART_ContentHost" Focusable="False" 
                  HorizontalScrollBarVisibility="Hidden" 
                  VerticalScrollBarVisibility="Hidden"
                  Margin="8,6,8,6"/>
  </Border>
  <ControlTemplate.Triggers>
    <Trigger Property="IsMouseOver" Value="True">
      <Setter TargetName="border" Property="BorderBrush" Value="#FF0078D4"/>
    </Trigger>
    <Trigger Property="IsFocused" Value="True">
      <Setter TargetName="border" Property="BorderBrush" Value="#FF0078D4"/>
      <Setter TargetName="border" Property="BorderThickness" Value="2"/>
    </Trigger>
    <Trigger Property="IsEnabled" Value="False">
      <Setter TargetName="border" Property="Opacity" Value="0.6"/>
    </Trigger>
  </ControlTemplate.Triggers>
</ControlTemplate>
'@

    $reader2b = [System.Xml.XmlReader]::Create([System.IO.StringReader]$passwordBoxTemplate)
    $passwordBoxControlTemplate = [Windows.Markup.XamlReader]::Load($reader2b)
    $reader2b.Close()


    $comboBoxTemplate = @'
<ControlTemplate xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation" 
                 TargetType="ComboBox">
    <Grid>
        <ToggleButton Name="ToggleButton" 
                      Focusable="false"
                      IsChecked="{Binding Path=IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"
                      ClickMode="Press"
                      Background="{TemplateBinding Background}"
                      BorderBrush="{TemplateBinding BorderBrush}"
                      BorderThickness="{TemplateBinding BorderThickness}">
            <ToggleButton.Template>
                <ControlTemplate TargetType="ToggleButton">
                    <Border Background="{TemplateBinding Background}"
                            BorderBrush="{TemplateBinding BorderBrush}"
                            BorderThickness="{TemplateBinding BorderThickness}"
                            CornerRadius="4">
                        <Grid>
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="20"/>
                            </Grid.ColumnDefinitions>
                            <Path Grid.Column="1" 
                                  Data="M 0 0 L 4 4 L 8 0 Z" 
                                  Fill="Black"
                                  HorizontalAlignment="Center"
                                  VerticalAlignment="Center"/>
                        </Grid>
                    </Border>
                </ControlTemplate>
            </ToggleButton.Template>
        </ToggleButton>
        <ContentPresenter Name="ContentSite"
                          IsHitTestVisible="False"
                          Content="{TemplateBinding SelectionBoxItem}"
                          Margin="8,6,28,6"
                          VerticalAlignment="Center"
                          HorizontalAlignment="Left" />
        <Popup Name="Popup"
               Placement="Bottom"
               IsOpen="{TemplateBinding IsDropDownOpen}"
               AllowsTransparency="True"
               Focusable="False"
               PopupAnimation="Slide">
            <Grid MinWidth="{TemplateBinding ActualWidth}"
                  MaxHeight="{TemplateBinding MaxDropDownHeight}">
                <Border Background="White"
                        BorderThickness="1"
                        BorderBrush="#FF3F3F46"
                        CornerRadius="4">
                    <ScrollViewer Margin="4,6,4,6">
                        <StackPanel IsItemsHost="True" />
                    </ScrollViewer>
                </Border>
            </Grid>
        </Popup>
    </Grid>
</ControlTemplate>
'@

    
    $reader3 = [System.Xml.XmlReader]::Create([System.IO.StringReader]$comboBoxTemplate)
    $comboBoxControlTemplate = [Windows.Markup.XamlReader]::Load($reader3)
    $reader3.Close()
   

    # Color scheme 
    $colors = @{
        Background    = '#FF1E1E1E'
        Surface       = '#FF2D2D30'
        SurfaceHover  = '#FF3E3E42'
        Primary       = '#FF0e629e'
        PrimaryHover  = '#FF0e629e'
        Text          = '#FFFFFFFF'
        TextSecondary = '#FFB0B0B0'
        Border        = '#FF3F3F46'
        Accent        = '#FF0e629e'
    }
    function New-StyledButton {
        param([string]$Content, [int]$Width = 120)
    
        $btn = New-Object System.Windows.Controls.Button
        $btn.Content = $Content
        $btn.Width = $Width
        $btn.Height = 32
        $btn.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Primary)
        $btn.Foreground = [System.Windows.Media.Brushes]::White
        $btn.BorderThickness = 0
        $btn.Cursor = [System.Windows.Input.Cursors]::Hand
        $btn.FontSize = 13
        $btn.Margin = '5'
        $btn.Template = $buttonControlTemplate
    
        $style = New-Object System.Windows.Style([System.Windows.Controls.Button])
    
        $disabledTrigger = New-Object System.Windows.Trigger
        $disabledTrigger.Property = [System.Windows.Controls.Control]::IsEnabledProperty
        $disabledTrigger.Value = $false
        $disabledTrigger.Setters.Add((New-Object System.Windows.Setter([System.Windows.Controls.Control]::ForegroundProperty, [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.TextSecondary))))
    
        $style.Triggers.Add($disabledTrigger)
        $btn.Style = $style
    
        return $btn
    }
    
    function New-StyledTextBox {
        param([string]$Text = '', [int]$Width = 400)
        
        $tb = New-Object System.Windows.Controls.TextBox
        $tb.Text = $Text
        $tb.Width = $Width
        $tb.Height = 32
        $tb.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Surface)
        $tb.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Text)
        $tb.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Border)
        $tb.BorderThickness = 1
        $tb.FontSize = 13
        $tb.Margin = '5'
        $tb.Template = $textBoxControlTemplate
    
        return $tb
    }
    
    function New-StyledCheckBox {
        param([string]$Content)
        
        $cb = New-Object System.Windows.Controls.CheckBox
        $cb.Content = $Content
        $cb.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Text)
        $cb.FontSize = 13
        $cb.Margin = '5,3'
        
        return $cb
    }
    
    function New-StyledLabel {
        param([string]$Content, [int]$FontSize = 13, [bool]$IsBold = $false)
        
        $lbl = New-Object System.Windows.Controls.Label
        $lbl.Content = $Content
        $lbl.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Text)
        $lbl.FontSize = $FontSize
        if ($IsBold) { $lbl.FontWeight = 'Bold' }
        $lbl.Margin = '5'
        
        return $lbl
    }
    
    function New-StyledGroupBox {
        param([string]$Header)
        
        $gb = New-Object System.Windows.Controls.GroupBox
        $gb.Header = $Header
        $gb.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Text)
        $gb.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Border)
        $gb.Margin = '10,5'
        $gb.Padding = '10'
        $gb.FontSize = 14
        $gb.FontWeight = 'SemiBold'
        
        return $gb
    }
    
    function New-StyledComboBox {
        param([int]$Width = 400)
        
        $cb = New-Object System.Windows.Controls.ComboBox
        $cb.Width = $Width
        $cb.Height = 32
        $cb.Background = [System.Windows.Media.Brushes]::White
        $cb.Foreground = [System.Windows.Media.Brushes]::Black
        $cb.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Border)
        $cb.BorderThickness = 1
        $cb.FontSize = 13
        $cb.Margin = '5'
        $cb.Padding = '8,6'
        $cb.Template = $comboBoxControlTemplate
    
        return $cb
    }
    
    $window = New-Object System.Windows.Window
    $window.Title = 'zISO Tweaker'
    $window.Width = 900
    $window.Height = 700
    $window.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Background)
    $window.WindowStartupLocation = 'CenterScreen'
    
    $scrollViewer = New-Object System.Windows.Controls.ScrollViewer
    $scrollViewer.VerticalScrollBarVisibility = 'Auto'
    $scrollViewer.Padding = '10'

    $mainStack = New-Object System.Windows.Controls.StackPanel
    $mainStack.Margin = '10'
    
    $title = New-StyledLabel -Content 'zISO Tweaker' -FontSize 24 -IsBold $true
    $title.HorizontalAlignment = 'Center'
    $title.Margin = '0,10,0,20'
    $mainStack.AddChild($title)

    $helpPanel = New-Object System.Windows.Controls.DockPanel
    $helpPanel.LastChildFill = $false
    $helpPanel.Margin = '0,0,0,10'

    $helpButton = New-StyledButton -Content '? Help' -Width 80
    $helpButton.HorizontalAlignment = 'Right'
    [System.Windows.Controls.DockPanel]::SetDock($helpButton, [System.Windows.Controls.Dock]::Right)

    $helpButton.Add_Click({
            
            $helpWindow = New-Object System.Windows.Window
            $helpWindow.Title = 'zISO Tweaker - Help Guide'
            $helpWindow.Width = 650
            $helpWindow.Height = 550
            $helpWindow.WindowStartupLocation = 'CenterScreen'
            $helpWindow.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Background)
    
            $helpScrollViewer = New-Object System.Windows.Controls.ScrollViewer
            $helpScrollViewer.VerticalScrollBarVisibility = 'Auto'
            $helpScrollViewer.Padding = '20'
    
            $helpStack = New-Object System.Windows.Controls.StackPanel
            $helpStack.Margin = '10'
    
            $helpTitle = New-StyledLabel -Content 'How to Use zISO Tweaker' -FontSize 20 -IsBold $true
            $helpTitle.HorizontalAlignment = 'Center'
            $helpTitle.Margin = '0,0,0,15'
            $helpStack.AddChild($helpTitle)
    
            $step1Header = New-StyledLabel -Content '1. Select or Download ISO' -FontSize 14 -IsBold $true
            $step1Header.Margin = '0,10,0,5'
            $helpStack.AddChild($step1Header)
    
            $step1Text = New-StyledLabel -Content "$([char]0x2022) Download from Massgrave (25H2 Official ISO) or UUPDump (23H2/24H2/25H2 Enterprise)`n$([char]0x2022) Or browse for an existing Windows ISO file`n$([char]0x2022) Select an output directory for the modified ISO"
            $step1Text.FontSize = 12
            $step1Text.Margin = '15,0,0,0'
            $helpStack.AddChild($step1Text)
    
            $step2Header = New-StyledLabel -Content '2. Mount ISO & Select Edition' -FontSize 14 -IsBold $true
            $step2Header.Margin = '0,10,0,5'
            $helpStack.AddChild($step2Header)
    
            $step2Text = New-StyledLabel -Content "$([char]0x2022) Click 'Mount ISO & Detect Editions' to prepare the ISO`n$([char]0x2022) Select which Windows edition you want to customize (Home, Pro, etc.)`n$([char]0x2022) This step is required before using the debloat options"
            $step2Text.FontSize = 12
            $step2Text.Margin = '15,0,0,0'
            $helpStack.AddChild($step2Text)
    
            $step3Header = New-StyledLabel -Content '3. Configure Account & OOBE' -FontSize 14 -IsBold $true
            $step3Header.Margin = '0,10,0,5'
            $helpStack.AddChild($step3Header)
    
            $step3Text = New-StyledLabel -Content "$([char]0x2022) Set a default username and password (optional, password and username can be left blank)`n$([char]0x2022) Skip OOBE (Out-of-Box Experience) for faster installation (recommended)"
            $step3Text.FontSize = 12
            $step3Text.Margin = '15,0,0,0'
            $helpStack.AddChild($step3Text)
    
            $step4Header = New-StyledLabel -Content '4. Windows Updates & Security' -FontSize 14 -IsBold $true
            $step4Header.Margin = '0,10,0,5'
            $helpStack.AddChild($step4Header)
    
            $step4Text = New-StyledLabel -Content "$([char]0x2022) Control Windows Update behavior (disable, security only, etc.)`n$([char]0x2022) Remove Windows Defender and other security features if desired`n$([char]0x2022) Disable security mitigations and BitLocker"
            $step4Text.FontSize = 12
            $step4Text.Margin = '15,0,0,0'
            $helpStack.AddChild($step4Text)
    
            $step5Header = New-StyledLabel -Content '5. Debloat & Remove Apps' -FontSize 14 -IsBold $true
            $step5Header.Margin = '0,10,0,5'
            $helpStack.AddChild($step5Header)
    
            $step5Text = New-StyledLabel -Content "$([char]0x2022) Quick removal: Edge, OneDrive, Windows AI`n$([char]0x2022) Advanced: Click buttons to select specific packages:`n  - AppX Packages (Store apps like Xbox, Mail, etc.)`n  - OS Packages (System components)`n  - Windows Capabilities (Optional features)`n  - Windows Features (Legacy features)`n$([char]0x2022) Use search to filter, Select All/Deselect All for bulk operations"
            $step5Text.FontSize = 12
            $step5Text.Margin = '15,0,0,0'
            $helpStack.AddChild($step5Text)
    
            $step6Header = New-StyledLabel -Content '6. Start Tweaking' -FontSize 14 -IsBold $true
            $step6Header.Margin = '0,10,0,5'
            $helpStack.AddChild($step6Header)
    
            $step6Text = New-StyledLabel -Content "$([char]0x2022) Review your selections`n$([char]0x2022) Click 'Start Tweaking' to begin the modification process`n$([char]0x2022) The tool will create a new customized ISO in your output directory`n$([char]0x2022) This process may take several minutes depending on your selections"
            $step6Text.FontSize = 12
            $step6Text.Margin = '15,0,0,0'
            $helpStack.AddChild($step6Text)
 
            $separator = New-Object System.Windows.Controls.Separator
            $separator.Margin = '0,15,0,15'
            $separator.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Border)
            $helpStack.AddChild($separator)
    
            $tipsHeader = New-StyledLabel -Content 'Tips & Notes' -FontSize 14 -IsBold $true
            $tipsHeader.Margin = '0,5,0,5'
            $helpStack.AddChild($tipsHeader)
    
            $tipsText = New-StyledLabel -Content "$([char]0x2022) When creating the bootable media with Rufus or Ventoy DO NOT select any of the tweaks`n$([char]0x2022) Ensure you have enough disk space (at least 2x the ISO size)`n$([char]0x2022) Windows 11 requirements are disabled along with other annoyances`n$([char]0x2022) No drivers will be auto installed when selecting security updates only or disable updates`n$([char]0x2022) Zoicware will be installed to the desktop to ensure you can install a browser/network driver"
            $tipsText.FontSize = 12
            $tipsText.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.TextSecondary)
            $tipsText.Margin = '15,0,0,0'
            $helpStack.AddChild($tipsText)
    
            $closeButtonPanel = New-Object System.Windows.Controls.StackPanel
            $closeButtonPanel.Orientation = 'Horizontal'
            $closeButtonPanel.HorizontalAlignment = 'Center'
            $closeButtonPanel.Margin = '0,20,0,0'
    
            $closeHelpButton = New-StyledButton -Content 'Close' -Width 100
            $closeHelpButton.Add_Click({
                    $helpWindow.Close()
                })
    
            $closeButtonPanel.AddChild($closeHelpButton)
            $helpStack.AddChild($closeButtonPanel)
    
            $helpScrollViewer.Content = $helpStack
            $helpWindow.Content = $helpScrollViewer
            $helpWindow.ShowDialog() | Out-Null
        })

    $helpPanel.Children.Add($helpButton)
    $mainStack.AddChild($helpPanel)
    
    # === 1. ISO Selection ===
    $isoGroup = New-StyledGroupBox -Header '1. ISO Selection'
    $isoStack = New-Object System.Windows.Controls.StackPanel

    $downloadSection = New-Object System.Windows.Controls.StackPanel
    $downloadSection.Margin = '0,0,0,15'

    $downloadLabel = New-StyledLabel -Content 'Download ISO:'
    $downloadLabel.FontWeight = 'SemiBold'
    $downloadSection.AddChild($downloadLabel)

    $downloadButtonsPanel = New-Object System.Windows.Controls.StackPanel
    $downloadButtonsPanel.Orientation = 'Horizontal'
    $downloadButtonsPanel.Margin = '5,0,0,0'

    $massgraveButton = New-StyledButton -Content 'Massgrave (25H2 Latest)' -Width 180
    $massgraveButton.Add_Click({
            $result = [System.Windows.MessageBox]::Show("Download Windows 11 25H2 latest from Massgrave?`n`nThis will download to your selected output directory.", 'Download ISO', 'YesNo', 'Question')
            if ($result -eq 'Yes') {
                if ([string]::IsNullOrWhiteSpace($outputTextBox.Text)) {
                    [System.Windows.MessageBox]::Show('Please select an output directory first.', 'Error', 'OK', 'Warning')
                    return
                }
        
                $massgraveButton.IsEnabled = $false
                $uupDumpButton.IsEnabled = $false
                $massgraveButton.Content = 'Downloading...'
        
                try {
                    $isoPath = Download-ISOMassgrave -outDir "$($outputTextBox.Text)\25h2_ge_release_svc_refresh_CLIENT_CONSUMER_x64FRE_en-us.iso"
                    $isoFileTextBox.Text = $isoPath
                }
                catch {
                    [System.Windows.MessageBox]::Show("Download failed: $($_.Exception.Message)", 'Error', 'OK', 'Error')
                }
                finally {
                    $massgraveButton.IsEnabled = $true
                    $uupDumpButton.IsEnabled = $true
                    $massgraveButton.Content = 'MassGrave (25H2 Latest)'
                }
            }
        })

    $uupDumpButton = New-StyledButton -Content 'UUPDump (Enterprise)' -Width 180
    $uupDumpButton.Add_Click({
         
            $versionWindow = New-Object System.Windows.Window
            $versionWindow.Title = 'Select Windows Version'
            $versionWindow.Width = 400
            $versionWindow.Height = 250
            $versionWindow.WindowStartupLocation = 'CenterScreen'
            $versionWindow.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Background)
    
            $versionStack = New-Object System.Windows.Controls.StackPanel
            $versionStack.Margin = '20'
    
            $versionTitle = New-StyledLabel -Content 'Select Windows 11 Enterprise Edition:' -FontSize 14 -IsBold $true
            $versionStack.AddChild($versionTitle)
    
            $version23h2 = New-StyledButton -Content 'Windows 11 23H2 Enterprise' -Width 300
            $version23h2.Margin = '0,10,0,5'
            $version23h2.Add_Click({
                    $versionWindow.Tag = '23H2'
                    $versionWindow.Close()
                })
    
            $version24h2 = New-StyledButton -Content 'Windows 11 24H2 Enterprise' -Width 300
            $version24h2.Margin = '0,5,0,5'
            $version24h2.Add_Click({
                    $versionWindow.Tag = '24H2'
                    $versionWindow.Close()
                })
    
            $version25h2 = New-StyledButton -Content 'Windows 11 25H2 Enterprise' -Width 300
            $version25h2.Margin = '0,5,0,5'
            $version25h2.Add_Click({
                    $versionWindow.Tag = '25H2'
                    $versionWindow.Close()
                })
    
            $cancelVersionButton = New-StyledButton -Content 'Cancel' -Width 300
            $cancelVersionButton.Margin = '0,15,0,0'
            $cancelVersionButton.Add_Click({
                    $versionWindow.Close()
                })
    
            $versionStack.AddChild($version23h2)
            $versionStack.AddChild($version24h2)
            $versionStack.AddChild($version25h2)
            $versionStack.AddChild($cancelVersionButton)
    
            $versionWindow.Content = $versionStack
            $versionWindow.ShowDialog() | Out-Null
    
            $selectedVersion = $versionWindow.Tag
    
            if ($selectedVersion -ne $null) {
                if ([string]::IsNullOrWhiteSpace($outputTextBox.Text)) {
                    [System.Windows.MessageBox]::Show('Please select an output directory first.', 'Error', 'OK', 'Warning')
                    return
                }
        
                
                $massgraveButton.IsEnabled = $false
                $uupDumpButton.IsEnabled = $false
                $uupDumpButton.Content = "Downloading $selectedVersion..."
        
                try {
                    $outputDir = $outputTextBox.Text
                    switch ($selectedVersion) {
                        '23H2' { 
                            Start-Process powershell -ArgumentList "-command `".`'$PSScriptRoot\uup-dump-get-windows-iso.ps1`'; UUP-Dump-GetISO -windowsTargetName 'windows11-23H2-E' -destinationDirectory '$outputDir'`"" -Wait
                            $isoPath = "$outputDir\windows11-23H2-E.iso"
                        }
                        '24H2' {
                            Start-Process powershell -ArgumentList "-command `".`'$PSScriptRoot\uup-dump-get-windows-iso.ps1`'; UUP-Dump-GetISO -windowsTargetName 'windows11-24H2-E' -destinationDirectory '$outputDir'`"" -Wait
                            $isoPath = "$outputDir\windows11-24H2-E.iso"
                        }
                        '25H2' {
                            Start-Process powershell -ArgumentList "-command `".`'$PSScriptRoot\uup-dump-get-windows-iso.ps1`'; UUP-Dump-GetISO -windowsTargetName 'windows11-25H2-E' -destinationDirectory '$outputDir'`"" -Wait
                            $isoPath = "$outputDir\windows11-25H2-E.iso"
                        }
    
                    }
                    
                    $isoFileTextBox.Text = $isoPath
            
                }
                catch {
                    [System.Windows.MessageBox]::Show("Download failed: $($_.Exception.Message)", 'Error', 'OK', 'Error')
                }
                finally {
                    $massgraveButton.IsEnabled = $true
                    $uupDumpButton.IsEnabled = $true
                    $uupDumpButton.Content = 'UUPDump (Enterprise)'
                }
            }
        })

    $downloadButtonsPanel.AddChild($massgraveButton)
    $downloadButtonsPanel.AddChild($uupDumpButton)
    $downloadSection.AddChild($downloadButtonsPanel)

    $isoStack.AddChild($downloadSection)

    $separator = New-Object System.Windows.Controls.Separator
    $separator.Margin = '0,10,0,15'
    $separator.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Border)
    $isoStack.AddChild($separator)

    $orLabel = New-StyledLabel -Content 'Or select existing ISO file:'
    $orLabel.FontWeight = 'SemiBold'
    $isoStack.AddChild($orLabel)

    $isoFilePanel = New-Object System.Windows.Controls.StackPanel
    $isoFilePanel.Orientation = 'Horizontal'
    $isoFileLabel = New-StyledLabel -Content 'ISO File:'
    $isoFileTextBox = New-StyledTextBox -Width 300
    $isoFileBrowse = New-StyledButton -Content 'Browse...' -Width 100
    $isoFileBrowse.Add_Click({
            $dialog = New-Object System.Windows.Forms.OpenFileDialog
            $dialog.Filter = 'ISO Files (*.iso)|*.iso'
            if ($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $isoFileTextBox.Text = $dialog.FileName
            }
        })
    $isoFilePanel.AddChild($isoFileLabel)
    $isoFilePanel.AddChild($isoFileTextBox)
    $isoFilePanel.AddChild($isoFileBrowse)
    $isoStack.AddChild($isoFilePanel)

    $outputPanel = New-Object System.Windows.Controls.StackPanel
    $outputPanel.Orientation = 'Horizontal'
    $outputLabel = New-StyledLabel -Content 'Output Directory:'
    $outputTextBox = New-StyledTextBox -Width 300
    $outputBrowse = New-StyledButton -Content 'Browse...' -Width 100
    $outputBrowse.Add_Click({
            $outPath = Show-ModernFilePicker -Mode Folder
            if ($outPath -ne '') {
                $outputTextBox.Text = $outPath
            }
        })
    $outputPanel.AddChild($outputLabel)
    $outputPanel.AddChild($outputTextBox)
    $outputPanel.AddChild($outputBrowse)
    $isoStack.AddChild($outputPanel)

    $isoGroup.Content = $isoStack
    $mainStack.AddChild($isoGroup)
    
    # === 2. Edition Selection ===
    $editionGroup = New-StyledGroupBox -Header '2. Edition Selection'
    $editionStack = New-Object System.Windows.Controls.StackPanel

    $editionInfoLabel = New-StyledLabel -Content 'Mount the ISO to detect available editions'
    $editionInfoLabel.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.TextSecondary)
    $editionInfoLabel.FontSize = 12
    $editionStack.AddChild($editionInfoLabel)

    $mountPanel = New-Object System.Windows.Controls.StackPanel
    $mountPanel.Orientation = 'Horizontal'
    $mountButton = New-StyledButton -Content 'Mount ISO & Detect Editions' -Width 200
    $mountButton.IsEnabled = $false
    $mountStatusLabel = New-StyledLabel -Content ''
    $mountStatusLabel.FontSize = 12
    $mountPanel.AddChild($mountButton)
    $mountPanel.AddChild($mountStatusLabel)
    $editionStack.AddChild($mountPanel)

    $editionPanel = New-Object System.Windows.Controls.StackPanel
    $editionPanel.Orientation = 'Horizontal'
    $editionPanel.Margin = '0,10,0,0'
    $editionLabel = New-StyledLabel -Content 'Select Edition:'
    $editionCombo = New-StyledComboBox -Width 300
    $editionCombo.IsEnabled = $false
    $editionPanel.AddChild($editionLabel)
    $editionPanel.AddChild($editionCombo)
    $editionStack.AddChild($editionPanel)

    $isoFileTextBox.Add_TextChanged({
            if ($isoFileTextBox.Text -ne '' -and (Test-Path $isoFileTextBox.Text)) {
                $mountButton.IsEnabled = $true
                $mountStatusLabel.Content = ''
                $editionCombo.Items.Clear()
                $editionCombo.IsEnabled = $false
            }
            else {
                $mountButton.IsEnabled = $false
            }
        })

    $mountButton.Add_Click({
            $isoPath = $isoFileTextBox.Text
            $workingDir = $outputTextBox.Text
    
            if ([string]::IsNullOrWhiteSpace($isoPath) -or -not (Test-Path $isoPath -PathType Leaf)) {
                [System.Windows.MessageBox]::Show('Please select a valid ISO file first.', 'Error', 'OK', 'Error')
                return
            }

            if ([string]::IsNullOrWhiteSpace($workingDir) -or -not (Test-Path $workingDir -PathType Container)) {
                [System.Windows.MessageBox]::Show('Please select a valid Output Directory first.', 'Error', 'OK', 'Error')
                return
            }

            #check output dir drive will have enough space
            $isoSize = (Get-Item -Path "$isoPath").Length
            $driveLetter = (Split-Path $workingDir -Qualifier) -replace ':', ''
            $spaceRemaining = (Get-Volume $driveLetter).SizeRemaining
            if ($spaceRemaining -lt ($isoSize * 2)) {
                Write-Status -Message "Not Much Storage Space Left on Drive: $($driveLetter):\, This May Cause Issues..." -Type Warning
            }
            elseif ($spaceRemaining -lt $isoSize) {
                $msg = "You don't have enough space for this operation. You need at least $([Math]::Round(($isoSize / ([Math]::Pow(1024, 2))) * 2, 2)) MB of free space."
                [System.Windows.MessageBox]::Show($msg, 'Error', 'OK', 'Error')
                return
            }
            
            #show loading state
            $mountButton.IsEnabled = $false
            $mountButton.Content = 'Mounting...'
            $mountStatusLabel.Content = 'Mounting ISO and detecting editions...'
            $mountStatusLabel.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#FFe8c743')
    
            # Force to UI update
            $window.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, [action] {})
    
            try {
                #first check for adk needed to create final iso
                install-adk

                [Void](Clear-WindowsCorruptMountPoint)
                $mountResult = (Mount-DiskImage -ImagePath $isoPath -StorageType ISO -PassThru -ErrorAction Stop | Get-Volume).DriveLetter + ':\'

                # Create a temporary directory to copy the ISO contents
                $Global:tempDir = "$workingDir\TEMP"
                try {
                    Remove-Item $Global:tempDir -Recurse -Force -ErrorAction SilentlyContinue
                }
                catch {}
                try {
                    Remove-Item "$workingDir\RemoveDir" -Recurse -Force -ErrorAction SilentlyContinue
                }
                catch {}
            
                New-Item -ItemType Directory -Force -Path $tempDir
                New-Item -Path $workingDir -Name 'RemoveDir' -ItemType Directory -Force

                Copy-Item -Path "$mountResult*" -Destination $tempDir -Recurse -Force

                Dismount-DiskImage -ImagePath $isoPath

                #remove read only from all the files
                $files = Get-ChildItem -Path $tempDir -Recurse -File -Force
                foreach ($file in $files) {
                    $file.Attributes = 'Normal'
                }
                $directories = Get-ChildItem -Path $tempDir -Recurse -Directory -Force
                foreach ($directory in $directories) {
                    $directory.Attributes = 'Directory'
                }
    
                #get editions
                $editions = Get-WindowsImage -ImagePath "$tempDir\sources\install.wim"

                $editionTable = @{}
                foreach ($edition in $editions) {
                    $editionTable.Add($edition.ImageName, $edition.ImageIndex)
                } 
                $editionCombo.Tag = $editionTable
                
                #add edition names to combo box
                $editionCombo.Items.Clear()
                foreach ($edition in $editionTable.GetEnumerator()) {
                    $editionCombo.Items.Add($edition.Key) | Out-Null
                }
        
                if ($editionCombo.Items.Count -gt 0) {
                    $editionCombo.SelectedIndex = 0
                    $editionCombo.IsEnabled = $true
                    $mountStatusLabel.Content = "Found $($editions.Count) edition(s)"
                    $mountStatusLabel.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#FF10B981')
                    $mountButton.Content = 'Remount ISO'
                    $mountButton.IsEnabled = $true
                    $editionInfoLabel.Content = 'ISO mounted successfully - select an edition below'
                }
                else {
                    throw 'No editions found in ISO'
                }
        
            }
            catch {
                [System.Windows.MessageBox]::Show("Failed to mount ISO or detect editions:`n$($_.Exception.Message)", 'Error', 'OK', 'Error')
                $mountStatusLabel.Content = 'Failed to detect editions'
                $mountStatusLabel.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString('#FFEF4444')
                $mountButton.Content = 'Mount ISO & Detect Editions'
                $mountButton.IsEnabled = $true
                $editionCombo.IsEnabled = $false
            }
        })

    $editionGroup.Content = $editionStack
    $mainStack.AddChild($editionGroup)
    
    # === 3. Account & OOBE Setup ===
    $accountGroup = New-StyledGroupBox -Header '3. Account & OOBE Setup'
    $accountStack = New-Object System.Windows.Controls.StackPanel
    
    $usernamePanel = New-Object System.Windows.Controls.StackPanel
    $usernamePanel.Orientation = 'Horizontal'
    $usernameLabel = New-StyledLabel -Content 'Username:'
    $usernameTextBox = New-StyledTextBox -Width 200
    $usernamePanel.AddChild($usernameLabel)
    $usernamePanel.AddChild($usernameTextBox)
    $accountStack.AddChild($usernamePanel)
    
    $passwordPanel = New-Object System.Windows.Controls.StackPanel
    $passwordPanel.Orientation = 'Horizontal'
    $passwordLabel = New-StyledLabel -Content 'Password:'

    $passwordContainer = New-Object System.Windows.Controls.Grid
    $passwordContainer.Width = 200
    $passwordContainer.Height = 32
    $passwordContainer.Margin = '5'
    
    $passwordBox = New-Object System.Windows.Controls.PasswordBox
    $passwordBox.Width = 200
    $passwordBox.Height = 32
    $passwordBox.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Surface)
    $passwordBox.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Text)
    $passwordBox.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Border)
    $passwordBox.FontSize = 13
    $passwordBox.Template = $passwordBoxControlTemplate
    $passwordBox.HorizontalAlignment = 'Left'
    $passwordBox.Visibility = 'Visible'
 
    $passwordTextBox = New-Object System.Windows.Controls.TextBox
    $passwordTextBox.Width = 200
    $passwordTextBox.Height = 32
    $passwordTextBox.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Surface)
    $passwordTextBox.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Text)
    $passwordTextBox.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Border)
    $passwordTextBox.FontSize = 13
    $passwordTextBox.Template = $textBoxControlTemplate
    $passwordTextBox.HorizontalAlignment = 'Left'
    $passwordTextBox.Visibility = 'Collapsed'
    
    $passwordContainer.Children.Add($passwordBox)
    $passwordContainer.Children.Add($passwordTextBox)
    
    $togglePasswordButton = New-Object System.Windows.Controls.Button
    $togglePasswordButton.Content = 'Show'
    $togglePasswordButton.Width = 50
    $togglePasswordButton.Height = 32
    $togglePasswordButton.FontSize = 11
    $togglePasswordButton.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Surface)
    $togglePasswordButton.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Text)
    $togglePasswordButton.BorderThickness = 1
    $togglePasswordButton.BorderBrush = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Border)
    $togglePasswordButton.Margin = '0,5,5,5'
    $togglePasswordButton.Cursor = [System.Windows.Input.Cursors]::Hand
    $togglePasswordButton.Template = $buttonControlTemplate
    $togglePasswordButton.ToolTip = 'Show/Hide Password'

    $togglePasswordButton.Add_Click({
            if ($passwordBox.Visibility -eq 'Visible') {
                #show
                $passwordTextBox.Text = $passwordBox.Password
                $passwordBox.Visibility = 'Collapsed'
                $passwordTextBox.Visibility = 'Visible'
                $togglePasswordButton.Content = 'Hide'
            }
            else {
                #hide
                $passwordBox.Password = $passwordTextBox.Text
                $passwordTextBox.Visibility = 'Collapsed'
                $passwordBox.Visibility = 'Visible'
                $togglePasswordButton.Content = 'Show'
            }
        })

    # Sync password changes
    $passwordBox.Add_PasswordChanged({
            if ($passwordBox.Visibility -eq 'Visible') {
                $passwordTextBox.Text = $passwordBox.Password
            }
        })

    $passwordTextBox.Add_TextChanged({
            if ($passwordTextBox.Visibility -eq 'Visible') {
                $passwordBox.Password = $passwordTextBox.Text
            }
        })

    $passwordPanel.AddChild($passwordLabel)
    $passwordPanel.AddChild($passwordContainer)
    $passwordPanel.AddChild($togglePasswordButton)
    $accountStack.AddChild($passwordPanel)
    
    $skipOOBE = New-StyledCheckBox -Content 'Skip OOBE (Out-of-Box Experience)'
    $skipOOBE.IsChecked = $true
    $accountStack.AddChild($skipOOBE)
    
    $accountGroup.Content = $accountStack
    $mainStack.AddChild($accountGroup)
    
    # === 4. Windows Update Options ===
    $updateGroup = New-StyledGroupBox -Header '4. Windows Update Options'
    $updateStack = New-Object System.Windows.Controls.StackPanel

    $disableUpdates = New-StyledCheckBox -Content 'Disable all Windows updates'
    $securityOnly = New-StyledCheckBox -Content 'Security updates only'
    $disableVersionUpgrade = New-StyledCheckBox -Content 'Disable version upgrades'
    # prevent other update options from being checked when disable all updates is checked for some reason this breaks the script 
    $disableUpdates.Add_Checked({
            $securityOnly.IsChecked = $false
            $securityOnly.IsEnabled = $false
            $disableVersionUpgrade.IsChecked = $false
            $disableVersionUpgrade.IsEnabled = $false
        })

    $disableUpdates.Add_Unchecked({
            $securityOnly.IsEnabled = $true
            $disableVersionUpgrade.IsEnabled = $true
        })

    $securityOnly.Add_Checked({
            if ($disableUpdates.IsChecked) {
                $disableUpdates.IsChecked = $false
            }
        })

    $updateStack.AddChild($disableUpdates)
    $updateStack.AddChild($securityOnly)
    $updateStack.AddChild($disableVersionUpgrade)

    $updateGroup.Content = $updateStack
    $mainStack.AddChild($updateGroup)
    
    # === 5. Windows Defender Options ===
    $defenderGroup = New-StyledGroupBox -Header '5. Security & Privacy'
    $defenderStack = New-Object System.Windows.Controls.StackPanel
    
    $removeDefender = New-StyledCheckBox -Content 'Remove Windows Defender'
    $removeBitlocker = New-StyledCheckBox -Content 'Remove Bitlocker'
    $disableMitigations = New-StyledCheckBox -Content 'Disable Security Mitigations'
    $disableTelemetry = New-StyledCheckBox -Content 'Disable Telemetry'
    $defenderStack.AddChild($removeDefender)
    $defenderStack.AddChild($removeBitlocker)
    $defenderStack.AddChild($disableMitigations)
    $defenderStack.AddChild($disableTelemetry)
    
    $defenderGroup.Content = $defenderStack
    $mainStack.AddChild($defenderGroup)
    
    # === 6. Default Apps & Debloat ===
    $appsGroup = New-StyledGroupBox -Header '6. Default Apps & Debloat'
    $appsStack = New-Object System.Windows.Controls.StackPanel

    $removeEdge = New-StyledCheckBox -Content 'Remove Microsoft Edge'
    $removeOneDrive = New-StyledCheckBox -Content 'Remove OneDrive'
    $removeWinAI = New-StyledCheckBox -Content 'Remove Windows AI'
    $appsStack.AddChild($removeEdge)
    $appsStack.AddChild($removeOneDrive)
    $appsStack.AddChild($removeWinAI)

    $separator2 = New-Object System.Windows.Controls.Separator
    $separator2.Margin = '0,10,0,10'
    $separator2.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Border)
    $appsStack.AddChild($separator2)

    $advancedLabel = New-StyledLabel -Content 'Advanced Package Selection:'
    $advancedLabel.FontWeight = 'SemiBold'
    $appsStack.AddChild($advancedLabel)

    $appxPanel = New-Object System.Windows.Controls.StackPanel
    $appxPanel.Orientation = 'Horizontal'

    $selectAppxButton = New-StyledButton -Content 'Select AppX Packages to Remove' -Width 250
    $appxCountLabel = New-StyledLabel -Content '(0 selected)'
    $appxCountLabel.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.TextSecondary)
    $appxCountLabel.FontSize = 11

    $Global:selectedAppxPackages = @()

    $selectAppxButton.Add_Click({
            # Check if ISO is mounted
            if ([string]::IsNullOrWhiteSpace($isoFileTextBox.Text) -or $editionCombo.SelectedItem -eq $null) {
                [System.Windows.MessageBox]::Show('Please mount the ISO and select an edition first.', 'Error', 'OK', 'Warning')
                return
            }
    
            $selectAppxButton.IsEnabled = $false
            $selectAppxButton.Content = 'Loading packages...'
    
            try {
                if (!(Get-WindowsImage -Mounted)) {
                    #need to mount the edition first to display the packages on the iso
                    Mount-Edition -ImagePath "$tempDir\sources\install.wim" -workingDir "$($outputTextBox.Text)\RemoveDir" -index ($editionCombo.Tag)[$editionCombo.SelectedItem] -edition $editionCombo.SelectedItem
                }

                Write-Status 'Getting Appx Packages from ISO...' Output
                $packages = Get-AppxProvisionedPackage -Path "$($outputTextBox.Text)\RemoveDir" | Select-Object DisplayName, PackageName | Where-Object { 
                    $_.DisplayName -notlike '*DesktopAppInstaller*' -and 
                    $_.DisplayName -notlike '*AppRuntime*' -and 
                    $_.DisplayName -notlike '*VCLibs*' -and 
                    $_.DisplayName -notlike '*UI.Xaml*' -and 
                    $_.DisplayName -notlike '*NET.Native*' 
                }
                
        
                $packageWindow = New-Object System.Windows.Window
                $packageWindow.Title = 'Select AppX Packages to Remove'
                $packageWindow.Width = 700
                $packageWindow.Height = 670
                $packageWindow.WindowStartupLocation = 'CenterScreen'
                $packageWindow.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Background)
        
                $packageMainStack = New-Object System.Windows.Controls.StackPanel
                $packageMainStack.Margin = '15'
        
                $headerStack = New-Object System.Windows.Controls.StackPanel
        
                $headerLabel = New-StyledLabel -Content 'Select packages to remove from the ISO:' -FontSize 14 -IsBold $true
                $headerStack.AddChild($headerLabel)
        
                $searchPanel = New-Object System.Windows.Controls.StackPanel
                $searchPanel.Orientation = 'Horizontal'
                $searchPanel.Margin = '0,10,0,10'
                $searchLabel = New-StyledLabel -Content 'Search:'
                $searchBox = New-StyledTextBox -Width 400
                $searchPanel.AddChild($searchLabel)
                $searchPanel.AddChild($searchBox)
                $headerStack.AddChild($searchPanel)
        
                $bulkButtonPanel = New-Object System.Windows.Controls.StackPanel
                $bulkButtonPanel.Orientation = 'Horizontal'
                $bulkButtonPanel.Margin = '0,0,0,10'
                $selectAllButton = New-StyledButton -Content 'Select All' -Width 100
                $deselectAllButton = New-StyledButton -Content 'Deselect All' -Width 100
                $bulkButtonPanel.AddChild($selectAllButton)
                $bulkButtonPanel.AddChild($deselectAllButton)
                $headerStack.AddChild($bulkButtonPanel)
        
                $packageMainStack.AddChild($headerStack)
    
                $packageScrollViewer = New-Object System.Windows.Controls.ScrollViewer
                $packageScrollViewer.Height = 370
                $packageScrollViewer.VerticalScrollBarVisibility = 'Auto'
        
                $packageListStack = New-Object System.Windows.Controls.StackPanel
        
          
                $checkboxList = @()
                foreach ($pkg in $packages) {
                    $cb = New-StyledCheckBox -Content $pkg.DisplayName
                    $cb.Tag = $pkg.PackageName
                    $cb.ToolTip = $pkg.PackageName
            
                    # Check if already selected
                    if ($Global:selectedAppxPackages -contains $pkg.PackageName) {
                        $cb.IsChecked = $true
                    }
            
                    $packageListStack.AddChild($cb)
                    $checkboxList += $cb
                }
        
                $packageScrollViewer.Content = $packageListStack
                $packageMainStack.AddChild($packageScrollViewer)
        
                $searchBox.Add_TextChanged({
                        $searchText = $searchBox.Text.ToLower()
                        foreach ($cb in $checkboxList) {
                            if ([string]::IsNullOrWhiteSpace($searchText) -or $cb.Content.ToLower().Contains($searchText) -or $cb.Tag.ToLower().Contains($searchText)) {
                                $cb.Visibility = 'Visible'
                            }
                            else {
                                $cb.Visibility = 'Collapsed'
                            }
                        }
                    })
        

                $selectAllButton.Add_Click({
                        foreach ($cb in $checkboxList) {
                            if ($cb.Visibility -eq 'Visible') {
                                $cb.IsChecked = $true
                            }
                        }
                    })
        
        
                $deselectAllButton.Add_Click({
                        foreach ($cb in $checkboxList) {
                            if ($cb.Visibility -eq 'Visible') {
                                $cb.IsChecked = $false
                            }
                        }
                    })
    
                $actionPanel = New-Object System.Windows.Controls.StackPanel
                $actionPanel.Orientation = 'Horizontal'
                $actionPanel.HorizontalAlignment = 'Center'
                $actionPanel.Margin = '0,15,0,0'
        
                $confirmButton = New-StyledButton -Content 'Confirm Selection' -Width 150
                $confirmButton.Add_Click({
                        $Global:selectedAppxPackages = @()
                        foreach ($cb in $checkboxList) {
                            if ($cb.IsChecked) {
                                $Global:selectedAppxPackages += $cb.Tag
                            }
                        }
                        $appxCountLabel.Content = "($($Global:selectedAppxPackages.Count) selected)"
                        $packageWindow.Close()
                    })
        
                $cancelPackageButton = New-StyledButton -Content 'Cancel' -Width 100
                $cancelPackageButton.Add_Click({
                        $packageWindow.Close()
                    })
        
                $actionPanel.AddChild($confirmButton)
                $actionPanel.AddChild($cancelPackageButton)
                $packageMainStack.AddChild($actionPanel)
        
                $packageWindow.Content = $packageMainStack
                $packageWindow.ShowDialog() | Out-Null
        
            }
            catch {
                [System.Windows.MessageBox]::Show("Failed to load packages: $($_.Exception.Message)", 'Error', 'OK', 'Error')
            }
            finally {
                $selectAppxButton.IsEnabled = $true
                $selectAppxButton.Content = 'Select AppX Packages to Remove'
            }
        })

    $appxPanel.AddChild($selectAppxButton)
    $appxPanel.AddChild($appxCountLabel)
    $appsStack.AddChild($appxPanel)

    $osPackagesPanel = New-Object System.Windows.Controls.StackPanel
    $osPackagesPanel.Orientation = 'Horizontal'
    $osPackagesPanel.Margin = '0,5,0,0'

    $selectOSPackagesButton = New-StyledButton -Content 'Select OS Packages to Remove' -Width 250
    $osPackagesCountLabel = New-StyledLabel -Content '(0 selected)'
    $osPackagesCountLabel.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.TextSecondary)
    $osPackagesCountLabel.FontSize = 11

    $Global:selectedOSPackages = @()

    $selectOSPackagesButton.Add_Click({
            # Check if ISO is mounted
            if ([string]::IsNullOrWhiteSpace($isoFileTextBox.Text) -or $editionCombo.SelectedItem -eq $null) {
                [System.Windows.MessageBox]::Show('Please mount the ISO and select an edition first.', 'Error', 'OK', 'Warning')
                return
            }
    
            $selectOSPackagesButton.IsEnabled = $false
            $selectOSPackagesButton.Content = 'Loading OS packages...'
    
            try {
                if (!(Get-WindowsImage -Mounted)) {
                    #need to mount the edition first to display the packages on the iso
                    Mount-Edition -ImagePath "$tempDir\sources\install.wim" -workingDir "$($outputTextBox.Text)\RemoveDir" -index ($editionCombo.Tag)[$editionCombo.SelectedItem] -edition $editionCombo.SelectedItem
                }

                Write-Status 'Getting OS Packages from ISO...' Output
                $osPackages = Get-WindowsPackage -Path "$($outputTextBox.Text)\RemoveDir" | Select-Object PackageName, PackageState | Where-Object {
                    $_.PackageName -notlike '*ApplicationModel*' -and
                    $_.PackageName -notlike '*LanguagePack*' -and
                    $_.PackageName -notlike '*LanguageFeatures*' -and
                    $_.PackageName -notlike '*ServicingStack*' -and
                    $_.PackageName -notlike '*DotNet*' -and
                    $_.PackageName -notlike '*Notepad*' -and 
                    $_.PackageName -notlike '*WMIC*' -and
                    $_.PackageName -notlike '*Ethernet*' -and
                    $_.PackageName -notlike '*Wifi*' -and
                    $_.PackageName -notlike '*FodMetadata*' -and
                    $_.PackageName -notlike '*Foundation*' -and
                    $_.PackageName -notlike '*VBSCRIPT*' -and
                    $_.PackageName -notlike '*License*' -and
                    $_.PackageName -notlike '*ISE*' -and
                    $_.PackageName -notlike '*OpenSSH*' -and
                    $_.PackageName -notlike '*MediaPlayer*' -and
                    $_.PackageName -notlike '*NetFx*' -and
                    $_.PackageName -notlike '*KB*' -and
                    $_.PackageName -notlike '*RollupFix*' -and 
                    $_.PackageState -eq 'Installed'
                }
        
                $osPackageWindow = New-Object System.Windows.Window
                $osPackageWindow.Title = 'Select OS Packages to Remove'
                $osPackageWindow.Width = 750
                $osPackageWindow.Height = 670
                $osPackageWindow.WindowStartupLocation = 'CenterScreen'
                $osPackageWindow.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Background)
        
                $osPackageMainStack = New-Object System.Windows.Controls.StackPanel
                $osPackageMainStack.Margin = '15'
        
                $headerStack = New-Object System.Windows.Controls.StackPanel
        
                $headerLabel = New-StyledLabel -Content 'Select OS packages to remove from the ISO:' -FontSize 14 -IsBold $true
                $headerStack.AddChild($headerLabel)
        
                $searchPanel = New-Object System.Windows.Controls.StackPanel
                $searchPanel.Orientation = 'Horizontal'
                $searchPanel.Margin = '0,10,0,10'
                $searchLabel = New-StyledLabel -Content 'Search:'
                $searchBox = New-StyledTextBox -Width 400
                $searchPanel.AddChild($searchLabel)
                $searchPanel.AddChild($searchBox)
                $headerStack.AddChild($searchPanel)
        
                $bulkButtonPanel = New-Object System.Windows.Controls.StackPanel
                $bulkButtonPanel.Orientation = 'Horizontal'
                $bulkButtonPanel.Margin = '0,0,0,10'
                $selectAllButton = New-StyledButton -Content 'Select All' -Width 100
                $deselectAllButton = New-StyledButton -Content 'Deselect All' -Width 100
                $bulkButtonPanel.AddChild($selectAllButton)
                $bulkButtonPanel.AddChild($deselectAllButton)
                $headerStack.AddChild($bulkButtonPanel)
        
                $osPackageMainStack.AddChild($headerStack)
        
                $osPackageScrollViewer = New-Object System.Windows.Controls.ScrollViewer
                $osPackageScrollViewer.Height = 370
                $osPackageScrollViewer.VerticalScrollBarVisibility = 'Auto'
        
                $osPackageListStack = New-Object System.Windows.Controls.StackPanel
        
                $checkboxList = @()
                foreach ($pkg in $osPackages) {
                    $displayText = "$($pkg.PackageName) - ($($pkg.PackageState))"
                    $cb = New-StyledCheckBox -Content $displayText
                    $cb.Tag = $pkg.PackageName
                    $cb.ToolTip = $pkg.PackageName
            
                    # Check if already selected
                    if ($Global:selectedOSPackages -contains $pkg.PackageName) {
                        $cb.IsChecked = $true
                    }
            
                    $osPackageListStack.AddChild($cb)
                    $checkboxList += $cb
                }
        
                $osPackageScrollViewer.Content = $osPackageListStack
                $osPackageMainStack.AddChild($osPackageScrollViewer)
        
                $searchBox.Add_TextChanged({
                        $searchText = $searchBox.Text.ToLower()
                        foreach ($cb in $checkboxList) {
                            if ([string]::IsNullOrWhiteSpace($searchText) -or $cb.Content.ToLower().Contains($searchText) -or $cb.Tag.ToLower().Contains($searchText)) {
                                $cb.Visibility = 'Visible'
                            }
                            else {
                                $cb.Visibility = 'Collapsed'
                            }
                        }
                    })
        

                $selectAllButton.Add_Click({
                        foreach ($cb in $checkboxList) {
                            if ($cb.Visibility -eq 'Visible') {
                                $cb.IsChecked = $true
                            }
                        }
                    })
        
    
                $deselectAllButton.Add_Click({
                        foreach ($cb in $checkboxList) {
                            if ($cb.Visibility -eq 'Visible') {
                                $cb.IsChecked = $false
                            }
                        }
                    })
     
                $actionPanel = New-Object System.Windows.Controls.StackPanel
                $actionPanel.Orientation = 'Horizontal'
                $actionPanel.HorizontalAlignment = 'Center'
                $actionPanel.Margin = '0,15,0,0'
        
                $confirmButton = New-StyledButton -Content 'Confirm Selection' -Width 150
                $confirmButton.Add_Click({
                        $Global:selectedOSPackages = @()
                        foreach ($cb in $checkboxList) {
                            if ($cb.IsChecked) {
                                $Global:selectedOSPackages += $cb.Tag
                            }
                        }
                        $osPackagesCountLabel.Content = "($($Global:selectedOSPackages.Count) selected)"
                        $osPackageWindow.Close()
                    })
        
                $cancelOSPackageButton = New-StyledButton -Content 'Cancel' -Width 100
                $cancelOSPackageButton.Add_Click({
                        $osPackageWindow.Close()
                    })
        
                $actionPanel.AddChild($confirmButton)
                $actionPanel.AddChild($cancelOSPackageButton)
                $osPackageMainStack.AddChild($actionPanel)
        
                $osPackageWindow.Content = $osPackageMainStack
                $osPackageWindow.ShowDialog() | Out-Null
        
            }
            catch {
                [System.Windows.MessageBox]::Show("Failed to load OS packages: $($_.Exception.Message)", 'Error', 'OK', 'Error')
            }
            finally {
                $selectOSPackagesButton.IsEnabled = $true
                $selectOSPackagesButton.Content = 'Select OS Packages to Remove'
            }
        })

    $osPackagesPanel.AddChild($selectOSPackagesButton)
    $osPackagesPanel.AddChild($osPackagesCountLabel)
    $appsStack.AddChild($osPackagesPanel)

    $capabilitiesPanel = New-Object System.Windows.Controls.StackPanel
    $capabilitiesPanel.Orientation = 'Horizontal'
    $capabilitiesPanel.Margin = '0,5,0,0'

    $selectCapabilitiesButton = New-StyledButton -Content 'Select Windows Capabilities to Remove' -Width 250
    $capabilitiesCountLabel = New-StyledLabel -Content '(0 selected)'
    $capabilitiesCountLabel.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.TextSecondary)
    $capabilitiesCountLabel.FontSize = 11

    $Global:selectedCapabilities = @()

    $selectCapabilitiesButton.Add_Click({
            # Check if ISO is mounted
            if ([string]::IsNullOrWhiteSpace($isoFileTextBox.Text) -or $editionCombo.SelectedItem -eq $null) {
                [System.Windows.MessageBox]::Show('Please mount the ISO and select an edition first.', 'Error', 'OK', 'Warning')
                return
            }
    
            $selectCapabilitiesButton.IsEnabled = $false
            $selectCapabilitiesButton.Content = 'Loading capabilities...'
    
            try {
                if (!(Get-WindowsImage -Mounted)) {
                    #need to mount the edition first to display the packages on the iso
                    Mount-Edition -ImagePath "$tempDir\sources\install.wim" -workingDir "$($outputTextBox.Text)\RemoveDir" -index ($editionCombo.Tag)[$editionCombo.SelectedItem] -edition $editionCombo.SelectedItem
                }

                Write-Status 'Getting Windows Capabilities from ISO...' Output
                $capabilities = Get-WindowsCapability -Path "$($outputTextBox.Text)\RemoveDir" | Select-Object Name, State | Where-Object {
                    $_.Name -notlike '*DirectX*' -and
                    $_.Name -notlike '*Language*' -and
                    $_.Name -notlike '*MediaPlayer*' -and
                    $_.Name -notlike '*Ethernet*' -and
                    $_.Name -notlike '*Notepad*' -and
                    $_.Name -notlike '*PowerShell*' -and
                    $_.Name -notlike '*Wifi*' -and
                    $_.Name -notlike '*NetFx*' -and
                    $_.Name -notlike '*OpenSSH*' -and
                    $_.Name -notlike '*VBScript*' -and
                    $_.Name -notlike '*WMIC*' -and 
                    $_.State -eq 'Installed'
                }
        
                $capabilityWindow = New-Object System.Windows.Window
                $capabilityWindow.Title = 'Select Windows Capabilities to Remove'
                $capabilityWindow.Width = 700
                $capabilityWindow.Height = 670
                $capabilityWindow.WindowStartupLocation = 'CenterScreen'
                $capabilityWindow.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Background)
        
                $capabilityMainStack = New-Object System.Windows.Controls.StackPanel
                $capabilityMainStack.Margin = '15'
        
                $headerStack = New-Object System.Windows.Controls.StackPanel
        
                $headerLabel = New-StyledLabel -Content 'Select Windows capabilities to remove from the ISO:' -FontSize 14 -IsBold $true
                $headerStack.AddChild($headerLabel)
        
                $searchPanel = New-Object System.Windows.Controls.StackPanel
                $searchPanel.Orientation = 'Horizontal'
                $searchPanel.Margin = '0,10,0,10'
                $searchLabel = New-StyledLabel -Content 'Search:'
                $searchBox = New-StyledTextBox -Width 400
                $searchPanel.AddChild($searchLabel)
                $searchPanel.AddChild($searchBox)
                $headerStack.AddChild($searchPanel)
        
                $bulkButtonPanel = New-Object System.Windows.Controls.StackPanel
                $bulkButtonPanel.Orientation = 'Horizontal'
                $bulkButtonPanel.Margin = '0,0,0,10'
                $selectAllButton = New-StyledButton -Content 'Select All' -Width 100
                $deselectAllButton = New-StyledButton -Content 'Deselect All' -Width 100
                $bulkButtonPanel.AddChild($selectAllButton)
                $bulkButtonPanel.AddChild($deselectAllButton)
                $headerStack.AddChild($bulkButtonPanel)
        
                $capabilityMainStack.AddChild($headerStack)
        
                $capabilityScrollViewer = New-Object System.Windows.Controls.ScrollViewer
                $capabilityScrollViewer.Height = 370
                $capabilityScrollViewer.VerticalScrollBarVisibility = 'Auto'
        
                $capabilityListStack = New-Object System.Windows.Controls.StackPanel
        
                $checkboxList = @()
                foreach ($cap in $capabilities) {
                    $displayText = "$($cap.Name) - ($($cap.State))"
                    $cb = New-StyledCheckBox -Content $displayText
                    $cb.Tag = $cap.Name
                    $cb.ToolTip = $cap.Name
            
                    # Check if already selected
                    if ($Global:selectedCapabilities -contains $cap.Name) {
                        $cb.IsChecked = $true
                    }
            
                    $capabilityListStack.AddChild($cb)
                    $checkboxList += $cb
                }
        
                $capabilityScrollViewer.Content = $capabilityListStack
                $capabilityMainStack.AddChild($capabilityScrollViewer)
        
                $searchBox.Add_TextChanged({
                        $searchText = $searchBox.Text.ToLower()
                        foreach ($cb in $checkboxList) {
                            if ([string]::IsNullOrWhiteSpace($searchText) -or $cb.Content.ToLower().Contains($searchText) -or $cb.Tag.ToLower().Contains($searchText)) {
                                $cb.Visibility = 'Visible'
                            }
                            else {
                                $cb.Visibility = 'Collapsed'
                            }
                        }
                    })
        
                $selectAllButton.Add_Click({
                        foreach ($cb in $checkboxList) {
                            if ($cb.Visibility -eq 'Visible') {
                                $cb.IsChecked = $true
                            }
                        }
                    })
        
                $deselectAllButton.Add_Click({
                        foreach ($cb in $checkboxList) {
                            if ($cb.Visibility -eq 'Visible') {
                                $cb.IsChecked = $false
                            }
                        }
                    })
        
                $actionPanel = New-Object System.Windows.Controls.StackPanel
                $actionPanel.Orientation = 'Horizontal'
                $actionPanel.HorizontalAlignment = 'Center'
                $actionPanel.Margin = '0,15,0,0'
        
                $confirmButton = New-StyledButton -Content 'Confirm Selection' -Width 150
                $confirmButton.Add_Click({
                        $Global:selectedCapabilities = @()
                        foreach ($cb in $checkboxList) {
                            if ($cb.IsChecked) {
                                $Global:selectedCapabilities += $cb.Tag
                            }
                        }
                        $capabilitiesCountLabel.Content = "($($Global:selectedCapabilities.Count) selected)"
                        $capabilityWindow.Close()
                    })
        
                $cancelCapabilityButton = New-StyledButton -Content 'Cancel' -Width 100
                $cancelCapabilityButton.Add_Click({
                        $capabilityWindow.Close()
                    })
        
                $actionPanel.AddChild($confirmButton)
                $actionPanel.AddChild($cancelCapabilityButton)
                $capabilityMainStack.AddChild($actionPanel)
        
                $capabilityWindow.Content = $capabilityMainStack
                $capabilityWindow.ShowDialog() | Out-Null
        
            }
            catch {
                [System.Windows.MessageBox]::Show("Failed to load Windows capabilities: $($_.Exception.Message)", 'Error', 'OK', 'Error')
            }
            finally {
                $selectCapabilitiesButton.IsEnabled = $true
                $selectCapabilitiesButton.Content = 'Select Windows Capabilities to Remove'
            }
        })

    $capabilitiesPanel.AddChild($selectCapabilitiesButton)
    $capabilitiesPanel.AddChild($capabilitiesCountLabel)
    $appsStack.AddChild($capabilitiesPanel)

    $featuresPanel = New-Object System.Windows.Controls.StackPanel
    $featuresPanel.Orientation = 'Horizontal'
    $featuresPanel.Margin = '0,5,0,0'

    $selectFeaturesButton = New-StyledButton -Content 'Select Windows Features to Remove' -Width 250
    $featuresCountLabel = New-StyledLabel -Content '(0 selected)'
    $featuresCountLabel.Foreground = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.TextSecondary)
    $featuresCountLabel.FontSize = 11

    $Global:selectedFeatures = @()

    $selectFeaturesButton.Add_Click({
            # Check if ISO is mounted
            if ([string]::IsNullOrWhiteSpace($isoFileTextBox.Text) -or $editionCombo.SelectedItem -eq $null) {
                [System.Windows.MessageBox]::Show('Please mount the ISO and select an edition first.', 'Error', 'OK', 'Warning')
                return
            }
    
            $selectFeaturesButton.IsEnabled = $false
            $selectFeaturesButton.Content = 'Loading features...'
    
            try {
                if (!(Get-WindowsImage -Mounted)) {
                    #need to mount the edition first to display the packages on the iso
                    Mount-Edition -ImagePath "$tempDir\sources\install.wim" -workingDir "$($outputTextBox.Text)\RemoveDir" -index ($editionCombo.Tag)[$editionCombo.SelectedItem] -edition $editionCombo.SelectedItem
                }

          
                Write-Status 'Getting Features from ISO...' Output
                $features = Get-WindowsOptionalFeature -Path "$($outputTextBox.Text)\RemoveDir" | Select-Object FeatureName, State | Where-Object { 
                    $_.FeatureName -notlike '*TelnetClient*' -and
                    $_.FeatureName -notlike '*PowerShell*' -and
                    $_.FeatureName -notlike '*NetFx*' -and
                    $_.FeatureName -notlike '*Media*' -and
                    $_.FeatureName -notlike '*NFS*' -and
                    $_.FeatureName -notlike '*SearchEngine*'
                }
        

                $featureWindow = New-Object System.Windows.Window
                $featureWindow.Title = 'Select Windows Features to Remove'
                $featureWindow.Width = 700
                $featureWindow.Height = 600
                $featureWindow.WindowStartupLocation = 'CenterScreen'
                $featureWindow.Background = [System.Windows.Media.BrushConverter]::new().ConvertFromString($colors.Background)
        
                $featureMainStack = New-Object System.Windows.Controls.StackPanel
                $featureMainStack.Margin = '15'
        
     
                $headerStack = New-Object System.Windows.Controls.StackPanel
        
                $headerLabel = New-StyledLabel -Content 'Select Windows features to remove from the ISO:' -FontSize 14 -IsBold $true
                $headerStack.AddChild($headerLabel)
  
                $searchPanel = New-Object System.Windows.Controls.StackPanel
                $searchPanel.Orientation = 'Horizontal'
                $searchPanel.Margin = '0,10,0,10'
                $searchLabel = New-StyledLabel -Content 'Search:'
                $searchBox = New-StyledTextBox -Width 400
                $searchPanel.AddChild($searchLabel)
                $searchPanel.AddChild($searchBox)
                $headerStack.AddChild($searchPanel)
        
            
                $bulkButtonPanel = New-Object System.Windows.Controls.StackPanel
                $bulkButtonPanel.Orientation = 'Horizontal'
                $bulkButtonPanel.Margin = '0,0,0,10'
                $selectAllButton = New-StyledButton -Content 'Select All' -Width 100
                $deselectAllButton = New-StyledButton -Content 'Deselect All' -Width 100
                $bulkButtonPanel.AddChild($selectAllButton)
                $bulkButtonPanel.AddChild($deselectAllButton)
                $headerStack.AddChild($bulkButtonPanel)
        
                $featureMainStack.AddChild($headerStack)
        
                $featureScrollViewer = New-Object System.Windows.Controls.ScrollViewer
                $featureScrollViewer.Height = 320
                $featureScrollViewer.VerticalScrollBarVisibility = 'Auto'
        
                $featureListStack = New-Object System.Windows.Controls.StackPanel
        
           
                $checkboxList = @()
                foreach ($feat in $features) {
                    $displayText = "$($feat.FeatureName) - ($($feat.State))"
                    $cb = New-StyledCheckBox -Content $displayText
                    $cb.Tag = $feat.FeatureName
                    $cb.ToolTip = $feat.FeatureName
            
                    # Check if already selected
                    if ($Global:selectedFeatures -contains $feat.FeatureName) {
                        $cb.IsChecked = $true
                    }
            
                    $featureListStack.AddChild($cb)
                    $checkboxList += $cb
                }
        
                $featureScrollViewer.Content = $featureListStack
                $featureMainStack.AddChild($featureScrollViewer)
        
                $searchBox.Add_TextChanged({
                        $searchText = $searchBox.Text.ToLower()
                        foreach ($cb in $checkboxList) {
                            if ([string]::IsNullOrWhiteSpace($searchText) -or $cb.Content.ToLower().Contains($searchText) -or $cb.Tag.ToLower().Contains($searchText)) {
                                $cb.Visibility = 'Visible'
                            }
                            else {
                                $cb.Visibility = 'Collapsed'
                            }
                        }
                    })
        
    
                $selectAllButton.Add_Click({
                        foreach ($cb in $checkboxList) {
                            if ($cb.Visibility -eq 'Visible') {
                                $cb.IsChecked = $true
                            }
                        }
                    })
        
    
                $deselectAllButton.Add_Click({
                        foreach ($cb in $checkboxList) {
                            if ($cb.Visibility -eq 'Visible') {
                                $cb.IsChecked = $false
                            }
                        }
                    })
     
                $actionPanel = New-Object System.Windows.Controls.StackPanel
                $actionPanel.Orientation = 'Horizontal'
                $actionPanel.HorizontalAlignment = 'Center'
                $actionPanel.Margin = '0,10,0,0'
        
                $confirmButton = New-StyledButton -Content 'Confirm Selection' -Width 150
                $confirmButton.Add_Click({
                        $Global:selectedFeatures = @()
                        foreach ($cb in $checkboxList) {
                            if ($cb.IsChecked) {
                                $Global:selectedFeatures += $cb.Tag
                            }
                        }
                        $featuresCountLabel.Content = "($($Global:selectedFeatures.Count) selected)"
                        $featureWindow.Close()
                    })
        
                $cancelFeatureButton = New-StyledButton -Content 'Cancel' -Width 100
                $cancelFeatureButton.Add_Click({
                        $featureWindow.Close()
                    })
        
                $actionPanel.AddChild($confirmButton)
                $actionPanel.AddChild($cancelFeatureButton)
                $featureMainStack.AddChild($actionPanel)
        
                $featureWindow.Content = $featureMainStack
                $featureWindow.ShowDialog() | Out-Null
        
            }
            catch {
                [System.Windows.MessageBox]::Show("Failed to load features: $($_.Exception.Message)", 'Error', 'OK', 'Error')
            }
            finally {
                $selectFeaturesButton.IsEnabled = $true
                $selectFeaturesButton.Content = 'Select Windows Features to Remove'
            }
        })

    $featuresPanel.AddChild($selectFeaturesButton)
    $featuresPanel.AddChild($featuresCountLabel)
    $appsStack.AddChild($featuresPanel)

    $appsGroup.Content = $appsStack
    $mainStack.AddChild($appsGroup)
    
    # === Action Buttons ===
    $buttonPanel = New-Object System.Windows.Controls.StackPanel
    $buttonPanel.Orientation = 'Horizontal'
    $buttonPanel.HorizontalAlignment = 'Center'
    $buttonPanel.Margin = '0,20,0,10'
    
    $startButton = New-StyledButton -Content 'Start Tweaking' -Width 150
    $Global:config = @{}
    $startButton.Add_Click({
            $Global:config = @{
                ISOPath               = $isoFileTextBox.Text
                OutputPath            = $outputTextBox.Text
                TempDir               = "$($outputTextBox.Text)\TEMP"
                RemoveDir             = "$($outputTextBox.Text)\RemoveDir"
                Edition               = $editionCombo.SelectedItem
                EditionIndex          = ($editionCombo.Tag)[$editionCombo.SelectedItem]
                Username              = $usernameTextBox.Text
                Password              = $passwordBox.Password
                SkipOOBE              = $skipOOBE.IsChecked
                DisableUpdates        = $disableUpdates.IsChecked
                SecurityOnly          = $securityOnly.IsChecked
                DisableVersionUpgrade = $disableVersionUpgrade.IsChecked
                RemoveDefender        = $removeDefender.IsChecked
                RemoveBitlocker       = $removeBitlocker.IsChecked
                DisableMitigations    = $disableMitigations.IsChecked
                RemoveAI              = $removeWinAI.IsChecked
                DisableTelemetry      = $disableTelemetry.IsChecked
                RemoveEdge            = $removeEdge.IsChecked
                RemoveOneDrive        = $removeOneDrive.IsChecked
            }

            [System.Windows.MessageBox]::Show('Configuration saved! Ready to process ISO.', 'ISO Tweaker', 'OK', 'Information')
            
            $window.Close()
        }.GetNewClosure())
    
    $cancelButton = New-StyledButton -Content 'Cancel' -Width 100
    $cancelButton.Add_Click({ $window.Close() })
    
    $buttonPanel.AddChild($startButton) 
    $buttonPanel.AddChild($cancelButton) 
    $mainStack.AddChild($buttonPanel) 

    $scrollViewer.Content = $mainStack
    $window.Content = $scrollViewer
    
    $window.ShowDialog() | Out-Null

    # return $Global:config
    

}
Export-ModuleMember -Function Display-UI