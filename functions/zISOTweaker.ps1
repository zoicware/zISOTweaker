if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    Write-Host 'Please Run this Script as Admin...' -f Red
    Write-Host 'Right Click Run-ISOTweaker.cmd > Run as Administrator' -f Red
    Write-Host 'Press Any Key to Exit...'
    $Host.UI.RawUI.ReadKey() *>$null
    Exit	
}


$modulePath = "$PSScriptRoot\ISOTweakerFuncs.psm1"
if (Test-Path $modulePath) {
    Import-Module -Name $modulePath -Force -Global *>$null
}
else {
    Write-Host 'Unable to Find ISOTweakerFuncs.psm1 in Functions Directory!' -ForegroundColor Red
    Write-Host
    Write-Host 'Press Any Key to Exit...'
    $Host.UI.RawUI.ReadKey() *>$null
    Exit
}

#chcp 65001 >$null 
#[Console]::OutputEncoding = [System.Text.Encoding]::UTF8


Write-Host
Write-Host


Display-UI | Out-Null
if ($Global:config.Count -gt 0) {
    #info needed to pass to functions
    $info = [PSCustomObject]@{
        isoPath      = $Global:config['ISOPath']
        outDir       = $Global:config['OutputPath']
        edition      = $Global:config['Edition']
        editionIndex = $Global:config['EditionIndex']
        password     = $Global:config['Password']
        username     = $Global:config['Username']
        tempDir      = $Global:config['TempDir']
        removeDir    = $Global:config['RemoveDir']
        SkipOOBE     = $Global:config['SkipOOBE']
    }

    #setup
    if (!(Get-WindowsImage -Mounted)) {
        Mount-Edition -ImagePath "$($info.tempDir)\sources\install.wim" -workingDir $info.removeDir -index $info.editionIndex -edition $info.edition
    }
    #ensure this is created even tho it should already exist
    Create-UnmountScript -outDir $info.outDir
    Create-Unattend -Username $info.username -Password $info.password -workingDir $info.removeDir -skipOOBE $info.SkipOOBE
    Create-FirstRun -removeDir $info.removeDir
    install-zoicware -removeDir $info.removeDir
    Load-Registry -removeDir $info.removeDir

    #do some tweaks to all installs 
    Disable-W11Req
    Disable-WindowsAnnoyances -removeDir $info.removeDir
    Unload-Registry
    Integrate-Net3 -removeDir $info.removeDir -tempDir $info.tempDir

    
    if ($Global:SelectedAppxPackages.Count -ne 0) {
        #  Unload-Registry
        Remove-Packages -removeDir $info.removeDir -packages $Global:SelectedAppxPackages
    }

    if ($Global:SelectedFeatures.Count -ne 0) {
        #   Unload-Registry
        Remove-Features -removeDir $info.removeDir -featureNames $Global:SelectedFeatures
    }

    if ($Global:selectedOSPackages.Count -ne 0) {
        #  Unload-Registry
        Remove-OSPackages -removeDir $info.removeDir -osPackages $Global:selectedOSPackages
    }

    if ($Global:selectedCapabilities.Count -ne 0) {
        # Unload-Registry
        Remove-Capabilities -removeDir $info.removeDir -caps $Global:selectedCapabilities
    }
    
    #gather selected options 
    $enabledOptions = @()
    foreach ($option in $Global:config.GetEnumerator()) {
        if ($option.Value -eq $true) {
            $enabledOptions += $option.Key
        }
    }

    #loop through options and run function
    foreach ($enabledOption in $enabledOptions) {
   
        switch ($enabledOption) {
             
            'DisableUpdates' {
                Load-Registry -removeDir $info.removeDir
                Disable-Updates
                Unload-Registry
            }      
            'SecurityOnly' {
                Load-Registry -removeDir $info.removeDir
                Sec-UpdatesOnly
                Unload-Registry
            }      
            'DisableVersionUpgrade' {
                Load-Registry -removeDir $info.removeDir
                Disable-VerUpgrade
                Unload-Registry
            }
            'RemoveDefender' {
                Unload-Registry
                remove-Defender -edition $info.edition -removeDir $info.removeDir 
                Load-Registry -removeDir $info.removeDir
                Disable-Defender
                Unload-Registry
            }
            'RemoveBitlocker' {
                Load-Registry -removeDir $info.removeDir
                Remove-BitLocker -removeDir $info.removeDir
                Unload-Registry
            }  
            'DisableMitigations' {
                Load-Registry -removeDir $info.removeDir
                Disable-Mitigations
                Unload-Registry
            }   
            'DisableTelemetry' {
                Load-Registry -removeDir $info.removeDir
                Disable-Telemetry -removeDir $info.removeDir
                Unload-Registry
            } 
            'RemoveAI' {
                Load-Registry -removeDir $info.removeDir
                Strip-WinAI -removeDir $info.removeDir
                Unload-Registry
            }           
            'RemoveEdge' {
                Load-Registry -removeDir $info.removeDir
                Remove-Edge -removeDir $info.removeDir
                Unload-Registry
            }       
            'RemoveOneDrive' {
                Load-Registry -removeDir $info.removeDir
                Remove-OneDrive -removeDir $info.removeDir
                Unload-Registry
            }     
        
        }
    }



    #finalize install.wim
    Unload-Registry
    Unmount-ISO -edition $info.edition -removeDir $info.removeDir
    Compress-ISO -tempDir $info.tempDir -index $info.editionIndex

    #boot wim
    Write-Status 'Disabling Windows 11 Requirements for boot.wim...' -Type Output
    Mount-WindowsImage -ImagePath "$($info.tempDir)\sources\boot.wim" -Index 2 -Path "$($info.removeDir)"
    Load-Registry -removeDir $info.removeDir
    Disable-W11Req
    reg add 'HKLM\OFFLINE_SYSTEM\Setup\Status\ChildCompletion' /v 'setup.exe' /t REG_DWORD /d 3 /f >$null
    Unload-Registry
    Dismount-WindowsImage -Path "$($info.removeDir)" -Save

    #finalize
    Create-ISO -tempDir $info.tempDir -index $info.editionIndex -outPath $info.outDir -isoPath $info.isoPath

    #cleanup
    Remove-Item $info.tempDir -Force -Recurse -ErrorAction SilentlyContinue
    Remove-Item $info.removeDir -Force -Recurse -ErrorAction SilentlyContinue

}



pause

