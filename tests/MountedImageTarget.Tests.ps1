Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'functions\ISOTweakerFuncs.psm1'
$tokens = $null
$parseErrors = $null
$moduleAst = [System.Management.Automation.Language.Parser]::ParseFile($modulePath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0) {
    throw "Unable to parse module under test: $($parseErrors[0].Message)"
}

$requiredFunctionNames = @(
    'ConvertTo-NormalizedMountPath'
    'Resolve-MountedImageTarget'
    'Mount-EditionIfNeeded'
)
$functionAsts = @($moduleAst.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
        }, $true))
$functionSources = [ordered]@{}
foreach ($functionName in $requiredFunctionNames) {
    $matches = @($functionAsts | Where-Object Name -eq $functionName)
    if ($matches.Count -ne 1) {
        throw "Expected exactly one [$functionName] definition, found [$($matches.Count)]."
    }
    $functionSources[$functionName] = $matches[0].Extent.Text
}

$mountEditionMatches = @($functionAsts | Where-Object Name -eq 'Mount-Edition')
if ($mountEditionMatches.Count -ne 1) {
    throw "Expected exactly one [Mount-Edition] definition, found [$($mountEditionMatches.Count)]."
}
$mountEditionDismCommands = @($mountEditionMatches[0].FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -in @('Export-WindowsImage', 'Mount-WindowsImage')
        }, $true))
$mountEditionDismCommandMetadata = @($mountEditionDismCommands | ForEach-Object {
        $command = $_
        $errorActionValue = $null
        for ($elementIndex = 0; $elementIndex -lt $command.CommandElements.Count; $elementIndex++) {
            $element = $command.CommandElements[$elementIndex]
            if ($element -is [System.Management.Automation.Language.CommandParameterAst] -and $element.ParameterName -eq 'ErrorAction') {
                if ($null -ne $element.Argument) {
                    $errorActionValue = $element.Argument.Extent.Text
                }
                elseif ($elementIndex + 1 -lt $command.CommandElements.Count) {
                    $errorActionValue = $command.CommandElements[$elementIndex + 1].Extent.Text
                }
            }
        }

        [PSCustomObject]@{
            Name                = $command.GetCommandName()
            ErrorActionValue    = $errorActionValue
            HasErrorActionStop  = $errorActionValue -eq 'Stop'
        }
    })

& {
    param($sources, $mountEditionCommands)

    $mockState = [PSCustomObject]@{
        TargetExists          = $true
        MountedImages         = @()
        MountedImageResponses = New-Object System.Collections.Queue
        QueryError            = $null
        TestPathCalls         = New-Object System.Collections.ArrayList
        GetWindowsImageCalls  = 0
        MountEditionCalls     = New-Object System.Collections.ArrayList
    }
    $testResults = New-Object System.Collections.ArrayList
    $testFailures = New-Object System.Collections.ArrayList

    function Reset-MockState {
        $mockState.TargetExists = $true
        $mockState.MountedImages = @()
        $mockState.MountedImageResponses.Clear()
        $mockState.QueryError = $null
        $mockState.TestPathCalls.Clear()
        $mockState.GetWindowsImageCalls = 0
        $mockState.MountEditionCalls.Clear()
    }

    function Test-Path {
        param (
            [string]$LiteralPath,
            $PathType
        )

        [void]$mockState.TestPathCalls.Add([PSCustomObject]@{
                LiteralPath = $LiteralPath
                PathType    = [string]$PathType
            })
        return [bool]$mockState.TargetExists
    }

    function Get-WindowsImage {
        [CmdletBinding()]
        param (
            [switch]$Mounted
        )

        if (!$Mounted) {
            throw 'Test mock only permits Get-WindowsImage -Mounted.'
        }

        $mockState.GetWindowsImageCalls++
        if ($null -ne $mockState.QueryError) {
            throw [System.InvalidOperationException]$mockState.QueryError
        }
        if ($mockState.MountedImageResponses.Count -gt 0) {
            return $mockState.MountedImageResponses.Dequeue()
        }
        return $mockState.MountedImages
    }

    function Mount-Edition {
        param (
            [string]$ImagePath,
            [string]$workingDir,
            $index,
            [string]$edition
        )

        [void]$mockState.MountEditionCalls.Add([PSCustomObject]@{
                ImagePath  = $ImagePath
                WorkingDir = $workingDir
                Index      = $index
                Edition    = $edition
            })
    }

    foreach ($functionName in $requiredFunctionNames) {
        . ([scriptblock]::Create([string]$sources[$functionName]))
    }

    function Assert-Equal {
        param (
            $Expected,
            $Actual,
            [string]$Message
        )

        if ($Expected -ne $Actual) {
            throw "$Message Expected [$Expected], actual [$Actual]."
        }
    }

    function Assert-Matches {
        param (
            [string]$ExpectedPattern,
            [string]$Actual,
            [string]$Message
        )

        if ($Actual -notmatch $ExpectedPattern) {
            throw "$Message Expected pattern [$ExpectedPattern], actual [$Actual]."
        }
    }

    function Assert-Throws {
        param (
            [scriptblock]$Action,
            [string]$MessagePattern
        )

        $caughtException = $null
        try {
            & $Action
        }
        catch {
            $caughtException = $_.Exception
        }

        if ($null -eq $caughtException) {
            throw "Expected an exception matching [$MessagePattern], but no exception was thrown."
        }
        Assert-Matches -ExpectedPattern $MessagePattern -Actual $caughtException.Message -Message 'Unexpected exception message.'
    }

    function New-MountedImageRecord {
        param (
            [string]$Path,
            [string]$ImagePath,
            $ImageIndex,
            [string]$MountStatus = 'Ok',
            [string]$MountMode = 'ReadWrite'
        )

        return [PSCustomObject]@{
            Path        = $Path
            ImagePath   = $ImagePath
            ImageIndex  = $ImageIndex
            MountStatus = $MountStatus
            MountMode   = $MountMode
        }
    }

    function Invoke-TestCase {
        param (
            [string]$Name,
            [scriptblock]$Body
        )

        Reset-MockState
        try {
            & $Body
        }
        catch {
            [void]$testFailures.Add("$Name`: $($_.Exception.Message)")
            Write-Output "FAIL: $Name"
            return
        }

        [void]$testResults.Add($Name)
        Write-Output "PASS: $Name"
    }

    $targetPath = 'C:\Work\RemoveDir'
    $imagePath = 'C:\images\install.wim'

    Invoke-TestCase 'uses terminating errors for all Mount-Edition DISM commands' {
        Assert-Equal 1 @($mountEditionCommands | Where-Object Name -eq 'Export-WindowsImage').Count 'Export-WindowsImage command count differed.'
        Assert-Equal 2 @($mountEditionCommands | Where-Object Name -eq 'Mount-WindowsImage').Count 'Mount-WindowsImage command count differed.'
        foreach ($command in $mountEditionCommands) {
            Assert-Equal $true $command.HasErrorActionStop "[$($command.Name)] does not use -ErrorAction Stop."
        }
    }

    Invoke-TestCase 'mounts and validates when the target initially is not mounted' {
        $mockState.MountedImageResponses.Enqueue([object[]]@())
        $mockState.MountedImageResponses.Enqueue([object[]]@(
                New-MountedImageRecord -Path $targetPath -ImagePath $imagePath -ImageIndex 3
            ))

        Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'

        Assert-Equal 2 $mockState.GetWindowsImageCalls 'Mounted-image query count differed.'
        Assert-Equal 1 $mockState.MountEditionCalls.Count 'Mount call count differed.'
        Assert-Equal $imagePath $mockState.MountEditionCalls[0].ImagePath 'Mount source differed.'
        Assert-Equal 3 $mockState.MountEditionCalls[0].Index 'Mount index differed.'
        Assert-Equal ([System.IO.Path]::GetFullPath($targetPath)) $mockState.MountEditionCalls[0].WorkingDir 'Normalised mount target differed.'
    }

    Invoke-TestCase 'mounts when only a similarly named unrelated target is mounted' {
        $unrelatedRecord = New-MountedImageRecord -Path "$targetPath-Other" -ImagePath 'C:\images\other.wim' -ImageIndex 1
        $matchingRecord = New-MountedImageRecord -Path $targetPath -ImagePath $imagePath -ImageIndex 3
        $mockState.MountedImageResponses.Enqueue([object[]]@($unrelatedRecord))
        $mockState.MountedImageResponses.Enqueue([object[]]@($unrelatedRecord, $matchingRecord))

        Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'

        Assert-Equal 2 $mockState.GetWindowsImageCalls 'The mounted-image inventory was not rechecked.'
        Assert-Equal 1 $mockState.MountEditionCalls.Count 'An unrelated mount suppressed the requested mount.'
    }

    Invoke-TestCase 'rejects a mount that does not appear in the refreshed inventory' {
        $mockState.MountedImageResponses.Enqueue([object[]]@())
        $mockState.MountedImageResponses.Enqueue([object[]]@())

        Assert-Throws {
            Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'
        } 'did not create a valid mounted image'
        Assert-Equal 2 $mockState.GetWindowsImageCalls 'The mounted-image inventory was not rechecked.'
        Assert-Equal 1 $mockState.MountEditionCalls.Count 'Mount call count differed.'
    }

    Invoke-TestCase 'rejects a conflicting image returned by the refreshed inventory' {
        $mockState.MountedImageResponses.Enqueue([object[]]@())
        $mockState.MountedImageResponses.Enqueue([object[]]@(
                New-MountedImageRecord -Path $targetPath -ImagePath 'C:\images\other.wim' -ImageIndex 2
            ))

        Assert-Throws {
            Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'
        } 'unexpected image'
        Assert-Equal 2 $mockState.GetWindowsImageCalls 'The mounted-image inventory was not rechecked.'
        Assert-Equal 1 $mockState.MountEditionCalls.Count 'Mount call count differed.'
    }

    Invoke-TestCase 'recognises its matching target after path normalisation' {
        $mockState.MountedImages = @(
            New-MountedImageRecord -Path 'c:\work\removedir\' -ImagePath 'c:\IMAGES\install.wim' -ImageIndex 3
        )

        Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'

        Assert-Equal 0 $mockState.MountEditionCalls.Count 'A matching healthy mount was mounted again.'
    }

    Invoke-TestCase 'rejects a different image mounted at its target' {
        $mockState.MountedImages = @(
            New-MountedImageRecord -Path $targetPath -ImagePath 'C:\images\other.wim' -ImageIndex 3
        )

        Assert-Throws {
            Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'
        } 'unexpected image'
        Assert-Equal 0 $mockState.MountEditionCalls.Count 'A conflicting image triggered a mount.'
    }

    Invoke-TestCase 'rejects a different image index mounted at its target' {
        $mockState.MountedImages = @(
            New-MountedImageRecord -Path $targetPath -ImagePath $imagePath -ImageIndex 2
        )

        Assert-Throws {
            Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'
        } 'unexpected image index'
        Assert-Equal 0 $mockState.MountEditionCalls.Count 'A conflicting image index triggered a mount.'
    }

    Invoke-TestCase 'recognises the exported split-image source and index' {
        $splitImagePath = 'C:\images\install.swm'
        $mockState.MountedImages = @(
            New-MountedImageRecord -Path $targetPath -ImagePath 'c:\IMAGES\install2.wim' -ImageIndex 1
        )

        Mount-EditionIfNeeded -ImagePath $splitImagePath -workingDir $targetPath -index 6 -edition 'Pro'

        Assert-Equal 0 $mockState.MountEditionCalls.Count 'The matching split-image export was mounted again.'
    }

    Invoke-TestCase 'rejects a target that needs remounting' {
        $mockState.MountedImages = @(
            New-MountedImageRecord -Path $targetPath -ImagePath $imagePath -ImageIndex 3 -MountStatus 'NeedsRemount'
        )

        Assert-Throws {
            Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'
        } 'NeedsRemount'
        Assert-Equal 0 $mockState.MountEditionCalls.Count 'An unhealthy target triggered a mount.'
    }

    Invoke-TestCase 'rejects a read-only target' {
        $mockState.MountedImages = @(
            New-MountedImageRecord -Path $targetPath -ImagePath $imagePath -ImageIndex 3 -MountMode 'ReadOnly'
        )

        Assert-Throws {
            Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'
        } 'ReadOnly'
        Assert-Equal 0 $mockState.MountEditionCalls.Count 'A read-only target triggered a mount.'
    }

    Invoke-TestCase 'rejects duplicate target records' {
        $mockState.MountedImages = @(
            New-MountedImageRecord -Path $targetPath -ImagePath $imagePath -ImageIndex 3
            New-MountedImageRecord -Path "$targetPath\" -ImagePath $imagePath -ImageIndex 3
        )

        Assert-Throws {
            Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'
        } 'Multiple mounted Windows images'
        Assert-Equal 0 $mockState.MountEditionCalls.Count 'Duplicate target records triggered a mount.'
    }

    Invoke-TestCase 'rejects a missing target before querying mounted images' {
        $mockState.TargetExists = $false

        Assert-Throws {
            Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'
        } 'does not exist or is not a directory'
        Assert-Equal 1 $mockState.TestPathCalls.Count 'Target validation count differed.'
        Assert-Equal 'Container' $mockState.TestPathCalls[0].PathType 'Target validation did not require a directory.'
        Assert-Equal 0 $mockState.GetWindowsImageCalls 'DISM inventory was queried for a missing target.'
        Assert-Equal 0 $mockState.MountEditionCalls.Count 'A missing target triggered a mount.'
    }

    Invoke-TestCase 'fails closed when the mounted-image query fails' {
        $mockState.QueryError = 'simulated inventory failure'

        Assert-Throws {
            Mount-EditionIfNeeded -ImagePath $imagePath -workingDir $targetPath -index 3 -edition 'Pro'
        } 'Unable to query mounted Windows images'
        Assert-Equal 0 $mockState.MountEditionCalls.Count 'An inventory failure triggered a mount.'
    }

    if ($testFailures.Count -ne 0) {
        throw "$($testFailures.Count) mounted-image test(s) failed:`n$($testFailures -join "`n")"
    }
    Write-Output "Dependency-free mounted-image tests: $($testResults.Count)/$($testResults.Count) passed."
} $functionSources $mountEditionDismCommandMetadata
