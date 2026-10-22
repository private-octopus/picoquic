# Diagnose a process that fails to load (0xC0000135 / 0xC0000139): for each DLL imported by
# the executable, show which file the loader would find and list imports that it does not export.
param([string]$Exe, [string]$SystemDir = "$Env:windir\SysWOW64")

$dumpbin = Get-ChildItem "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx86\x86\dumpbin.exe",
    "$Env:ProgramFiles\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx86\x86\dumpbin.exe" -ErrorAction SilentlyContinue |
    Select-Object -Last 1
if ($dumpbin -eq $null) {
    Write-Host "dumpbin.exe not found"
}
else {
    $exePath = (Resolve-Path $Exe).Path
    $exeDir = Split-Path $exePath
    $imports = @{}
    $current = $null
    foreach ($line in (& $dumpbin.FullName /nologo /imports $exePath)) {
        if ($line -match '^\s{4}(\S+\.dll)\s*$') {
            $current = $Matches[1]
            $imports[$current] = @()
        }
        elseif ($current -ne $null -and $line -match '^\s+[0-9A-Fa-f]+\s+(\w+)\s*$') {
            $imports[$current] += $Matches[1]
        }
    }
    foreach ($dll in ($imports.Keys | Sort-Object)) {
        if ($dll -like "api-ms-*") {
            continue
        }
        $found = $null
        foreach ($dir in @($exeDir, $SystemDir, $Env:windir) + ($Env:Path -split ';')) {
            if ($dir -and (Test-Path (Join-Path $dir $dll))) {
                $found = Join-Path $dir $dll
                break
            }
        }
        if ($found -eq $null) {
            Write-Host "$dll : NOT FOUND"
        }
        else {
            $version = (Get-Item $found).VersionInfo.FileVersion
            $exports = @{}
            foreach ($line in (& $dumpbin.FullName /nologo /exports $found)) {
                if ($line -match '^\s+\d+\s+[0-9A-Fa-f]+\s+(?:[0-9A-Fa-f]{8}\s+)?(\w+)') {
                    $exports[$Matches[1]] = 1
                }
            }
            $missing = @($imports[$dll] | Where-Object { -not $exports.ContainsKey($_) })
            Write-Host "$dll : $found ($version), $($imports[$dll].Count) imports, $($missing.Count) missing"
            foreach ($name in $missing) {
                Write-Host "    missing: $name"
            }
        }
    }
}
