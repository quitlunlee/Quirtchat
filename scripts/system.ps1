param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CargoArgs)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
$originalDirectory = Get-Location
$originalEnvironment = @{}
Get-ChildItem Env: | ForEach-Object { $originalEnvironment[$_.Name] = $_.Value }
$buildExitCode = 1

try {
    if ($env:OS -ne 'Windows_NT') { throw 'This wrapper configures the Windows MSVC toolchain. Use cargo directly on Linux/macOS.' }
    Set-Location -LiteralPath $taskRoot
    $userProfilePath = [Environment]::GetFolderPath('UserProfile')
    $systemCargoHome = Join-Path $userProfilePath '.cargo'
    $systemRustupHome = Join-Path $userProfilePath '.rustup'
    $cargoPath = Join-Path $systemCargoHome 'bin/cargo.exe'
    if (!(Test-Path -LiteralPath $cargoPath)) { throw 'System Rust was not found at the standard user .cargo/bin location. Install Rust through rustup first.' }

    $vswherePath = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
    if (!(Test-Path -LiteralPath $vswherePath)) { throw 'Visual Studio Installer was not found. Install Visual C++ Build Tools and the Windows SDK.' }
    $visualStudioPath = & $vswherePath -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if ($LASTEXITCODE -ne 0 -or !$visualStudioPath) { throw 'Visual C++ x64/x86 build tools were not found. Add the Desktop development with C++ workload.' }
    $developerModule = Join-Path $visualStudioPath.Trim() 'Common7/Tools/Microsoft.VisualStudio.DevShell.dll'
    Import-Module $developerModule
    Enter-VsDevShell -VsInstallPath $visualStudioPath.Trim() -Arch amd64 -HostArch amd64 -SkipAutomaticLocation

    # Never inherit the temporary GNU build's Rust homes or OpenSSL libraries.
    $env:CARGO_HOME = $systemCargoHome
    $env:RUSTUP_HOME = $systemRustupHome
    $env:CARGO_BUILD_TARGET = 'x86_64-pc-windows-msvc'
    # Native OpenSSL's Perl build cannot reliably handle non-ASCII output paths.
    $env:CARGO_TARGET_DIR = Join-Path ([System.IO.Path]::GetTempPath()) 'clichat-system-build/target'
    foreach ($name in @('OPENSSL_DIR', 'OPENSSL_LIB_DIR', 'OPENSSL_INCLUDE_DIR', 'OPENSSL_NO_VENDOR', 'OPENSSL_STATIC', 'OPENSSL_CONFIG_DIR', 'PERL5LIB', 'PERL5OPT', 'MAKEFLAGS', 'MSYS2_ENV_CONV_EXCL', 'RUSTUP_TOOLCHAIN')) {
        Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
    }

    # OpenSSL needs native Windows Perl; Git/MSYS Perl cannot drive this build.
    $perlCandidates = @()
    $perlCommand = Get-Command perl.exe -ErrorAction SilentlyContinue
    if ($perlCommand) { $perlCandidates += $perlCommand.Source }
    $perlCandidates += @(
        (Join-Path ($env:SystemDrive + '\') 'Strawberry/perl/bin/perl.exe'),
        (Join-Path ($env:SystemDrive + '\') 'Perl64/bin/perl.exe'),
        (Join-Path ([System.IO.Path]::GetTempPath()) 'clichat-build-tools/perl/perl/bin/perl.exe')
    )
    $env:LC_ALL = 'C'
    $env:LANG = 'C'
    $nativePerl = $null
    foreach ($candidate in ($perlCandidates | Select-Object -Unique)) {
        if (!(Test-Path -LiteralPath $candidate)) { continue }
        $perlPlatform = & $candidate -e 'print $^O' 2>$null
        if ($LASTEXITCODE -eq 0 -and $perlPlatform -eq 'MSWin32') { $nativePerl = $candidate; break }
    }
    if (!$nativePerl) { throw 'Native Windows Perl is required to build bundled OpenSSL. Install Strawberry Perl and run this wrapper again.' }
    $env:PATH = (Join-Path $systemCargoHome 'bin') + ';' + (Split-Path -Parent $nativePerl) + ';' + $env:PATH
    $env:OPENSSL_SRC_PERL = $nativePerl
    $channelLine = Get-Content -LiteralPath (Join-Path $taskRoot 'rust-toolchain.toml') | Select-String '^\s*channel\s*=\s*"([^"]+)"'
    if (!$channelLine) { throw 'rust-toolchain.toml does not declare a toolchain channel.' }
    $toolchain = $channelLine.Matches[0].Groups[1].Value + '-x86_64-pc-windows-msvc'
    if (!$CargoArgs -or $CargoArgs.Count -eq 0) { $CargoArgs = @('check', '--lib') }
    if ($CargoArgs -contains '--release') {
        # Ship one executable without requiring the Visual C++ redistributable.
        if ($env:CARGO_ENCODED_RUSTFLAGS) {
            $env:CARGO_ENCODED_RUSTFLAGS += [char]31 + '-C' + [char]31 + 'target-feature=+crt-static'
        } else {
            $env:RUSTFLAGS = ($env:RUSTFLAGS + ' -C target-feature=+crt-static').Trim()
        }
        # openssl-src builds the same optimized /MT /Zl NDEBUG library in dev and
        # release. Reuse only a complete MSVC build matching this lockfile's version.
        $lockfile = Get-Content -LiteralPath (Join-Path $taskRoot 'Cargo.lock') -Raw
        $opensslPackage = [regex]::Match($lockfile, '(?s)\[\[package\]\]\s+name = "openssl-src"\s+version = "([^\"]+)"')
        if ($opensslPackage.Success -and $opensslPackage.Groups[1].Value.Contains('+')) {
            $opensslVersion = $opensslPackage.Groups[1].Value.Split('+')[-1]
            $debugBuild = Join-Path $env:CARGO_TARGET_DIR 'x86_64-pc-windows-msvc/debug/build'
            if (Test-Path -LiteralPath $debugBuild) {
                foreach ($candidate in (Get-ChildItem -LiteralPath $debugBuild -Directory -Filter 'openssl-sys-*')) {
                    $install = Join-Path $candidate.FullName 'out/openssl-build/install'
                    $required = @('lib/libcrypto.lib', 'lib/libssl.lib', 'include/openssl/opensslv.h', 'include/openssl/ssl.h', 'include/openssl/evp.h', 'include/openssl/configuration.h')
                    if (@($required | Where-Object { !(Test-Path -LiteralPath (Join-Path $install $_) -PathType Leaf) }).Count -gt 0) { continue }
                    if ((Get-Item -LiteralPath (Join-Path $install 'lib/libcrypto.lib')).Length -lt 1MB -or (Get-Item -LiteralPath (Join-Path $install 'lib/libssl.lib')).Length -lt 64KB) { continue }
                    $header = Get-Content -LiteralPath (Join-Path $install 'include/openssl/opensslv.h') -Raw
                    if ($header -notmatch ('OPENSSL_VERSION_TEXT\s+"OpenSSL ' + [regex]::Escape($opensslVersion) + ' ')) { continue }
                    $output = Join-Path $candidate.FullName 'output'
                    if (!(Test-Path -LiteralPath $output)) { continue }
                    $nativeBuild = Get-Content -LiteralPath $output -Raw
                    if ($nativeBuild -notmatch '/MT /Zl' -or $nativeBuild -notmatch '/O2' -or $nativeBuild -notmatch 'NDEBUG') { continue }
                    $env:OPENSSL_DIR = $install
                    $env:OPENSSL_STATIC = '1'
                    $env:OPENSSL_NO_VENDOR = '1'
                    $nativePdb = Join-Path $install 'lib/ossl_static.pdb'
                    if (Test-Path -LiteralPath $nativePdb) {
                        $releaseDeps = Join-Path $env:CARGO_TARGET_DIR 'x86_64-pc-windows-msvc/release/deps'
                        New-Item -ItemType Directory -Force -Path $releaseDeps | Out-Null
                        Copy-Item -LiteralPath $nativePdb -Destination (Join-Path $releaseDeps 'ossl_static.pdb') -Force
                    }
                    Write-Host "Reusing the completed MSVC OpenSSL $opensslVersion static build."
                    break
                }
            }
        }
    }
    Write-Host "Using system Rust ($toolchain), MSVC, and native Windows Perl."
    & $cargoPath "+$toolchain" @CargoArgs
    $buildExitCode = $LASTEXITCODE
}
finally {
    Get-ChildItem Env: | Where-Object { !$originalEnvironment.ContainsKey($_.Name) } | ForEach-Object {
        Remove-Item -LiteralPath ("Env:" + $_.Name)
    }
    foreach ($name in $originalEnvironment.Keys) {
        [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], 'Process')
    }
    Set-Location -LiteralPath $originalDirectory
}
exit $buildExitCode
