param([Parameter(ValueFromRemainingArguments = $true)][string[]]$CargoArgs)
$ErrorActionPreference = 'Stop'
$taskRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $taskRoot
# Native GNU tools require a physical ASCII path, even for their sysroot.
$taskTools = Join-Path ([System.IO.Path]::GetTempPath()) 'clichat-build-tools'
if (!(Test-Path -LiteralPath (Join-Path $taskTools 'cargo/bin/cargo.exe'))) { $taskTools = Join-Path $taskRoot '.tools' }
$env:RUSTUP_HOME = Join-Path $taskTools 'rustup'
$env:CARGO_HOME = Join-Path $taskTools 'cargo'
$env:PATH = 'C:\Program Files\Git\usr\bin;' + (Join-Path $taskTools 'w64devkit/bin') + ';' + (Join-Path $taskTools 'cargo/bin') + ';' + $env:PATH
$env:PERL5LIB = $null
$env:PERL5OPT = '-I/' + ((Join-Path $taskTools 'perl-pure').Replace('\', '/').Replace(':', ''))
$env:MSYS2_ENV_CONV_EXCL = 'PERL5OPT'
$env:MAKEFLAGS = '-j12'
$env:CARGO_TARGET_DIR = Join-Path $taskTools 'target'
$env:CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER = Join-Path $taskTools 'w64devkit/bin/gcc.exe'
if (Test-Path -LiteralPath (Join-Path $taskTools 'openssl/lib/libcrypto.a')) {
    $env:OPENSSL_NO_VENDOR = '1'
    $env:OPENSSL_STATIC = '1'
    $env:OPENSSL_DIR = Join-Path $taskTools 'openssl'
}
& cargo @CargoArgs
exit $LASTEXITCODE
