#!/usr/bin/env pwsh
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& 'bash' (Join-Path $ScriptDir 'check') @Args
exit $LASTEXITCODE
