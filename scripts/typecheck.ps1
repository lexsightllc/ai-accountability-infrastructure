#!/usr/bin/env pwsh
# SPDX-License-Identifier: MPL-2.0
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& 'bash' (Join-Path $ScriptDir 'typecheck') @Args
exit $LASTEXITCODE
