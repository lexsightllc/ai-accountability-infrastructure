#!/usr/bin/env pwsh
# SPDX-License-Identifier: MPL-2.0
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
& 'bash' (Join-Path $ScriptDir 'e2e') @Args
exit $LASTEXITCODE
