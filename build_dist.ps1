$ErrorActionPreference = 'Continue'
Set-Location $PSScriptRoot

python -m pip install --upgrade build 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'pip install build failed' }
python -m build 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'python -m build failed' }

$stage = Join-Path $env:TEMP 'usbkey-guard-stage'
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item -Recurse -Force src, tests, .github -Destination $stage
Copy-Item -Force README.md, INSTALL.md, QUICKSTART.md, LIMITATIONS.md, RELEASE.md, LICENSE, pyproject.toml, requirements.txt, .gitignore, build_dist.ps1 -Destination $stage
Get-ChildItem -Recurse -Force -Directory -Path $stage -Filter '__pycache__' | Remove-Item -Recurse -Force
Get-ChildItem -Recurse -Force -Directory -Path $stage -Filter '*.egg-info' | Remove-Item -Recurse -Force
Get-ChildItem -Recurse -Force -File -Path $stage -Filter '*.pyc' | Remove-Item -Force
Compress-Archive -Path (Join-Path $stage '*') -DestinationPath (Join-Path $PSScriptRoot 'dist\usbkey-guard-source.zip') -Force

Get-ChildItem (Join-Path $PSScriptRoot 'dist') | Select-Object Name, Length | Format-Table -AutoSize
