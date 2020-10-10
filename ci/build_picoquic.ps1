if ($Env:Platform -eq "x64") { mkdir -Force x64; cd x64 }
mkdir -Force $Env:Configuration"
pwd
if ($Env:Platform -eq "x64") { cd .. }
pwd
msbuild "/p:Configuration=$Env:Configuration" "/p:Platform=$Env:Platform" /m picoquic.sln

