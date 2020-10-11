if ($Env:Platform -eq "x64") { mkdir -Force x64; mkdir -Force x64\$Env:Configuration }
else { mkdir -Force $Env:Configuration }
pwd
msbuild "/p:Configuration=$Env:Configuration" "/p:Platform=$Env:Platform" /m .\picoquic.sln

