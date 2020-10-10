if ($Env:Platform -eq "x64") { cd x64 }
cd "$Env:Configuration"
pwd

msbuild "/p:Configuration=$Env:Configuration" "/p:Platform=$Env:Platform" /m picotlsvs\picoquic.sln

