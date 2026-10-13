# Build at a known-good commit
$COMMIT_ID= "f06553b877ada93c860dd1db9002eabf7365292d"

# Match expectations of picotlsvs project.
mkdir $dir\include\
foreach ($dir in "$Env:OPENSSLDIR","$Env:OPENSSL64DIR") {
    if ($dir) {
        cp "$dir\lib\libcrypto.lib" "$dir"
        cp C:\OpenSSL-Win32\include\openssl\applink.c "$dir\include\openssl"
    }
}

pushd ..
git clone https://github.com/h2o/picotls 2>&1 | %{ "$_" }
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
cd picotls
git checkout -q "$COMMIT_ID" 2>&1 | %{ "$_" }
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# git writes submodule progress to stderr; PowerShell treats that as a failed command.
git submodule update --init --recursive 2>&1 | %{ "$_" }
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

msbuild "/p:Configuration=$Env:Configuration" "/p:Platform=$Env:Platform" /m picotlsvs\picotlsvs.sln

popd
