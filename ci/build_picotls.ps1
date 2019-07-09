# Build at a known-good commit
$COMMIT_ID="aa309cc0728dee0b4d45b0615fd04bf019e63e9c"

# Match expectations of picotlsvs project.
foreach ($dir in "$Env:OPENSSLDIR","$Env:OPENSSL64DIR") {
    if ($dir) {
        cp "$dir\lib\libcrypto.lib" "$dir"
        cp C:\OpenSSL-Win32\include\openssl\applink.c "$dir\include\openssl"
    }
}

pushd ..
git clone https://github.com/h2o/picotls 2>&1 | %{ "$_" }
cd picotls
git checkout -q "$COMMIT_ID"
git apply ..\picoquic\ci\picotls-win32.patch
git submodule init
git submodule update

msbuild "/p:Configuration=$Env:Configuration" "/p:Platform=$Env:Platform" /m picotlsvs\picotlsvs.sln

popd
