# Build at a known-good commit
$COMMIT_ID="c91baf9c9971332d9280a7062943c54a4f13a7ec"

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
cd picotls
git checkout -q "$COMMIT_ID"
git submodule init
git submodule update
git apply ..\picoquic\ci\picotls-win32.patch

msbuild "/p:Configuration=$Env:Configuration" "/p:Platform=$Env:Platform" /m picotlsvs\picotlsvs.sln

popd
