# Build at a known-good commit
# Must select a commit date (can copy-paste from git log)
$COMMIT_ID="8443c09c0f091482679e0b32c4f238928b7f5c1e"
$COMMIT_DATE="Thu Oct 4 10:28:52 2018 +0900"

# Match expectations of picotlsvs project.
foreach ($dir in "$Env:OPENSSLDIR","$Env:OPENSSL64DIR") {
    if ($dir) {
        cp "$dir\lib\libcrypto.lib" "$dir"
        cp C:\OpenSSL-Win32\include\openssl\applink.c "$dir\include\openssl"
    }
}

pushd ..
git clone --branch master --single-branch --shallow-submodules --recurse-submodules --no-tags --shallow-since="$COMMIT_DATE" https://github.com/h2o/picotls 2>&1 | %{ "$_" }
cd picotls
git apply ..\picoquic\ci\picotls-win32.patch
git checkout -q "$COMMIT_ID"
#git submodule init
#git submodule update

msbuild "/p:Configuration=$Env:Configuration" "/p:Platform=$Env:Platform" /m picotlsvs\picotlsvs.sln

popd
