# Build at a known-good commit
$COMMIT_ID="9accdf4af580e2ad883c929f8ca7a4cc58f15379"

pushd ..
git clone https://github.com/h2o/picotls 2>&1 | %{ "$_" }
cd picotls
git checkout -q "$COMMIT_ID"
git submodule init
git submodule update
git apply ..\picoquic\ci\picotls-win32.patch

msbuild "/p:Configuration=$Env:Configuration" "/p:Platform=$Env:Platform" /m picotlsvs\picotlsvs.sln

popd
