#!/bin/sh
#install missing openssl for brew

echo "Try: brew install openssl"
brew install openssl
whereis openssl