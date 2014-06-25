if [ "${TRAVIS_OS_NAME}" = "osx" ] || [ "${PLATFORM}" = "osx" ]; then
    target=apple-darwin
elif [ "${TRAVIS_OS_NAME}" = "linux" ] || [ "${PLATFORM}" = "linux" ]; then
    target=unknown-linux-gnu
elif [ "${OS}" = "Windows_NT" ] || [ "${PLATFORM}" = "win" ]; then
    target=pc-mingw32
    windows=1
fi

if [ "${TRAVIS}" = "true" ] && [ "${target}" == "unknown-linux-gnu" ]; then
    # Install a 32-bit compiler for linux
    sudo apt-get update
    sudo apt-get install gcc-multilib
fi

# Install both 64 and 32 bit libraries. Apparently travis barfs if you try to
# just install the right ones? This should enable cross compilation in the
# future anyway.
if [ -z "${windows}" ]; then
    curl -O http://static.rust-lang.org/dist/rust-nightly-i686-$target.tar.gz
    tar xfz rust-nightly-i686-$target.tar.gz
    curl -O http://static.rust-lang.org/dist/rust-nightly-x86_64-$target.tar.gz
    tar xfz rust-nightly-x86_64-$target.tar.gz
    cp -r rust-nightly-i686-$target/lib/rustlib/i686-$target \
          rust-nightly-x86_64-$target/lib/rustlib
    (cd rust-nightly-x86_64-$target && \
     find lib/rustlib/i686-$target/lib -type f >> \
     lib/rustlib/manifest.in)

    ./rust-nightly-x86_64-$target/install.sh --prefix=rustc
    rm -rf rust-nightly-x86_64-$target
else
    rm -rf *.exe rustc
    curl -O http://static.rust-lang.org/dist/rust-nightly-install.exe
    innounp -y -x rust-nightly-install.exe
    mv '{app}' rustc
fi

export RUSTC_FLAGS="--target=${ARCH}-${target}"

