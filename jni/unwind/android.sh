
__internal_prepare_armeabi_v7a(){
      export NDK=/home/ring0/develop/android-ndk-r14b
      export TOOLCHAINS=$NDK/toolchains/arm-linux-androideabi-4.9/prebuilt/linux-x86_64/bin
      export TOOLCHAIN=arm-linux-androideabi
      export SYSROOT=$NDK/platforms/android-21/arch-arm
      export CC="$TOOLCHAINS/arm-linux-androideabi-gcc --sysroot=$SYSROOT"
      export CXX="$TOOLCHAINS/arm-linux-androideabi-g++ --sysroot=$SYSROOT"
      export PATH=$TOOLCHAINS:$PATH
      sed -i -e 's/#define HAVE_DECL_PTRACE_POKEUSER 0/#define HAVE_DECL_PTRACE_POKEUSER 1/g' include/config.h
}

__internal_prepare_arm64_v8a() {
      export NDK=/home/ring0/develop/android-ndk-r14b
      export TOOLCHAINS=$NDK/toolchains/aarch64-linux-android-4.9/prebuilt/linux-x86_64/bin
      export TOOLCHAIN=aarch64-linux-android
      export SYSROOT=$NDK/platforms/android-21/arch-arm64
      export CC="$TOOLCHAINS/aarch64-linux-android-gcc --sysroot=$SYSROOT"
      export CXX="$TOOLCHAINS/aarch64-linux-android-g++ --sysroot=$SYSROOT"
      export PATH=$TOOLCHAINS:$PATH
      sed -i -e 's/#define HAVE_DECL_PTRACE_POKEUSER 1/#define HAVE_DECL_PTRACE_POKEUSER 0/g' include/config.h
}

__internal_prepare_x86(){
      export NDK=/home/ring0/develop/android-ndk-r14b
      export TOOLCHAINS=$NDK/toolchains/x86-4.9/prebuilt/linux-x86_64/bin
      export TOOLCHAIN=i686-linux-android
      export SYSROOT=$NDK/platforms/android-21/arch-x86
      export CC="$TOOLCHAINS/i686-linux-android-gcc --sysroot=$SYSROOT"
      export CXX="$TOOLCHAINS/i686-linux-android-g++ --sysroot=$SYSROOT"
      export PATH=$TOOLCHAINS:$PATH
      sed -i -e 's/#define HAVE_DECL_PTRACE_POKEUSER 0/#define HAVE_DECL_PTRACE_POKEUSER 1/g' include/config.h
}

__internal_prepare_x86_64(){
      export NDK=/home/ring0/develop/android-ndk-r14b
      export TOOLCHAINS=$NDK/toolchains/x86_64-4.9/prebuilt/linux-x86_64/bin
      export TOOLCHAIN=x86_64-linux-android
      export SYSROOT=$NDK/platforms/android-21/arch-x86_64
      export CC="$TOOLCHAINS/x86_64-linux-android-gcc --sysroot=$SYSROOT"
      export CXX="$TOOLCHAINS/x86_64-linux-android-g++ --sysroot=$SYSROOT"
      export PATH=$TOOLCHAINS:$PATH
      sed -i -e 's/#define HAVE_DECL_PTRACE_POKEUSER 0/#define HAVE_DECL_PTRACE_POKEUSER 1/g' include/config.h
}

__internal_general_configure() {
      ./configure --host=$TOOLCHAIN --disable-coredump
      make -j 4 CFLAGS="" LDFLAGS="-static"
}

build_armeabi_v7a(){
      __internal_prepare_armeabi_v7a
      __internal_general_configure
}

build_arm64_v8a(){
      __internal_prepare_arm64_v8a
      __internal_general_configure
}

build_x86(){
      __internal_prepare_x86
      __internal_general_configure
}

build_x86_64(){
      __internal_prepare_x86_64
      __internal_general_configure
}

build_x86_64
