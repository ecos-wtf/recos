#!/bin/sh

TARGET="mipsisa32-elf"
PREFIX="${HOME}/gnutools"

mkdir -p ${PREFIX}
mkdir -p /tmp/src

echo "[+] Installing dependencies."
sudo yum install -q -y compat-gcc-34 binutils glibc-devel.i686 tcl unzip

echo "[+] Downloading sources."
wget --quiet ftp://ftp.gnu.org/gnu/gcc/gcc-3.2.1/gcc-core-3.2.1.tar.gz
wget --quiet ftp://ftp.gnu.org/gnu/gcc/gcc-3.2.1/gcc-g++-3.2.1.tar.gz
wget --quiet ftp://ftp.gnu.org/gnu/binutils/binutils-2.13.1.tar.bz2
wget --quiet ftp://ftp-stud.fht-esslingen.de/pub/Mirrors/sourceware.org/newlib/newlib-1.11.0.tar.gz
wget --quiet https://ftp.gnu.org/gnu/gcc/gcc-3.4.6/gcc-3.4.6.tar.gz

echo "[+] Downloading patches."
wget --quiet https://ecos.sourceware.org/binutils-2.13.1-v850-hashtable.patch -O /tmp/src/binutils-2.13.1-v850-hashtable.patch
wget --quiet https://ecos.sourceware.org/gcc-3.2.1-arm-multilib.patch -O /tmp/src/gcc-3.2.1-arm-multilib.patch

tar xzf gcc-core-3.2.1.tar.gz -C /tmp/src
tar xzf gcc-g++-3.2.1.tar.gz -C /tmp/src
tar xzf gcc-3.4.6.tar.gz -C /tmp/src
tar xf binutils-2.13.1.tar.bz2 -C /tmp/src
tar xzf newlib-1.11.0.tar.gz -C /tmp/src

cd /tmp/src

echo "[+] Applying patches."
patch -p0 < binutils-2.13.1-v850-hashtable.patch
patch -p0 < gcc-3.2.1-arm-multilib.patch

echo "[+] Moving newlibs."
mv newlib-1.11.0/newlib gcc-3.2.1 > /dev/null 2>&1
mv newlib-1.11.0/libgloss gcc-3.2.1 > /dev/null 2>&1

echo "[+] Building binutils 2.13.1."
mkdir -p /tmp/build/binutils
cd /tmp/build/binutils
/tmp/src/binutils-2.13.1/configure --target=${TARGET} --prefix=${PREFIX}
make -w all
make install

echo "[+] Building GCC 3.4.6"
mkdir -p /tmp/build/gcc-3.4.6
cd /tmp/build/gcc-3.4.6
/tmp/src/gcc-3.4.6/configure --prefix=${PREFIX} --enable-languages=c,c++ --with-gnu-as --with-gnu-ld
make -w all
make install

export PATH="$PATH:${PREFIX}/bin"
export gcc="${PREFIX}/bin/gcc"
export CC="${PREFIX}/bin/gcc"

echo "[+] Building GCC 3.2.1."
mkdir -p /tmp/build/gcc
cd /tmp/build/gcc
/tmp/src/gcc-3.2.1/configure --target=${TARGET} --prefix=${PREFIX} --enable-languages=c,c++ --with-gnu-as --with-gnu-ld --with-newlib --with-gxx-include-dir="${PREFIX}/${TARGET}/include" -v
make -w all
make install
echo "[+] Cleaning up."
cd
rm -f *gz
rm -f *bz2
rm -rf /tmp/src
rm -rf /tmp/build
echo "[+] Done"

cd
export PATH="$PATH:${HOME}/gnutools/bin"

echo "[+] Downloading eCOS source."
wget --quiet "https://www.downloads.netgear.com/files/GPL/CG3700B_v5.5.7mp2_LxG1.0.7mp2_src.zip"
unzip CG3700B_v5.5.7mp2_LxG1.0.7mp2_src.zip
unzip CG3700B_v5.5.7mp2_LxG1.0.7mp2_src/CG3700B_v5.5.7mp2_src.zip
tar xvf CG3700B_v5.5.7mp2_src/ProdD30_BFC5.5.7mp2_eCos.tar.bz2

# fix tail call syntax
find -name "build.bash" -print -exec sed -i "s/make -s clean/find -iname \"make*\" -exec sed -i \'s\/tail \+2\/tail -n\+2\/g\' \{\} \\\;\nmake -s clean/" {} \;
# remove unnecessary call to diff
find -name "build.bash" -print -exec sed -i 's/^diff.*$//' {} \;

echo "[+] Building bcm33xx."
cd ${HOME}/rbb_cm_ecos/ecos-src/bcm33xx
bash build.bash > /dev/null 2>&1
echo "[+] Done."

echo "[+] Building bcm33xx_smp."
cd ${HOME}/rbb_cm_ecos/ecos-src/bcm33xx_smp
bash build.bash > /dev/null 2>&1
echo "[+] Done"

echo "[+] Building bcm33xx_ipv6."
cd rbb_cm_ecos/ecos-src/bcm33xx_ipv6
bash build.bash > /dev/null 2>&1
echo "[+] Done"

mkdir -p /tmp/ecoslibs
find -name "*.o" -print -exec cp {} /tmp/ecoslibs/ \;
FUNC_TOTAL=`find /tmp/ecoslibs -name "*.o" -exec mipsisa32-elf-objdump -t {} \; | grep F | awk '{ print $6}' | sort -u | wc -l`
echo "[+] ${FUNC_TOTAL} functions ready to be translated into FIDB."
echo "[+] Object files are now available in /tmp/ecoslibs."
