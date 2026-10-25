#!/usr/bin/env bash
# Builds the video converter the app ships: a static FFmpeg that can read the
# usual phone and camera videos and write VP9/Opus WebM, and nothing else.
# No network, no devices, no hardware access; LGPL components only.
#
#   tools/ffmpeg/build.sh android   # needs ANDROID_NDK_HOME
#   tools/ffmpeg/build.sh windows   # needs mingw-w64 (x86_64-w64-mingw32-gcc)
#
# The result lands in tools/ffmpeg/<target>/ffmpeg (or ffmpeg.exe).
set -euo pipefail

TARGET=${1:?android, windows or linux}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${FFMPEG_WORK:-$HERE/.work}/$TARGET
OUT=$HERE/$TARGET
PREFIX=$WORK/prefix
FFMPEG_VERSION=7.1.1
OPUS_VERSION=1.5.2
VPX_TAG=v1.15.2
JOBS=$(nproc)
mkdir -p "$WORK" "$OUT" "$PREFIX"
cd "$WORK"

case $TARGET in
  android)
    : "${ANDROID_NDK_HOME:?set ANDROID_NDK_HOME}"
    API=24
    TOOLS=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin
    HOST=aarch64-linux-android
    export CC=$TOOLS/$HOST$API-clang CXX=$TOOLS/$HOST$API-clang++ AR=$TOOLS/llvm-ar RANLIB=$TOOLS/llvm-ranlib
    export NM=$TOOLS/llvm-nm STRIP=$TOOLS/llvm-strip
    VPX_TARGET=arm64-android-gcc
    FF_FLAGS=(--target-os=android --arch=aarch64 --enable-cross-compile --cc="$CC" --cxx="$CXX" --ar="$AR"
      --ranlib="$RANLIB" --nm="$NM" --strip="$STRIP" --enable-pic --extra-ldflags="-static")
    EXE=ffmpeg
    ;;
  windows)
    HOST=x86_64-w64-mingw32
    export CC=$HOST-gcc CXX=$HOST-g++ AR=$HOST-ar RANLIB=$HOST-ranlib NM=$HOST-nm STRIP=$HOST-strip
    VPX_TARGET=x86_64-win64-gcc
    FF_FLAGS=(--target-os=mingw32 --arch=x86_64 --enable-cross-compile --cross-prefix=$HOST-
      --extra-ldflags="-static -static-libgcc")
    EXE=ffmpeg.exe
    ;;
  linux)
    HOST=x86_64-linux-gnu
    export CC=$HOST-gcc CXX=$HOST-g++ AR=$HOST-ar RANLIB=$HOST-ranlib NM=$HOST-nm STRIP=$HOST-strip
    VPX_TARGET=x86_64-linux-gcc
    FF_FLAGS=(--target-os=linux --arch=x86_64 --cc="$CC" --cxx="$CXX" --ar="$AR"
      --ranlib="$RANLIB" --nm="$NM" --strip="$STRIP" --enable-pic --extra-ldflags="-static")
    EXE=ffmpeg
    ;;
  *) echo "unknown target $TARGET" >&2; exit 2 ;;
esac

fetch() { [ -e "$2" ] || curl -sSfL -o "$2" "$1"; }

# Opus
fetch "https://downloads.xiph.org/releases/opus/opus-$OPUS_VERSION.tar.gz" opus.tar.gz
rm -rf opus && mkdir opus && tar -xzf opus.tar.gz -C opus --strip-components=1
(cd opus && ./configure --host=$HOST --prefix="$PREFIX" --disable-shared --enable-static \
  --disable-doc --disable-extra-programs --with-pic >/dev/null && make -j"$JOBS" >/dev/null && make install >/dev/null)

# libvpx (VP8/VP9)
if [ ! -d libvpx ]; then
  if command -v git >/dev/null 2>&1; then
    git clone -q --depth 1 --branch $VPX_TAG https://chromium.googlesource.com/webm/libvpx
  else
    fetch "https://github.com/webmproject/libvpx/archive/refs/tags/$VPX_TAG.tar.gz" libvpx.tar.gz
    mkdir libvpx && tar -xzf libvpx.tar.gz -C libvpx --strip-components=1
  fi
fi
(cd libvpx && make distclean >/dev/null 2>&1 || true
 CROSS=${HOST}- ./configure --target=$VPX_TARGET --prefix="$PREFIX" --disable-shared --enable-static \
   --disable-examples --disable-tools --disable-docs --disable-unit-tests --enable-vp9-highbitdepth \
   --enable-pic >/dev/null && make -j"$JOBS" >/dev/null && make install >/dev/null)

# FFmpeg
fetch "https://ffmpeg.org/releases/ffmpeg-$FFMPEG_VERSION.tar.xz" ffmpeg.tar.xz
rm -rf ffmpeg && mkdir ffmpeg && tar -xJf ffmpeg.tar.xz -C ffmpeg --strip-components=1
cd ffmpeg
PKG_CONFIG_LIBDIR=$PREFIX/lib/pkgconfig PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig ./configure \
  "${FF_FLAGS[@]}" --prefix="$PREFIX" --pkg-config=pkg-config --pkg-config-flags=--static \
  --extra-cflags="-I$PREFIX/include" --extra-ldflags="-L$PREFIX/lib" \
  --disable-everything --disable-autodetect --disable-network --disable-doc --disable-debug \
  --disable-ffplay --disable-ffprobe --disable-avdevice --disable-postproc --disable-shared --enable-static \
  --enable-ffmpeg --enable-avfilter --enable-swscale --enable-swresample \
  --enable-libvpx --enable-libopus --enable-zlib \
  --enable-protocol=pipe \
  --enable-demuxer=mov,matroska \
  --enable-muxer=webm,image2pipe \
  --enable-parser=h264,hevc,vp8,vp9,aac,mpegaudio,opus,vorbis,ac3,flac,mpeg4video \
  --enable-decoder=h264,hevc,vp8,vp9,libvpx_vp8,libvpx_vp9,mpeg4,mjpeg,prores,aac,aac_latm,mp3,mp3float,opus,vorbis,ac3,eac3,flac,alac,pcm_s16le,pcm_s16be,pcm_s24le,pcm_s32le,pcm_f32le,pcm_u8,pcm_mulaw,pcm_alaw \
  --enable-encoder=libvpx_vp9,libopus,png \
  --enable-filter=scale,thumbnail,format,aformat,aresample,null,anull,setsar,fps \
  --enable-bsf=h264_mp4toannexb,hevc_mp4toannexb,vp9_superframe >/dev/null
make -j"$JOBS" >/dev/null
$STRIP ffmpeg${EXE#ffmpeg}
cp "ffmpeg${EXE#ffmpeg}" "$OUT/$EXE"
cp LICENSE.md "$OUT/LICENSE.md"
echo "built $OUT/$EXE"
