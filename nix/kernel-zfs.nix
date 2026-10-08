# The enclave kernel, built from source rather than taken from AWS's prebuilt
# blobs, for the ZFS storage spike.
#
# The blobs (Linux 4.14) have no NBD and no device-mapper, so they cannot
# attach the parent's disk over vsock or put dm-crypt under it, and ZFS's
# module has to be compiled against the exact kernel it loads into. This is
# AWS's own enclave kernel recipe — aws-nitro-enclaves-sdk-bootstrap: the 6.6
# line, their config, their two patches — with only the block layers added.
#
# The vsock patch is not optional here. It removes a pushback path that
# deadlocks when the parent's and the enclave's TX queues fill together, and
# block I/O over vsock is exactly that load. It is not upstream as of 6.12,
# and does not apply there, which is why this stays on 6.6.
{ lib
, stdenv
, fetchFromGitHub
, runCommand
, flex
, bison
, linux_6_6
, linuxManualConfig
, linuxPackagesFor
, zfs
}:

let
  bootstrap = fetchFromGitHub {
    owner = "aws";
    repo = "aws-nitro-enclaves-sdk-bootstrap";
    rev = "f718dea60a9d9bb8b8682fd852ad793912f3c5db";
    hash = "sha256-DmNnH6lqweRz1u8nza6FvgJFvDGPactpHruyq0SYkp8=";
  };

  kernelPatches = map (name: { inherit name; patch = "${bootstrap}/kernel/${name}"; }) [
    "nsm.patch"
    "0001-vsock-virtio-Remove-queued_replies-pushback-logic.patch"
  ];

  # What olddefconfig must keep. Anything it cannot satisfy it drops without
  # a word, so each is checked rather than trusted.
  required = [
    "MODULES=y" "NSM=m" "VSOCKETS=y" "VIRTIO_VSOCKETS=y"
    "BLK_DEV_NBD=y" "BLK_DEV_DM=y" "DM_CRYPT=y"
    # OpenZFS's configure refuses a kernel without these.
    "ZLIB_INFLATE=y" "ZLIB_DEFLATE=y"
  ];

  configfile = stdenv.mkDerivation {
    name = "nitro-enclave-zfs-kernel-config";
    inherit (linux_6_6) src;
    patches = map (p: p.patch) kernelPatches;
    nativeBuildInputs = [ flex bison ];
    dontConfigure = true;
    buildPhase = ''
      cat ${bootstrap}/kernel/microvm-kernel-config-x86_64 - > .config <<'EOF'
      CONFIG_NSM=m
      CONFIG_BLK_DEV_NBD=y
      CONFIG_MD=y
      CONFIG_BLK_DEV_DM=y
      CONFIG_DM_CRYPT=y
      CONFIG_CRYPTO_AES_NI_INTEL=y
      EOF
      make olddefconfig
      for o in ${lib.concatStringsSep " " required}; do
        grep -qx "CONFIG_$o" .config || { echo "olddefconfig dropped CONFIG_$o" >&2; exit 1; }
      done
    '';
    installPhase = "cp .config $out";
  };

  kernel = linuxManualConfig {
    inherit (linux_6_6) src version modDirVersion;
    inherit configfile kernelPatches;
    allowImportFromDerivation = true;
    # The version string the kernel embeds is part of PCR0. Unpinned it names
    # whoever built it (`joshua@joshua-OptiPlex-7070`), so two machines
    # produce two measurements. The same values as AWS's recipe.
    extraMakeFlags = [ "KBUILD_BUILD_USER=nixbuild" "KBUILD_BUILD_HOST=nixbuilder" ];
  };

  zfsKmod = (linuxPackagesFor kernel).${zfs.kernelModuleAttribute};
in
assert zfsKmod.version == zfs.version;
{
  inherit kernel zfsKmod;
  zfsUser = zfs;

  # The layout eif.nix reads in place of blobs/x86_64.
  dir = runCommand "nitro-enclave-zfs-kernel" { } ''
    mkdir -p $out
    cp ${kernel}/bzImage $out/bzImage
    cp ${configfile} $out/bzImage.config
    cp ${bootstrap}/kernel/cmdline/x86_64.cmdline $out/cmdline
    cp "$(find ${kernel.modules}/lib/modules -name nsm.ko)" $out/nsm.ko
  '';
}
