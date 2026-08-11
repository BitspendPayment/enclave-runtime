# Assemble an Enclave Image Format file.
#
# The layout is not a matter of taste — it is what AWS's `init` expects, and
# each detail below was learned by booting an image that failed in a way that
# named something else:
#
#   ramdisk1   init, nsm.ko
#   ramdisk2   cmd, env, rootfs/…
#
# `init` inserts the NSM driver, sends a heartbeat to the parent over vsock,
# then binds `/rootfs` onto itself, mounts the pseudo-filesystems *inside* it,
# and runs the contents of `/cmd` with the environment from `/env`.
#
# The mountpoints therefore live under `rootfs/`. An image without them dies
# with `mount: /dev: No such file or directory`, which reads like a bootstrap
# fault and is not.
{ lib
, stdenvNoCC
, cpio
, jq
, libfaketime
, closureInfo
, blobs
, eif-build
}:

{ name
  # Attribute set of destination path (relative to rootfs/) → store path.
, payload
  # Packages whose runtime closures must be inside the image. These are the
  # derivations themselves, not the files copied out of them: `closureInfo`
  # resolves store *paths*, and handing it `${pkg}/bin/thing` fails with
  # "not in the Nix store", which is true and unhelpful.
, closureRoots ? [ ]
  # What `init` executes, as an absolute path inside rootfs/.
, command
  # Environment for the command, as an attribute set.
, env ? { }
  # Copy the payload's runtime closure into the image. Needed for anything
  # dynamically linked — which is everything except the static musl self-test.
, withClosure ? true
  # Shell run inside the assembled rootfs/, for anything a plain file copy
  # cannot express — symlinks, scripts, permissions.
, extraSetup ? ""
}:

let
  # The transitive runtime dependencies of the payload: glibc, libgcc and
  # whatever else the binaries actually open at runtime.
  closure = closureInfo { rootPaths = closureRoots; };

  envFile = lib.concatStringsSep "\n"
    (lib.mapAttrsToList (k: v: "${k}=${v}") env);

  copyPayload = lib.concatStringsSep "\n" (lib.mapAttrsToList
    (dest: src: ''
      mkdir -p "rootfs/$(dirname ${lib.escapeShellArg dest})"
      cp -L ${lib.escapeShellArg src} "rootfs/${dest}"
      chmod +x "rootfs/${dest}" || true
    '')
    payload);
in
stdenvNoCC.mkDerivation {
  pname = "${name}-eif";
  version = "1";

  dontUnpack = true;
  nativeBuildInputs = [ cpio jq libfaketime eif-build ];

  buildPhase = ''
    runHook preBuild

    # ---- ramdisk 1: what boots -----------------------------------------
    mkdir -p rd1
    cp ${blobs}/blobs/x86_64/init rd1/init
    cp ${blobs}/blobs/x86_64/nsm.ko rd1/nsm.ko
    chmod +x rd1/init

    # ---- ramdisk 2: what runs ------------------------------------------
    mkdir -p rd2 && cd rd2
    mkdir -p rootfs/{dev/pts,dev/shm,proc,sys/fs/cgroup,run,tmp,etc}

    ${copyPayload}

    ${lib.optionalString withClosure ''
      # Everything the payload links against, at the same store paths it was
      # built to look for. `init` runs inside rootfs/, so the store has to be
      # there rather than at the image root.
      mkdir -p rootfs/nix/store
      for path in $(cat ${closure}/store-paths); do
        cp -a "$path" rootfs/nix/store/
      done
      chmod -R u+w rootfs/nix/store
    ''}

    ${lib.optionalString (extraSetup != "") ''
      ( cd rootfs
        ${extraSetup}
      )
    ''}

    printf '%s\n' ${lib.escapeShellArg command} > cmd
    printf '%s\n' ${lib.escapeShellArg envFile} > env

    cd ..

    # ---- the archives ---------------------------------------------------
    # Reproducibility lives here, and it is not free. PCR0 and PCR1 are
    # digests of exactly these bytes, so anything the archive records that
    # varies between builds changes the measurement an enclave attests to.
    #
    # The `newc` header carries four such things, and all four had to be
    # pinned. Without `--reproducible` the *bootstrap* ramdisk came out
    # different every build even though its two input files never change,
    # because cpio stores each file's inode and device numbers and those are
    # whatever the filesystem handed out that time:
    #
    #   inode, device   --reproducible (renumbers inodes, drops devno)
    #   mtime           touch -d @1; store paths are already epoch+1
    #   uid, gid        --owner=0:0
    #   member order    find | LC_ALL=C sort, which also keeps parent
    #                   directories ahead of their contents
    archive() {
      local dir="$1" out="$2"
      find "$dir" -mindepth 1 -exec touch -h -d @1 {} +
      ( cd "$dir" && find . -mindepth 1 -printf '%P\0' | LC_ALL=C sort -z \
          | cpio --null -o -H newc --quiet --reproducible --owner=0:0 ) > "$out"
    }

    archive rd1 ramdisk1.cpio
    archive rd2 ramdisk2.cpio

    # ---- the image ------------------------------------------------------
    # `faketime` freezes the clock, because eif_build stamps wall-clock
    # `BuildTime` into the image's metadata. Without it two builds of identical
    # inputs differ by exactly 15 bytes: the 13-digit timestamp and the 4-byte
    # header CRC it changes.
    #
    # Those bytes are in metadata, which no PCR covers, so the *measurements*
    # were already reproducible without this. Freezing time makes the file
    # itself byte-identical too, which matters for the plainer reason that
    # people compare artifacts by hashing them, and because it lets
    # `nix build --rebuild` be a check that passes rather than a known
    # exception.
    faketime -f '@1970-01-01 00:00:01' \
    eif_build \
      --kernel ${blobs}/blobs/x86_64/bzImage \
      --kernel_config ${blobs}/blobs/x86_64/bzImage.config \
      --cmdline "$(cat ${blobs}/blobs/x86_64/cmdline)" \
      --ramdisk ramdisk1.cpio \
      --ramdisk ramdisk2.cpio \
      --output ${name}.eif \
      | tee eif_build.log

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    mkdir -p $out
    cp ${name}.eif $out/${name}.eif

    # eif_build prints the measurements as JSON after a header line. Keeping
    # them beside the image is what lets an operator compare a running
    # enclave's attested PCR0 against the build that claims to have produced
    # it — without that, a reproducible build proves nothing to anyone.
    sed -n '/^{/,/^}/p' eif_build.log > $out/pcr.json
    jq -e '.PCR0 | length == 96' $out/pcr.json > /dev/null \
      || { echo "eif_build did not report a PCR0; the image cannot be attested" >&2; exit 1; }

    echo "PCR0 $(jq -r .PCR0 $out/pcr.json)"

    runHook postInstall
  '';

  meta = {
    description = "AWS Nitro Enclave image for ${name}";
    platforms = [ "x86_64-linux" ];
  };
}
