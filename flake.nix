{
  description = "Reproducible AWS Nitro Enclave image (EIF) for the s3fs enclave runtime";

  # Why this exists at all: PCR0 is a digest of the enclave image, and a KMS key
  # policy pins it while a client checks it. That number is only worth anything
  # if someone else can rebuild the image and get the same one. The Dockerfile
  # this replaces ran `apt-get update` on `debian:bookworm-slim`, so it produced
  # a different PCR0 every week and attested to nothing reproducible.
  #
  # Only the *enclave* is built here. The parent instance is built with Packer,
  # because the parent is the party the enclave excludes — nothing it contains
  # is attested, so reproducing it buys no security property.

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    # nixpkgs' rustPlatform ships std for the host only. The guest component
    # targets wasm32-wasip2, so the toolchain has to come from somewhere that
    # can add targets.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    crane.url = "github:ipetkov/crane";
  };

  outputs = { self, nixpkgs, rust-overlay, crane }:
    let
      # An EIF is x86_64 only. Nothing here is meant to build elsewhere, and
      # pretending otherwise would just produce a confusing failure.
      system = "x86_64-linux";

      pkgs = import nixpkgs {
        inherit system;
        overlays = [ (import rust-overlay) ];
      };

      inherit (pkgs) lib;

      # Honours rust-toolchain.toml, plus the wasm target for the guest.
      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        targets = [ "wasm32-wasip2" "x86_64-unknown-linux-musl" ];
      };
      craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

      # `cleanCargoSource` drops everything that is not Rust. Two things here
      # are not Rust and are not optional:
      #
      #   .pem   the AWS Nitro root, embedded by `include_str!`
      #   .wit   the vendored WASI interfaces, read from disk by `bindgen!`
      #
      # Losing either fails deep in the build naming something else entirely —
      # the WIT one surfaces as `could not find 'wasi' in 'bindings'`.
      srcFilter = path: type:
        (lib.hasSuffix ".pem" path)
        || (lib.hasSuffix ".wit" path)
        || (craneLib.filterCargoSources path type);

      workspaceSrc = lib.cleanSourceWith {
        src = ./.;
        filter = srcFilter;
        name = "source";
      };

      # aws-lc-sys compiles a bundled C library; blake3 and friends want a C
      # compiler too. This is the usual place a Rust-in-Nix build stops.
      nativeArgs = {
        strictDeps = true;
        nativeBuildInputs = with pkgs; [ cmake pkg-config perl ];
        # aws-lc-sys drives cmake itself; letting Nix's cmake hook configure
        # the crate's own build tree makes it fail confusingly.
        dontUseCmakeConfigure = true;
      };

      # ---- the runtime -----------------------------------------------------
      runtimeArgs = nativeArgs // {
        pname = "enclave-runtime";
        version = "0.1.0";
        src = workspaceSrc;
        # `--bin` so crane builds the binary rather than also the library's
        # test targets. The crate has no features to select: it is one crate
        # with one shape.
        cargoExtraArgs = "--locked -p enclave-runtime --bin enclave-runtime";
        # The workspace has integration tests needing a built wasm guest and a
        # running MinIO. `nix flake check` runs the unit tests instead.
        doCheck = false;
      };

      runtimeDeps = craneLib.buildDepsOnly runtimeArgs;
      enclave-runtime = craneLib.buildPackage (runtimeArgs // {
        cargoArtifacts = runtimeDeps;
      });

      # ---- the verifier ----------------------------------------------------
      # A client-side tool, built from the same tree so it cannot drift from
      # the runtime it checks.
      attestArgs = nativeArgs // {
        pname = "nitro-attest";
        version = "0.1.0";
        src = workspaceSrc;
        cargoExtraArgs = "--locked -p nitro-attestation --features cli";
        doCheck = false;
      };

      nitro-attest = craneLib.buildPackage (attestArgs // {
        cargoArtifacts = craneLib.buildDepsOnly attestArgs;
      });

      # ---- the guest -------------------------------------------------------
      # A separate workspace with its own lock file, and a different target, so
      # it cannot share the runtime's dependency layer.
      guestArgs = {
        pname = "guest-http";
        version = "0.1.0";
        src = craneLib.cleanCargoSource ./examples/guest-http;
        strictDeps = true;
        CARGO_BUILD_TARGET = "wasm32-wasip2";
        cargoExtraArgs = "--locked";
        doCheck = false;
      };

      guestDeps = craneLib.buildDepsOnly guestArgs;
      guest-http = craneLib.buildPackage (guestArgs // {
        cargoArtifacts = guestDeps;
      });

      # ---- the self-test payload -------------------------------------------
      # Static musl, so the entropy harness keeps its tiny ramdisk with no
      # closure at all. It only uses rustix, anyhow and ciborium, which is why
      # this one can be static where the runtime cannot.
      selftestArgs = {
        pname = "nsm-selftest";
        version = "0.1.0";
        src = workspaceSrc;
        strictDeps = true;
        CARGO_BUILD_TARGET = "x86_64-unknown-linux-musl";
        CARGO_BUILD_RUSTFLAGS = "-C target-feature=+crt-static";
        cargoExtraArgs = "--locked -p nitro-nsm --bin nsm-selftest";
        doCheck = false;
      };

      nsm-selftest = craneLib.buildPackage (selftestArgs // {
        cargoArtifacts = craneLib.buildDepsOnly selftestArgs;
      });

      # ---- eif_build -------------------------------------------------------
      eif-build = pkgs.rustPlatform.buildRustPackage rec {
        pname = "eif_build";
        version = "0.6.0";

        src = pkgs.fetchFromGitHub {
          owner = "aws";
          repo = "aws-nitro-enclaves-image-format";
          rev = "v${version}";
          hash = "sha256-d70XEPRY/dCgYJOCOImpOFuwNGcTxBj6FTA17Rp9l20=";
        };

        # Upstream gitignores its lock file, so one is kept here. That is not
        # a workaround: eif_build is the tool that *computes PCR0*, and letting
        # its dependency set float would mean the measurement was produced by
        # something slightly different each time.
        postPatch = "cp ${./deploy/nix/eif_build-Cargo.lock} Cargo.lock";
        cargoLock.lockFile = ./deploy/nix/eif_build-Cargo.lock;
        cargoBuildFlags = [ "-p" "eif_build" ];
        doCheck = false;

        # openssl-sys, for the EIF's signing support.
        nativeBuildInputs = [ pkgs.pkg-config ];
        buildInputs = [ pkgs.openssl ];

        meta.description = "Assembles an Enclave Image Format file";
      };

      # ---- AWS's enclave kernel and bootstrap ------------------------------
      # The kernel, its config, the cmdline, `init` and the NSM driver. Pinned
      # by hash so every build uses identical bytes.
      #
      # These are prebuilt binaries whose provenance is taken on trust — the
      # one opaque input to PCR0. AWS publishes aws-nitro-enclaves-sdk-bootstrap,
      # which builds them from source with nixpkgs; moving to it would close
      # that gap at the cost of a kernel compile.
      blobs = pkgs.fetchFromGitHub {
        owner = "aws";
        repo = "aws-nitro-enclaves-cli";
        rev = "v1.4.5";
        hash = "sha256-pdTbmsf7Kj7uF2g8zN6ur8gBJWOEkpb9YOLc2v0xnxQ=";
        sparseCheckout = [ "blobs/x86_64" ];
      };

      gvproxy-static = pkgs.gvproxy.overrideAttrs (old: {
        env = (old.env or { }) // { CGO_ENABLED = "0"; };
      });

      callEif = pkgs.callPackage ./nix/eif.nix {
        inherit blobs eif-build;
      };

      # gvforwarder brings the tap device up and then shells out to a DHCP
      # client for its address — `udhcpc` if present, otherwise `dhclient`.
      # Neither is in the runtime's closure, and the symptom is a forwarder
      # that connects to gvproxy, is disconnected immediately, and retries
      # forever while the gateway never answers. The cause is only visible if
      # the child's stderr is not discarded, which is why it now isn't.
      #
      # busybox supplies udhcpc and the applets its lease script needs, as one
      # static binary. Hand-rolling netlink instead would save ~1 MB and cost a
      # reimplementation of the part of gvforwarder that already works.
      #
      # It goes in as a whole store path rather than a copied binary, because
      # udhcpc does not configure the interface itself — it execs a lease
      # script, and nixpkgs patches busybox to look for that script *inside its
      # own store path*. Copy out just `bin/busybox` and the client obtains a
      # perfectly good lease and then applies none of it, silently. Shipping
      # the closure makes the script, its `#!` line and the applets it calls
      # all resolve, and needs no hand-written replacement.
      busybox = pkgs.pkgsStatic.busybox;

      # Which store the production image belongs to. Baked in, so PCR0 covers
      # it — see deploy/nix/deployment.nix for why that has to be true.
      deployment = import ./deploy/nix/deployment.nix;

      # What both the production and emulator images are made of. Only the
      # environment differs between them.
      runtimeImage = {
        name = "s3fs";
        payload = {
          "enclave-runtime" = "${enclave-runtime}/bin/enclave-runtime";
          "guest.wasm" = "${guest-http}/bin/guest-http.wasm";
          "usr/local/bin/gvforwarder" = "${gvproxy-static}/bin/gvforwarder";
        };
        closureRoots = [ enclave-runtime busybox pkgs.cacert ];
        command = "/enclave-runtime";
        env = {
          # Without a trust store the AWS SDK panics with "no CA certificates
          # found" before it makes a single request — including against a
          # plaintext endpoint, since the check happens when the client is
          # built rather than when it connects.
          #
          # This is the enclave's *own* trust store, shipped inside the image
          # and covered by PCR0. It is what makes "the parent cannot redirect
          # us" true: the parent answers DNS, so the only thing stopping it
          # pointing S3 at itself is that the certificate would not validate
          # against these roots.
          SSL_CERT_FILE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
          # gvforwarder finds its DHCP client with exec.LookPath, so busybox's
          # own bin directory goes on PATH — no symlinks, and the lease script
          # it execs resolves through the same closure.
          PATH = "${busybox}/bin:/usr/local/bin";
          S3FS_GUEST_PATH = "/guest.wasm";
          S3FS_MODE = "serve";
          S3FS_HTTP_LISTEN = "0.0.0.0:443";
          S3FS_TLS = "self-signed";
          S3FS_NETWORK = "gvproxy";
          S3FS_GVFORWARDER = "/usr/local/bin/gvforwarder";
          S3FS_RANDOM_SOURCE = "nsm";
          S3FS_CLOCK_SOURCE = "ptp";

          # The store this image is for. Attested, because a receipt only
          # means "no filesystem here" if the host cannot choose "here".
          S3FS_BUCKET = deployment.dataBucket;
          S3FS_ROOTS_BUCKET = deployment.rootsBucket;
          S3FS_BUCKET_PREFIX = deployment.bucketPrefix;
          S3FS_ID = deployment.fsId;
          AWS_REGION = deployment.region;
          S3FS_TLS_DOMAINS = lib.concatStringsSep "," deployment.tlsDomains;

          # A production image demands a receipt signed by AWS. The emulator
          # image overrides this, and because the environment is measured,
          # PCR0 tells a client which kind it is talking to.
          S3FS_RECEIPT_TRUST = "required";
        };
      };

    in
    {
      packages.${system} = {
        inherit enclave-runtime guest-http nsm-selftest nitro-attest eif-build blobs;

        # Both ends of the vsock from one package: `make build` emits gvproxy
        # for the parent and gvforwarder for the enclave, so they cannot drift.
        #
        # Built with CGO disabled, which upstream already does for gvforwarder
        # but not for gvproxy. Nix's gvproxy is dynamically linked against a
        # glibc in the store, so it runs nowhere that lacks that exact store
        # path — not on this host outside a Nix namespace, and not on the
        # Amazon Linux parent the AMI bakes. Static, it is one file that runs
        # anywhere, which is what a binary crossing out of Nix needs to be.
        gvproxy = gvproxy-static;

        # The production image.
        eif = callEif runtimeImage;

        # The same runtime and guest, configured for the emulator.
        #
        # A different image, and therefore a *different PCR0* — which is the
        # honest outcome: an enclave image is its configuration as much as its
        # code, and two configurations cannot share a measurement. The e2e
        # proves the machinery, not that production's exact bytes booted.
        #
        # Two things have to differ. QEMU's nitro-enclave machine has no PTP
        # device, so the trusted clock falls back to the system one. And the
        # store is MinIO on the host, reachable at gvproxy's host address.
        # The credentials here are test values in a test image; nothing that
        # matters is protected by them.
        eif-qemu = callEif (runtimeImage // {
          name = "s3fs-qemu";
          env = runtimeImage.env // {
            S3FS_CLOCK_SOURCE = "host";
            # QEMU's NSM does not sign attestation documents, so a receipt it
            # produced has no signature to check. Contents are still verified —
            # PCR0, PCR31 and the state_root — which is the whole boot machine
            # minus the one part that needs real hardware.
            S3FS_RECEIPT_TRUST = "unsigned-emulator";
            S3FS_ENDPOINT = "http://192.168.127.254:9000";
            S3FS_FORCE_PATH_STYLE = "1";
            S3FS_BUCKET = "e2e-data";
            S3FS_ROOTS_BUCKET = "e2e-roots";
            S3FS_MASTER_KEY = "00000000000000000000000000000000000000000000000000000000000000ab";
            AWS_ACCESS_KEY_ID = "minioadmin";
            AWS_SECRET_ACCESS_KEY = "minioadmin";
            AWS_REGION = "us-east-1";
            RUST_LOG = "info,s3fs=debug";
          };
        });

        # The entropy harness's image: no closure, no network, nothing but the
        # device check.
        eif-selftest = callEif {
          name = "selftest";
          payload = { "nsm-selftest" = "${nsm-selftest}/bin/nsm-selftest"; };
          command = "/nsm-selftest";
          env = { };
          withClosure = false;
        };

        default = self.packages.${system}.eif;
      };

      devShells.${system}.default = pkgs.mkShell {
        inputsFrom = [ enclave-runtime ];
        packages = with pkgs; [
          rustToolchain
          cmake
          pkg-config
          gvproxy
          cpio
          jq
          eif-build
          opentofu
          packer
        ];
      };

      checks.${system} = {
        inherit enclave-runtime guest-http nsm-selftest;

        workspace-tests = craneLib.cargoTest (runtimeArgs // {
          cargoArtifacts = runtimeDeps;
          cargoTestExtraArgs = "--workspace --lib";
          doCheck = true;
        });
      };

      formatter.${system} = pkgs.nixpkgs-fmt;
    };
}
