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
        # Guests are separate workspaces. Including their sources here changes
        # the runtime's store path (and its image's PCR0) on guest-only edits.
        !(lib.hasPrefix "${toString ./.}/examples/" (toString path)
          || toString path == "${toString ./.}/examples")
        && ((lib.hasSuffix ".pem" path)
        || (lib.hasSuffix ".wit" path)
        || (craneLib.filterCargoSources path type));

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
        # OpenSSL, for `openssl-sys` under `webauthn-rs`. It is here reluctantly
        # and the reluctance is the point: this is a second crypto stack, with a
        # native library, entering the closure that PCR0 measures — alongside
        # aws-lc-rs, which already provides every primitive it is used for.
        #
        # It is also load-bearing rather than cosmetic. Without it the enclave
        # image does not build at all, which is how the cost first showed up:
        # a host cargo build succeeded against the system OpenSSL and the
        # reproducible build did not.
        buildInputs = [ pkgs.openssl ];
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
        # test targets.
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
        src = lib.cleanSourceWith {
          src = ./examples/guest-http;
          filter = path: type:
            lib.hasSuffix ".wit" path || craneLib.filterCargoSources path type;
          name = "guest-source";
        };
        strictDeps = true;
        CARGO_BUILD_TARGET = "wasm32-wasip2";
        cargoExtraArgs = "--locked";
        doCheck = false;
      };

      guestDeps = craneLib.buildDepsOnly guestArgs;
      guest-http = craneLib.buildPackage (guestArgs // {
        cargoArtifacts = guestDeps;
      });

      # What an operator uploads to the roots bucket, and the PCR16 a key policy
      # pins for it. The guest is not in the enclave image: the runtime fetches
      # `deployment.guestObject` at boot and measures it into PCR16.
      #
      # `guest-pcr16.json` comes from `nitro-attest --measure`, the function a
      # client verifies with, so the number in the policy and the number a
      # client checks cannot disagree.
      guest-release = pkgs.runCommand "guest-release"
        { nativeBuildInputs = [ nitro-attest pkgs.jq ]; }
        ''
          mkdir -p $out
          cp ${guest-http}/bin/guest-http.wasm $out/guest.wasm
          nitro-attest --measure $out/guest.wasm > $out/guest-pcr16.json
          jq -e '.PCR16 | length == 96' $out/guest-pcr16.json > /dev/null \
            || { echo "nitro-attest did not report a PCR16" >&2; exit 1; }
          echo "PCR16 $(jq -r .PCR16 $out/guest-pcr16.json)"
        '';

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
      # The same runtime, built with `testing`, for the QEMU emulator only.
      #
      # It exists for one reason: the emulator has no domain and no CA it can
      # reach, so it cannot obtain an ACME certificate — and the production
      # binary refuses to serve anything else. `testing` restores
      # `--tls self-signed` and, with it, `rcgen`.
      #
      # This is a **different binary with a different PCR0**, which is the point:
      # nothing here can be mistaken for the production image, and the e2e
      # asserts its PCR0 against its own build rather than a published one. The
      # production image contains no certificate generator at all.
      enclave-runtime-testing = craneLib.buildPackage (runtimeArgs // {
        pname = "enclave-runtime-testing";
        cargoArtifacts = runtimeDeps;
        cargoExtraArgs =
          "--locked -p enclave-runtime --bin enclave-runtime --features testing";
      });

      runtimeImage = {
        name = "s3fs";
        # No guest here. It is fetched from the store at boot and measured
        # into PCR16 — see `guest-release` and S3FS_GUEST_OBJECT below.
        payload = {
          "enclave-runtime" = "${enclave-runtime}/bin/enclave-runtime";
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
          # Where the guest comes from — not the guest, which is not in the
          # image. The runtime fetches this key from the roots bucket, extends
          # PCR16 with the object's hash and locks the register before it asks
          # KMS for a key. The location is measured here, by PCR0; what arrives
          # is measured there, by PCR16, so the object need not be trusted.
          S3FS_GUEST_OBJECT = deployment.guestObject;
          S3FS_BACKGROUND_TASKS = lib.boolToString deployment.backgroundTasks;
          S3FS_BACKGROUND_CONCURRENCY = toString deployment.backgroundConcurrency;
          S3FS_HTTP_LISTEN = "0.0.0.0:443";
          # ACME, not self-signed: a platform authenticator will not attest
          # against a certificate a browser does not trust, so a self-signed one
          # would mean no passkey could ever register.
          S3FS_TLS = "acme";
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

          # The master secret is minted by KMS inside the enclave and released
          # only against an attestation whose PCR0 and PCR16 match the key
          # policy. A wrong image or a wrong guest does not get a refused
          # mount — it gets no key at all.
          #
          # S3FS_MASTER_KEY is deliberately absent, and the runtime *refuses*
          # to start if it is set alongside this: a key from configuration is a
          # key the parent instance holds, which is the whole thing this
          # prevents. S3FS_KMS_KEY_ID and S3FS_MASTER_KEY_PARAMETER come from
          # the deployment, since they name resources this repository does not
          # own.
          S3FS_MASTER_KEY_SOURCE = "kms";

          # Guest stdout and stderr go to CloudWatch as well as the console.
          # The enclave calls PutLogEvents itself, over the same path it uses
          # for S3 and KMS, so TLS terminates inside and the parent carries
          # ciphertext. The group and stream are created by Terraform; this
          # runtime holds `logs:PutLogEvents` and cannot make them.
          S3FS_GUEST_LOG_GROUP = deployment.guestLogGroup;
          S3FS_GUEST_LOG_STREAM = deployment.guestLogStream;

          # Every request that could reach the guest needs a fresh WebAuthn
          # assertion bound to exactly that request. Without an RP id the
          # runtime serves the guest to anyone who can open a connection and
          # says so at startup — which is a development arrangement, not this
          # one. The domain must be the one the app's passkeys are scoped to,
          # and it must be browser-trusted, hence ACME rather than self-signed.
          S3FS_WEBAUTHN_RP_ID = deployment.rpId;
          S3FS_WEBAUTHN_ORIGIN = "https://" + deployment.rpId;
          #
          # Registration is open: anyone who can reach the port may create a
          # tenant of their own. There is nothing to provision, and nothing an
          # image could leak by carrying it.
        };
      };

    in
    {
      packages.${system} = {
        inherit enclave-runtime guest-http guest-release nsm-selftest nitro-attest eif-build blobs;

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

        # The same runtime, configured for the emulator. Neither image contains
        # the guest: the e2e uploads `guest-release` to MinIO, at the key
        # `deployment.guestObject` names, and the enclave measures it there.
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
          payload = runtimeImage.payload // {
            "enclave-runtime" = "${enclave-runtime-testing}/bin/enclave-runtime";
            # Pebble's ACME API is served under a certificate no public root
            # signed, so its root ships *inside* the image and is covered by
            # PCR0 like every other piece of configuration. A test root in a
            # test image: the production EIF has no such file, and the
            # production binary has no flag that would read one.
            "pebble-ca.pem" = ./deploy/qemu-nitro/pebble/ca.pem;
          };
          closureRoots = [ enclave-runtime-testing busybox pkgs.cacert ];
          name = "s3fs-qemu";
          env = runtimeImage.env // {
            S3FS_CLOCK_SOURCE = "host";
            # QEMU's NSM does not sign attestation documents, so a receipt it
            # produced has no signature to check. Contents are still verified —
            # PCR0, PCR16 and the state_root — which is the whole boot machine
            # minus the one part that needs real hardware.
            S3FS_RECEIPT_TRUST = "unsigned-emulator";
            # A directory per client, which the e2e exercises with two client
            # certificates. Concurrency has to rise with it or every client
            # still queues behind every other and the per-client locks buy
            # nothing.
            # And it cannot use KMS at all, for the same reason: KMS verifies
            # the attestation document carrying the enclave's recipient public
            # key, and will not accept one that is unsigned. So the emulator
            # keeps the development key source. PCR0 differs between the two
            # images, so a client can tell which it is talking to.
            S3FS_MASTER_KEY_SOURCE = "static";
            # Real ACME, against a Pebble running on the host — the same code
            # path production takes, which is the whole reason to prefer it.
            #
            # This image used to serve a self-signed certificate, because there
            # is no public domain here and nothing Let's Encrypt could reach, so
            # an order failed forever and stalled every handshake rather than
            # failing loudly. The consequence was worse than the workaround: the
            # e2e proved a TLS mode a production build cannot even parse. Pebble
            # removes the reason, so the mode went with it.
            #
            # `enclave.test` resolves, inside the Pebble container, to the host
            # loopback where gvproxy forwards :443 into this enclave — so the
            # TLS-ALPN-01 challenge arrives on the same port the service uses,
            # which is exactly the arrangement production runs.
            S3FS_TLS = "acme";
            S3FS_TLS_DOMAINS = "enclave.test";
            S3FS_ACME_DIRECTORY = "https://192.168.127.254:14000/dir";
            S3FS_ACME_CA = "/pebble-ca.pem";
            # The e2e schedules work and waits for it to run. Production leaves
            # this off in deployment.nix; turning it on here changes only the
            # emulator's PCR0, and the harness checks PCR0 against its own
            # `nix build` rather than against a published number, so nothing
            # downstream moves. The guest is guest-http, which exports the
            # `run-task` the runtime refuses to start without when this is set.
            S3FS_BACKGROUND_TASKS = "true";
            # Off. Inherited from the production image, and there is no AWS
            # here to send to: the harness's credentials are MinIO's, which
            # CloudWatch would reject. Empty means off — the same shape as the
            # TLS override above, and the reason `guest_log_config` treats an
            # empty setting as unset rather than as a typo.
            S3FS_GUEST_LOG_GROUP = "";
            S3FS_GUEST_LOG_STREAM = "";
            # The gate, with a relying party the harness can drive. A platform
            # authenticator would refuse this self-signed certificate, so the
            # e2e exercises the gate with the software passkey the `testing`
            # feature provides rather than a real one.
            S3FS_WEBAUTHN_RP_ID = "enclave.test";
            S3FS_WEBAUTHN_ORIGIN = "https://enclave.test";
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
