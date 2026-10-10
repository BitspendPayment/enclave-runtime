{
  description = "Reproducible AWS Nitro Enclave image (EIF) for the enclave runtime";

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

      # `cleanCargoSource` drops everything that is not Rust. One thing here
      # is not Rust and is not optional: `.pem`, the AWS Nitro root, embedded
      # by `include_str!`. Losing it fails deep in the build naming something
      # else entirely.
      srcFilter = path: type:
        # Guests are separate workspaces. Including their sources here changes
        # the runtime's store path (and its image's PCR0) on guest-only edits.
        !(lib.hasPrefix "${toString ./.}/examples/" (toString path)
          || toString path == "${toString ./.}/examples")
        && ((lib.hasSuffix ".pem" path)
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
        # The build directory, kept out of the binary. Rust embeds source paths
        # (panic locations, vendored crates) and C embeds `__FILE__`, and the
        # directory is /build under a sandboxed Nix but /tmp/nix-build-<name>-0
        # without one (nix-portable): the same inputs gave two PCR0s. Mapped to
        # one name, the image no longer says where it was built.
        preConfigure = ''
          export RUSTFLAGS="''${RUSTFLAGS:-} --remap-path-prefix=$NIX_BUILD_TOP=/build"
          export NIX_CFLAGS_COMPILE="''${NIX_CFLAGS_COMPILE:-} -ffile-prefix-map=$NIX_BUILD_TOP=/build"
        '';
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
      # `guest/guest.wasm` from the roots bucket at boot and measures it into
      # PCR16.
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

      # Tenant data is on ZFS: AWS's enclave kernel built from source, plus NBD
      # and dm-crypt, and the OpenZFS module built against it.
      kernelZfs = pkgs.callPackage ./nix/kernel-zfs.nix { };
      zfsModules = "${kernelZfs.zfsKmod}/lib/modules/${kernelZfs.kernel.modDirVersion}/extra";
      # What the runtime runs to bring the pool up: zpool and zfs, and dmsetup.
      zfsTools = [ kernelZfs.zfsUser pkgs.lvm2.bin ];

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
      # it — see deploy/nix/deployment.nix for why that has to be true. A
      # deployment kept elsewhere builds its image with `lib.mkEif`.
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

      runtimeImageFor = deployment: {
        name = "enclave";
        kernel = kernelZfs.dir;
        # No guest here. It is fetched from `guest/guest.wasm` in the roots
        # bucket at boot and measured into PCR16 — see `guest-release`.
        payload = {
          "enclave-runtime" = "${enclave-runtime}/bin/enclave-runtime";
          "usr/local/bin/gvforwarder" = "${gvproxy-static}/bin/gvforwarder";
          "lib/zfs/spl.ko" = "${zfsModules}/spl.ko";
          "lib/zfs/zfs.ko" = "${zfsModules}/zfs.ko";
        };
        closureRoots = [ enclave-runtime busybox pkgs.cacert ] ++ zfsTools;
        command = "/enclave-runtime";
        # Only what differs between deployments. Everything else — KMS, PTP, the
        # NSM, gvproxy, ACME on :443 — is a constant in the runtime, and the
        # emulator's alternatives exist only in its `testing` build.
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
          PATH = "${busybox}/bin:/usr/local/bin:${kernelZfs.zfsUser}/bin:${pkgs.lvm2.bin}/bin";
          # Push notifications, through an AWS End User Messaging Push
          # application. Empty means off. Only the application is named: its FCM
          # channel holds the Firebase credential, and the runtime signs as the
          # instance's role, so no image carries a secret.
          ENCLAVE_PUSH_APP_ID = deployment.pushAppId;
          # The instance's role, for the runtime alone: gvproxy maps this one
          # address to the metadata service, which a guest cannot reach at any
          # address (`serve::egress` refuses the whole proxy network). `AWS_*`
          # never reaches a guest either.
          AWS_EC2_METADATA_SERVICE_ENDPOINT = "http://192.168.127.253";

          # The store this image is for. Attested, because a receipt only
          # means "no pool here" if the host cannot choose "here".
          ENCLAVE_ROOTS_BUCKET = deployment.rootsBucket;
          ENCLAVE_BUCKET_PREFIX = deployment.bucketPrefix;
          ENCLAVE_ID = deployment.fsId;
          AWS_REGION = deployment.region;
          # ACME, which a platform authenticator needs: it will not attest
          # against a certificate a browser does not trust.
          ENCLAVE_TLS_DOMAINS = lib.concatStringsSep "," deployment.tlsDomains;

          # The master secret is minted by KMS inside the enclave and released
          # only against an attestation whose PCR0 and PCR16 match the key
          # policy. A wrong image or a wrong guest does not get a refused
          # mount — it gets no key at all. The key and the parameter come from
          # the deployment, since they name resources this repository does not
          # own.
          ENCLAVE_KMS_KEY_ID = deployment.kmsKeyId;
          ENCLAVE_MASTER_KEY_PARAMETER = deployment.masterKeyParameter;

          # How long root records are locked — the rollback guarantee's horizon,
          # and how long the roots bucket outlives the deployment.
          ENCLAVE_ROOT_RETENTION_SECS = toString deployment.rootRetentionSecs;

          # Guest stdout and stderr go to CloudWatch as well as the console.
          # The enclave calls PutLogEvents itself, over the same path it uses
          # for S3 and KMS, so TLS terminates inside and the parent carries
          # ciphertext. The group and its `guest` stream are created by
          # Terraform; this runtime holds `logs:PutLogEvents` and cannot make
          # them.
          ENCLAVE_GUEST_LOG_GROUP = deployment.guestLogGroup;

          # Every request that could reach the guest needs a fresh WebAuthn
          # assertion bound to exactly that request. Without an RP id the
          # runtime serves the guest to anyone who can open a connection and
          # says so at startup — which is a development arrangement, not this
          # one. The domain must be the one the app's passkeys are scoped to,
          # and it must be browser-trusted, hence ACME rather than self-signed.
          ENCLAVE_WEBAUTHN_RP_ID = deployment.rpId;
          ENCLAVE_WEBAUTHN_ALLOWED_ORIGINS = lib.concatStringsSep "," deployment.webauthnAllowedOrigins;
          #
          # Registration is open: anyone who can reach the port may create a
          # tenant of their own. There is nothing to provision, and nothing an
          # image could leak by carrying it.
        };
      };

      runtimeImage = runtimeImageFor deployment;

      # The production image for a deployment kept outside this repository —
      # a file in deployment.nix's shape:
      #
      #   packages.x86_64-linux.eif = enclave-runtime.lib.x86_64-linux.mkEif (import ./deployment.nix);
      #
      # The result is `enclave.eif` and `pcr.json`, as `packages.eif`.
      mkEif = deployment: callEif (runtimeImageFor deployment);

      # The runtime configured for the emulator, as a function of the relying
      # party so a client developer can boot one their app can sign for:
      #
      #   nix build --impure --expr '(builtins.getFlake "git+file://$PWD").lib.x86_64-linux.eifQemu
      #     { rpId = "example.com"; allowedOrigins = [ "android:apk-key-hash:..." ]; }'
      #
      # which is what `dev-enclave.sh --rp-id --allowed-origin` does. The
      # defaults are `packages.eif-qemu`, the image the e2e boots.
      eifQemu = {
        rpId ? "enclave.test",
        allowedOrigins ? [ ],
        # The certificate. The defaults are Pebble on the harness host, for `enclave.test`. An emulator
        # on a public host passes its real name and a real CA instead — `dev-enclave.sh --domain` —
        # with `acmeCa = null`, since a public CA's API needs no trust root shipped in the image.
        tlsDomains ? [ "enclave.test" ],
        acmeDirectory ? "https://192.168.127.254:14000/dir",
        acmeCa ? "/pebble-ca.pem",
        acmeContacts ? [ ],
        # Real notifications: the AWS End User Messaging Push application to send through, signed as
        # the host's instance role (gvproxy maps `.253` to its metadata service). Null keeps the
        # stub on the host. Not a secret: the application's FCM channel holds the credential.
        pushAppId ? null,
      }: callEif (runtimeImage // {
        payload = runtimeImage.payload // {
          "enclave-runtime" = "${enclave-runtime-testing}/bin/enclave-runtime";
          # Pebble's ACME API is served under a certificate no public root
          # signed, so its root ships *inside* the image and is covered by
          # PCR0 like every other piece of configuration. A test root in a
          # test image: the production EIF has no such file, and the
          # production binary has no flag that would read one.
          "pebble-ca.pem" = ./deploy/qemu-nitro/pebble/ca.pem;
        };
        closureRoots = [ enclave-runtime-testing busybox pkgs.cacert ] ++ zfsTools;
        name = "enclave-qemu";
        # The key settings go: this image keeps the static key below, and the
        # runtime refuses one alongside KMS settings rather than pick between them.
        env = builtins.removeAttrs runtimeImage.env [
          "ENCLAVE_KMS_KEY_ID"
          "ENCLAVE_MASTER_KEY_PARAMETER"
        ] // {
          ENCLAVE_CLOCK_SOURCE = "host";

          # QEMU's NSM does not sign at all: its source says "we don't
          # actually sign the data, so we use -1 as the 'alg' value", and -1
          # is not a COSE algorithm. A client meeting one of its documents has
          # to skip the signature, the chain and the validity windows — most
          # of what a client does, and precisely the part worth exercising
          # before it meets hardware.
          #
          # So the runtime re-signs what the device produced, contents
          # untouched, with a chain it mints at boot. It says nothing about
          # *who* produced a document — the key is inside an image its
          # operator controls — but it means the client code developed against
          # the emulator is the code that runs against Nitro, rather than a
          # relaxed variant of it. The root is reported on the console at
          # startup; `deploy/qemu-nitro/lib.sh` captures it for the clients.
          #
          # Testing-only, like `ENCLAVE_ACME_CA`: the production binary has no
          # such flag, so no deployment can sign its own attestations.
          ENCLAVE_COSIGN_ATTESTATIONS = "1";

          # And receipts stay content-checked, because that chain is minted
          # fresh at every boot. A receipt signed at genesis names a root the
          # next boot no longer has, so requiring a signature here would turn
          # every restart into a refusal to resume. Contents are still
          # verified — PCR0, PCR16 and the state_root — which is the whole
          # boot machine minus the one part that needs real hardware.
          ENCLAVE_RECEIPT_TRUST = "unsigned-emulator";
          # And it cannot use KMS at all, for the same reason: KMS verifies
          # the attestation document carrying the enclave's recipient public
          # key, and will not accept one that is unsigned. So the emulator
          # keeps the development key source. PCR0 differs between the two
          # images, so a client can tell which it is talking to.
          ENCLAVE_MASTER_KEY_SOURCE = "static";
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
          ENCLAVE_TLS_DOMAINS = nixpkgs.lib.concatStringsSep "," tlsDomains;
          ENCLAVE_ACME_DIRECTORY = acmeDirectory;
          # Notifications, against a stub on the host rather than AWS — which
          # would refuse an invented registration token anyway. What the e2e
          # checks is what the *runtime* sends, and the stub records exactly
          # that. The `http://` endpoint is the same downgrade
          # `--guest-log-endpoint` already is, and PCR0 records it. A real
          # application replaces both below.
          ENCLAVE_PUSH_APP_ID = "e2e";
          # Off. Inherited from the production image, and there is no AWS
          # here to send to: the harness's credentials are MinIO's, which
          # CloudWatch would reject. Empty means off, which is why
          # `guest_log_config` treats an empty setting as unset rather than as
          # a typo.
          ENCLAVE_GUEST_LOG_GROUP = "";
          # The gate, with a relying party the harness can drive. The e2e
          # exercises it with the software passkey the `testing` feature
          # provides, so the default is a name nothing else answers to.
          #
          # A developer testing a phone app against this passes their own: a
          # platform authenticator creates a passkey only for an rp id whose
          # domain publishes assetlinks.json naming the app, and the app claims
          # `android:apk-key-hash:<hash>` rather than the web origin. The rp id
          # is independent of the certificate's name, which stays enclave.test.
          ENCLAVE_WEBAUTHN_RP_ID = rpId;
          ENCLAVE_ENDPOINT = "http://192.168.127.254:9000";
          ENCLAVE_FORCE_PATH_STYLE = "1";
          ENCLAVE_ROOTS_BUCKET = "e2e-roots";
          ENCLAVE_MASTER_KEY = "00000000000000000000000000000000000000000000000000000000000000ab";
          AWS_ACCESS_KEY_ID = "minioadmin";
          AWS_SECRET_ACCESS_KEY = "minioadmin";
          AWS_REGION = "us-east-1";
          RUST_LOG = "info";
        } // nixpkgs.lib.optionalAttrs (acmeCa != null) {
          ENCLAVE_ACME_CA = acmeCa;
        } // nixpkgs.lib.optionalAttrs (acmeContacts != [ ]) {
          ENCLAVE_ACME_CONTACTS = nixpkgs.lib.concatStringsSep "," acmeContacts;
        } // nixpkgs.lib.optionalAttrs (pushAppId == null) {
          ENCLAVE_PUSH_ENDPOINT = "http://192.168.127.254:9180";
        } // nixpkgs.lib.optionalAttrs (pushAppId != null) {
          ENCLAVE_PUSH_APP_ID = pushAppId;
        } // nixpkgs.lib.optionalAttrs (allowedOrigins != [ ]) {
          ENCLAVE_WEBAUTHN_ALLOWED_ORIGINS = nixpkgs.lib.concatStringsSep "," allowedOrigins;
        };
      });

    in
    {
      lib.${system} = { inherit eifQemu mkEif; };

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
        # the guest: the e2e uploads `guest-release` to MinIO, at
        # `guest/guest.wasm`, and the enclave measures it there.
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
        eif-qemu = eifQemu { };

        # The entropy harness's image: no closure, no network, nothing but the
        # device check.
        eif-selftest = callEif {
          name = "selftest";
          payload = { "nsm-selftest" = "${nsm-selftest}/bin/nsm-selftest"; };
          command = "/nsm-selftest";
          env = { };
          withClosure = false;
        };

        # The same self-test on the kernel built from source, to show it boots,
        # reaches init's heartbeat over vsock and loads its own nsm.ko.
        eif-selftest-zfskernel = callEif {
          name = "selftest";
          payload = { "nsm-selftest" = "${nsm-selftest}/bin/nsm-selftest"; };
          command = "/nsm-selftest";
          env = { };
          withClosure = false;
          kernel = kernelZfs.dir;
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
