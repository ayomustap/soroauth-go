{
  description = "soroauth — build, sign and inspect Soroban authorization entries";

  inputs = {
    # Pinned in flake.lock, not floating: `nix build` against a flake whose
    # inputs move is not reproducible. Update with `nix flake update`.
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      inherit (nixpkgs) lib;

      # The CLI's `--version` string.
      #
      # When the flake is fetched at a tag (for example
      # `nix build github:soroauth/soroauth-go/v0.1.0#`), Nix sets `self.ref`
      # to that tag and the released version is what the binary reports. For a
      # checkout or a branch there is no tag, so the committed default below is
      # used; the release workflow updates it on `main` after each release so a
      # `main` install still reports the newest version rather than `dev`.
      defaultVersion = import ./packaging/nix/release-version.nix;
      tag =
        let
          ref = self.ref or "";
        in
        if lib.hasPrefix "refs/tags/" ref then lib.removePrefix "refs/tags/" ref else null;
      version =
        let
          v = if tag == null then defaultVersion else tag;
        in
        lib.removePrefix "v" v;

      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      forAllSystems = f: lib.genAttrs systems (system: f system);

      # `go build` is told the same three values the Makefile and the release
      # workflow stamp, so a nix-built binary reports the tag, the commit and
      # the build time exactly as a released one does.
      ldflags = [
        "-s"
        "-w"
        "-X"
        "main.version=${version}"
        "-X"
        "main.commit=${self.shortRev or self.dirtyShortRev or "unknown"}"
        "-X"
        "main.date=${builtins.toString (self.lastModified or 0)}"
      ];

      mkSoroauth =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        pkgs.buildGoModule {
          pname = "soroauth";
          inherit version;

          # The whole repository, not a subdirectory: `go build ./cmd/soroauth`
          # resolves the module from the root go.mod.
          src = ./.;

          # The root module imports no wallet SDK and has no `replace`
          # directives; the nested modules under adapters/, integrations/ and
          # bindings/ are separate modules the go tool stops at, so they do not
          # enter the vendor tree.
          subPackages = [ "cmd/soroauth" ];

          inherit ldflags;

          # The CLI's completion tests run the generated scripts through real
          # shells. The sandbox's default bash is a non-interactive build
          # without programmable completion (`complete`/`compgen` are missing),
          # which the test needs; bashInteractive is the nixpkgs bash compiled
          # with it. It is put first on PATH for the check so the test finds
          # that bash rather than the stdenv one.
          nativeCheckInputs = [ pkgs.bashInteractive ];
          preCheck = ''
            export PATH="${lib.makeBinPath [ pkgs.bashInteractive ]}:$PATH"
          '';

          # Hash of the vendored dependency tree. It changes only when go.mod
          # or go.sum changes; `nix build` prints the correct value when this
          # one is stale, and it is committed here so a build never needs the
          # network beyond the pinned nixpkgs input.
          vendorHash = "sha256-aFpigj+nc+2w397iRZv2L7/0E5R8BjNDCrc1WGLS2d4=";

          meta = {
            description = "Build, sign and inspect Soroban authorization entries";
            homepage = "https://github.com/soroauth/soroauth-go";
            license = lib.licenses.asl20;
            mainProgram = "soroauth";
            platforms = systems;
          };
        };

      # `nix run`/`nix build` entry point, and the shell a contributor gets
      # from `nix develop`.
      mkApp = system: {
        type = "app";
        program = "${(mkSoroauth system)}/bin/soroauth";
      };

      mkDevShell =
        system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        pkgs.mkShell {
          packages = [
            pkgs.go
            pkgs.gopls
            pkgs.nodejs_22
            pkgs.prettier
          ];
        };
    in
    {
      packages = forAllSystems (system: rec {
        soroauth = mkSoroauth system;
        default = soroauth;
      });

      apps = forAllSystems (system: {
        default = mkApp system;
      });

      devShells = forAllSystems (system: {
        default = mkDevShell system;
      });

      # `nix flake check` builds the package on the host system, which is what
      # CI runs on Linux and macOS.
      checks = forAllSystems (system: {
        soroauth = self.packages.${system}.default;
      });
    };
}
