{
  description = "HeapSentinel off-game test toolchain. The plugin itself is a Windows SKSE DLL and builds on Windows (see .github/workflows/build.yml); this shell exists for src/Ipc's shared-memory IPC layer, which is plain C++ and is built and run on Linux too.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          # pkgs.gcc is the WRAPPED gcc. A bare g++ picked up from a Nix profile
          # cannot link here: it fails with "ld.bfd: cannot find Scrt1.o", which
          # looks like a missing library but is a wrapper problem.
          packages = [
            pkgs.xmake
            pkgs.gcc
            pkgs.binutils
            pkgs.git
          ];

          shellHook = ''
            echo "HeapSentinel test shell (Linux). Note the xmake argument order:"
            echo "  xmake f     -P tests -p linux -m release -y"
            echo "  xmake build -P tests -y"
            echo "  xmake run   -P tests"
            echo "The action must come BEFORE -P, or xmake walks up and configures the"
            echo "Windows-only plugin project instead of tests/."
          '';
        };
      });
    };
}
