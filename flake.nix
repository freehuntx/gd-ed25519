{
  description = "Development environment for the gd-ed25519 Godot GDExtension (built with SCons)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # MinGW-w64 cross toolchain for building Windows binaries on Linux.
        mingwBuild = pkgs.pkgsCross.mingwW64.buildPackages;
        mingwTarget = pkgs.pkgsCross.mingwW64;

        # Nix's mingw GCC is built against the mcfgthread threading library, so
        # its <mutex>/<thread> headers pull in <mcfgthread/gthr.h>. Those headers
        # and the static lib live in separate outputs that the gcc wrapper only
        # wires up via propagated target-target deps inside a proper stdenv build
        # -- not in a bare `mkShell`. On top of that, SCons sanitizes the
        # environment it passes to the compiler (only PATH is forwarded), so
        # env-var-based fixes don't reach the compiler either.
        #
        # We work around both problems by merging the cross gcc + binutils into
        # a single tree and overwriting the g++/gcc driver scripts with shims
        # that inject the needed include/lib paths. Linking -lbcrypt (needed by
        # src/csprng.c on Windows) is handled in SConstruct via
        # env.Append(LIBS=["bcrypt"]) for platform=windows, so the shim does
        # not need to add it.
        mcfgthreadsDev = mingwTarget.windows.mcfgthreads.dev;
        mcfgthreadsLib = mingwTarget.windows.mcfgthreads; # the `out` output, with libmcfgthread.a

        mingwWrapped = pkgs.symlinkJoin {
          name = "mingw-w64-wrapped-x86_64";
          paths = [ mingwBuild.gcc mingwBuild.binutils ];
          buildInputs = [ pkgs.buildPackages.makeWrapper ];
          postBuild = ''
            for driver in x86_64-w64-mingw32-g++ x86_64-w64-mingw32-gcc \
                          x86_64-w64-mingw32-c++ x86_64-w64-mingw32-cc; do
              rm -f "$out/bin/$driver"
              cat > "$out/bin/$driver" <<SH
            #!${pkgs.stdenv.shell}
            exec "${mingwBuild.gcc}/bin/$driver" \
              -isystem "${mcfgthreadsDev}/include" \
              -L "${mcfgthreadsLib}/lib" "\$@"
            SH
              chmod +x "$out/bin/$driver"
            done
          '';
        };
      in
      {
        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            # Build system
            scons
            python3

            # Native C/C++ toolchain (godot-cpp uses the gnu toolchain on Linux by default)
            gcc
            gnumake
            binutils

            # Windows cross-compiler (use: scons platform=windows arch=x86_64 ...)
            # Shims inject mcfgthreads headers/libs; -lbcrypt is added by SConstruct.
            mingwWrapped

            # Web/WASM compiler (use: scons platform=web arch=wasm32 ...)
            emscripten

            # Version control (needed for submodules)
            git

            # Code formatting
            llvmPackages_18.clang-tools

            # Godot editor for testing the extension in-project
            godot_4

            # Misc helpers
            which
            curl
            unzip
          ];

          shellHook = ''
            # Make SCons pick up the native toolchain from this shell.
            export CC="${pkgs.gcc}/bin/gcc"
            export CXX="${pkgs.gcc}/bin/g++"

            echo ""
            echo "🛠  gd-ed25519 dev shell"
            echo "   Linux:   scons platform=linux   arch=x86_64 target=template_debug"
            echo "   Windows: scons platform=windows arch=x86_64 target=template_debug"
            echo "   Web:     scons platform=web      arch=wasm32 target=template_debug"
            echo "   macOS:   requires building on macOS with Xcode installed"
            echo "   Release: scons platform=linux   arch=x86_64 target=template_release"
            echo ""
          '';
        };
      });
}
