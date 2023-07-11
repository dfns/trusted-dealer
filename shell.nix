let pkgs = import <nixpkgs> {};

in pkgs.stdenv.mkDerivation {
  name = "signers-env";
  buildInputs = [
    pkgs.gmp
    pkgs.iconv
    pkgs.darwin.apple_sdk.frameworks.Security
  ];
}
