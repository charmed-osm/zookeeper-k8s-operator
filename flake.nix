{
  inputs.nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

  outputs = {
    self,
    nixpkgs,
  }: let
    pkgs = import nixpkgs {system = "x86_64-linux";};
    renovate = pkgs.writeShellScriptBin "renovate" ''
      node node_modules/renovate/dist/renovate.js
    '';
  in {
    devShells.x86_64-linux.default = pkgs.mkShell {
      packages = [
        pkgs.nodejs_20
        renovate
      ];

      shellHook = ''
        npm install renovate@latest
        export RENOVATE_CONFIG_FILE=./renovate.json5
        export LOG_LEVEL=debug
      '';
    };
  };
}
