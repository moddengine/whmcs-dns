{ pkgs ? import <nixpkgs> { } }:

let
  php = pkgs.php83.withExtensions ({ enabled, all }: enabled ++ [ all.xdebug ]);
in
pkgs.mkShell {
  packages = with pkgs; [
    php
    (php83Packages.composer.override { inherit php; })
    zip
  ];
}
