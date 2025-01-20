{ buildGoModule, stdenv, darwin, ... }:

buildGoModule rec {
  name = "saml2aws";
  version = "2.36.14-tencent";
  src = ./.;

  buildInputs = [] ++ (if stdenv.hostPlatform.isDarwin then [
    darwin.apple_sdk.frameworks.AppKit
  ] else []);

  ldflags = [
    "-s"
    "-w"
    "-X main.Version=${version}"
  ];

  vendorHash = "sha256-pml6M45IJXfeOiMcPq8K88LxQFR/WmOzQXwGXHGOCew";
  subPackages = [ "cmd/saml2aws" ];
}
