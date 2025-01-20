{ buildGoModule, ... }:

buildGoModule {
  name = "saml2aws";
  version = "2.36.14-tencent";
  src = ./.;
  vendorHash = "sha256-pml6M45IJXfeOiMcPq8K88LxQFR/WmOzQXwGXHGOCew";
  env = {
    CGO_ENABLED = "0";
  };
  subPackages = [ "cmd/saml2aws" ];
}
