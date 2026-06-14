# Package
version = "1.0.0"
author = "example"
description = "foo"
license = "MIT"
srcDir = "src"

# Deps
when defined(release):
  requires "https://github.com/example/relonly.git#v1.0.0"
