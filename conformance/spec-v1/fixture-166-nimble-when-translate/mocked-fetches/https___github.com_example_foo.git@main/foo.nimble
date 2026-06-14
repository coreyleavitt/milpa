# Package
version = "1.0.0"
author = "example"
description = "foo"
license = "MIT"
srcDir = "src"

# Deps
when defined(linux):
  requires "https://github.com/example/extra.git#v1.0.0"
