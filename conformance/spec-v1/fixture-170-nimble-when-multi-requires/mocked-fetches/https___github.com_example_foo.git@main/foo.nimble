# Package
version = "1.0.0"
author = "example"
description = "foo"
license = "MIT"
srcDir = "src"

# Deps
when defined(linux):
  requires "https://github.com/example/depx.git#v1.0.0"
  requires "https://github.com/example/depy.git#v1.0.0"
