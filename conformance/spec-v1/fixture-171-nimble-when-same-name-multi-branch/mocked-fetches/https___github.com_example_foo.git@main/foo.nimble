# Package
version = "1.0.0"
author = "example"
description = "foo"
license = "MIT"
srcDir = "src"

# Deps
when defined(linux):
  requires "https://github.com/example/bar.git#v1.0.0"
when defined(macosx):
  requires "https://github.com/example/bar.git#v1.0.0"
