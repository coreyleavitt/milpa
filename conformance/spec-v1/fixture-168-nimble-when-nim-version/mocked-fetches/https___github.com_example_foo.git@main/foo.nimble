# Package
version = "1.0.0"
author = "example"
description = "foo"
license = "MIT"
srcDir = "src"

# Deps
when (NimMajor, NimMinor) >= (1, 4) and (NimMajor, NimMinor) < (2, 0):
  requires "https://github.com/example/nimcompat.git#v1.0.0"
