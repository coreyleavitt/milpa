# Package
version = "1.0.0"
author = "example"
description = "qux"
license = "MIT"
srcDir = "src"

# Deps
requires "bar >= 2.0.0"
when defined(linux):
  requires "extra >= 1.0.0"
