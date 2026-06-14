# Package
version = "1.0.0"
author = "example"
description = "foo"
license = "MIT"
srcDir = "src"

# Deps
when defined(linux):
  requires "https://github.com/example/extra_a.git#v1.0.0"
elif defined(macosx):
  requires "https://github.com/example/extra_b.git#v1.0.0"
else:
  requires "https://github.com/example/extra_c.git#v1.0.0"
