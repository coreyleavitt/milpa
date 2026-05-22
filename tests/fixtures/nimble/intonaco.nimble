# Package metadata for intonaco — the compile-time-first reactive
# systems substrate. Sibling to fresco (terminal frontend) and the
# planned sinopia (trace frontend). See ../fresco/docs/rfc-intonaco-
# fresco-split.md for the architectural framing.

version       = "0.1.0"
author        = "Corey Leavitt"
description   = "Compile-time-first reactive substrate for Nim — signals/scopes/supervision/journal/caps over a chronos contextvar substrate."
license       = "Apache-2.0"
srcDir        = "src"

requires "nim >= 2.0.0"

# Async runtime: chronos, pinned to our fork's `feat/contextvars`
# branch while the upstream PR (continuation-local storage primitive)
# is in review. intonaco's currentScope / currentSpeculative /
# parallelCollector are chronos contextVars; the substrate cannot
# work without this primitive.
requires "https://github.com/coreyleavitt/chronos.git#feat/contextvars"

# Tests will be added once the substrate gets standalone test
# coverage. Today intonaco's behavior is exercised through fresco's
# test suite; standalone tests are deferred until sinopia or another
# consumer needs intonaco-only verification.
