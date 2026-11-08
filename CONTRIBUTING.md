# Contributing

Use patched Go 1.26+. Run gofmt, go vet, tests/race tests and the README vulnerability check. Add behavior-oriented integration tests for changes and regression tests for fixes. Avoid production policy bypasses, disabled TLS verification or browsing-history logs. Changes to authentication, address policy and tunnel lifecycle need threat-model review.

Keep dependencies minimal. Follow SECURITY.md for vulnerability reports. Contributions are provided under the repository's MIT license.
