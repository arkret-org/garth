# Tag releases

Pushing a `v*` tag builds and publishes a GitHub Release after every required
build succeeds. `workflow_dispatch` builds the same artifacts without publishing
a release; use it before tagging. Existing source versions are not changed.

Sibling checkout revisions in the workflow are part of the release source set.
Before tagging, update those pins to a compatible tested set and commit any
required Cargo.lock changes. Do not replace pinned revisions with `main`. Each
archive includes `build-info.json` with the source commits and lockfile hash,
and a companion SHA-256 file. Verify it from the download directory with
`sha256sum --check ./*.sha256`.

Cross-repository private dependencies require `CI_REPO_TOKEN` with read access;
`GITHUB_TOKEN` only supplies the current repository's permissions. Publishing
uses the release job's `contents: write` permission.

This runtime-neutral library publishes source packages, not executables.
The release workflow runs native-feature tests; ordinary CI covers Windows,
macOS, iOS, Android and WebAssembly. This workflow does not publish to crates.io:
the coordinated SDK dependency set must be published first.
