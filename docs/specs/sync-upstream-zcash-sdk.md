# Sync Fork With Upstream Zcash SDK

## Goal

Update the Horizontal Systems fork from the current parent repository state while preserving the existing fork commits that downstream applications rely on.

Current fork base:

- `origin/master`: `f186d017a2d33d50f0276c10adf8b544484acfe6`
- Local integration branch: `master`
- Parent repository: `zcash/zcash-swift-wallet-sdk`
- Parent integration branch: `main`
- Current fetched parent tip: `b3675ba9ecadd2b777f21d8b770e88cba294d26e`

## Assumptions

- Existing apps that must keep building are pinned to commit `f186d017a2d33d50f0276c10adf8b544484acfe6`, not to the moving `master` branch name.
- The fork-specific behavior to preserve is represented by these commits on top of the parent history:
  - `025d010c Add public methods for estimate birthday heights/time`
  - `f186d017 Change bool flag to values.`
- Updating the fork should preserve those commits in repository history instead of replacing `master` with the parent branch tip.
- The upstream source of truth is the GitHub parent repository `zcash/zcash-swift-wallet-sdk`, default branch `main`.

## Scope

- Bring the fork up to the current `upstream/main` contents.
- Preserve the fork-specific static birthday estimation API changes and the `f186d017` behavior.
- Resolve any merge conflicts caused by upstream changes.
- Keep generated or vendored files aligned with upstream unless a fork-specific change is required.
- Update tests only where needed to keep preserved fork behavior covered.

## Affected Areas

- Swift package manifest and build support files.
- `Sources/ZcashLightClientKit` public API and implementation files.
- Tests covering checkpoint birthday estimation and any upstream behavior affected by conflict resolution.
- Generated protobuf/FFI-related files if upstream changed them.
- Documentation only if upstream merge conflicts require it.

## Proposed Implementation

1. Work from this branch, which starts at `origin/master`.
2. Merge the fetched parent branch `upstream/main` into the fork branch rather than resetting to it.
3. Resolve conflicts by preferring upstream for general SDK changes and preserving fork-specific static birthday estimation methods and `f186d017` behavior.
4. Verify that `f186d017a2d33d50f0276c10adf8b544484acfe6` remains reachable from the updated branch history.
5. Run focused tests first, then broader package verification if dependencies and local environment allow it.

## Acceptance Criteria

- The updated branch contains the latest fetched upstream commit `b3675ba9ecadd2b777f21d8b770e88cba294d26e`.
- Commit `f186d017a2d33d50f0276c10adf8b544484acfe6` remains reachable in history.
- Fork-specific public/static birthday estimation methods remain available.
- The project builds for the supported local Swift/Xcode configuration.
- Relevant tests pass, or any blocked tests are reported with exact commands and failure reasons.
- No unrelated cleanup, formatting churn, or tool-generated local directories are committed.

## Verification Plan

- `git merge-base --is-ancestor f186d017a2d33d50f0276c10adf8b544484acfe6 HEAD`
- `git merge-base --is-ancestor b3675ba9ecadd2b777f21d8b770e88cba294d26e HEAD`
- Search for and inspect the preserved static birthday estimation API.
- Run package or project build command appropriate for the updated upstream state.
- Run focused tests around birthday estimation/checkpoints.
- Run broader test suite if it is practical in the local environment.

## Open Questions

- Should the updated fork target upstream `main` exactly at `b3675ba9ecadd2b777f21d8b770e88cba294d26e`, or should it target a release branch/tag such as `2.6.0-alpha.1` or `release/2.6.0`?
- After review, should the implementation branch be merged back into fork `master`, or should it be published as a separate branch first for app integration testing?
