# Tamizdat build and fleet versioning

Tamizdat uses one build identity for the server binary, panel and release
manifest. Database schema versions are separate and must not be used as an
application release version.

## Identity fields

- `version`: release line from `VERSION` or a Git tag in release CI.
- `build_id`: immutable deployment identifier, normally `<version>-<commit12>`.
- `commit`: full source commit.
- `build_time`: UTC/RFC3339 build timestamp.
- `dirty`: whether Go detected uncommitted source in a manual build.
- `sha256`: identity of the exact installed artifact.

`tamizdat-server-app --version` is human-readable and
`tamizdat-server-app --version-json` is the machine interface. A normal server
start logs the same identity before opening listeners.

The panel's authenticated `/api/panel` response contains `server_build` and
`panel_build`. When `/etc/tamizdat/build-info.json` is installed, each component
also reports `manifest_match`; `false` means a file was replaced outside the
recorded release bundle.

## Release policy

1. Merge and test on a clean commit. Never publish a binary from a dirty tree.
2. Update `VERSION` for the next release line.
3. Push the commit, then create/push a matching `v*` tag. Tags trigger the
   release workflow and therefore must be deliberate.
4. Deploy the generated architecture bundle, not loose files from different
   runs. The bundle carries `build-info.json` binding server, client and panel.
5. Verify `--version-json` and `manifest_match` after deployment.

The checked-in value may use a prerelease suffix such as `v0.2.0-dev.1`.
Production tags should use SemVer (`v0.2.0`, `v0.2.1`, and so on).

## Fleet audit

Run the read-only helper with the SSH aliases configured on the operator host:

```sh
scripts/fleet-versions.sh gateway ru2 sync2 router
```

New binaries return version/build/commit. Legacy binaries are still uniquely
reported as `sha256-<prefix>` so they can be compared before migration.

CCI-managed targets without an SSH alias should be checked through their
authenticated panel `/api/panel` response after a CCI deployment. They must not
be silently converted to manual SSH deployment just for inventory.
