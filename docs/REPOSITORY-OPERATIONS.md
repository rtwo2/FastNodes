# Repository operations and branch protection

## Branch responsibilities

- `main` contains collector source, tests, scripts, documentation and workflows.
- `outputs` contains the generated `sub/` subscriptions and `state/` files used
  between collection runs. The collection workflow refreshes this branch with a
  force-with-lease update; it does not rewrite `main`.
- Public raw subscription URLs use `outputs`, not `main`.

The collector restores `sub/` and `state/` from `outputs` before a full run. It
validates the newly generated tree before publishing. The output branch should be
initialized before removing the checked-in snapshot from `main`.

## Recommended GitHub settings

These are repository settings, not files that a pull request can enforce. After the
output-branch migration is merged:

### Protect `main`

- Require pull requests before merging.
- Require the CI job `build-and-validate` to pass.
- Require branches to be up to date before merging, if practical for the project.
- Block force pushes and branch deletion.
- Do not grant the collection workflow a bypass for `main`.

### Restrict `outputs`

- Do not apply the no-force-push rule to `outputs`: publication intentionally replaces
  its snapshot history.
- Restrict updates to the GitHub Actions workflow identity where repository rules
  permit it.
- Do not use `outputs` as a source-code review branch.

The collection workflow needs `contents: write` so it can update `outputs`. Its
publication step uses a force-with-lease check against the output-branch SHA captured
at the beginning of the run, preventing an overlapping run from overwriting a newer
publication.

## Recovery

If a collection run fails before publication, the previous `outputs` branch remains
available. Fix the source or workflow on `main`, run the collection again, and let
the validated output tree replace the previous snapshot. Do not manually force-push
to `main` to repair generated data.
