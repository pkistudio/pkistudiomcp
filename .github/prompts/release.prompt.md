---
description: "Use when: running the pkistudiomcp issue-to-release workflow, including issue creation, branch work, PR, merge, npm publish, tag, GitHub Release, and verification checks."
name: "pkistudiomcp release workflow"
argument-hint: "[version|TBD] [#issue] <short feature or fix summary>"
agent: "agent"
---

# pkistudiomcp Release Workflow

Run the standard `pkistudio/pkistudiomcp` release workflow from issue creation through npm publication and GitHub Release publication.

Expected invocation examples:

```text
/release 0.0.4 "Add a new ASN.1 MCP tool"
/release v0.0.4 "Fix MCP input validation"
/release TBD "Improve OID lookup output"
/release TBD #12
/release 0.0.5 #12 "Implement requested parsing option"
```

The release version may be omitted or set to `TBD` when development should proceed before the final version is known. If an existing issue number is supplied, use that issue instead of creating a duplicate issue. If the feature summary, desired release scope, issue reference, or whether a known-looking first argument is a version is unclear, ask concise clarifying questions before making changes. Otherwise proceed proactively.

## Required Safety Rules

- This prompt is a workflow guide only and does not grant repository, npm, or GitHub permissions.
- Push, merge, npm publish, tag, release, and secret-backed operations are possible only for users or tokens with the required permissions.
- Work in the current repository only.
- Confirm the repository is `pkistudio/pkistudiomcp` unless the user intentionally targets another repo.
- Check the current branch, remote, and working tree before making changes.
- Never discard uncommitted user changes.
- If unrelated local changes exist, stop and ask how to proceed.
- Create implementation work on a feature branch, never directly on `main`, unless the user explicitly asks for a direct release-only maintenance change.
- Do not merge the PR, publish to npm, create tags, or publish the GitHub Release until the user confirms they have reviewed the behavior, unless the user explicitly asks to proceed without that confirmation.
- Use existing repository patterns and keep changes focused on the requested issue.
- Use non-interactive git commands.
- Never print npm tokens, GitHub tokens, or secret values.
- Prefer non-interactive npm authentication through `NODE_AUTH_TOKEN` or `NPM_TOKEN`. Do not run `npm login` during the release workflow unless the user explicitly asks for an interactive login.

## Inputs

Derive these from the invocation when possible:

- `version`: release version, normalized to both `X.Y.Z` and `vX.Y.Z` forms when known. If omitted or `TBD`, treat it as pending and do not publish npm packages, create tags, publish releases, or make final version bumps until the release step.
- `issueNumber`: existing GitHub issue number when the invocation includes a `#<number>` reference or an unambiguous issue URL.
- `summary`: short feature or fix summary.
- `issueBody`: issue requirements. If the user supplied detailed requirements, preserve them.
- `verificationPlan`: expected local checks. If not supplied, infer from the changed area.

## Repository Facts

- npm package name: `@pkistudio/pkistudiomcp`
- npm package access: public
- npm publish command: `npm publish --access public`
- npm non-interactive auth: use `NODE_AUTH_TOKEN` or `NPM_TOKEN` with a temporary npm user config.
- Runtime command after publish: `npx -y @pkistudio/pkistudiomcp`
- Main verification command: `npm run check`
- Publish dry run command: `npm pack --dry-run`
- Release tags use the `vX.Y.Z` format.

For pkistudiomcp version bumps, update at least:

- `package.json` `version`
- `package-lock.json` root package version entries
- `src/index.ts` MCP server metadata `version`
- `README.md` when usage, installation, release, or version documentation changes

Keep the package name as `@pkistudio/pkistudiomcp`. Keep the CLI bin name as `pkistudiomcp` unless the user explicitly asks to change the executable name.

## Workflow

1. Preflight
   - Confirm the repository is `pkistudio/pkistudiomcp`.
   - Run a clean working tree check.
   - Confirm the current branch, default branch, and remote.
   - Confirm npm package metadata with `node -p "require('./package.json').name + '@' + require('./package.json').version"`.
   - If `version` is known, check existing git tags and npm versions so the requested release version does not already exist:

     ```sh
     git tag --list "vX.Y.Z"
     npm view @pkistudio/pkistudiomcp@X.Y.Z version --prefer-online
     ```

   - If `version` is pending, record that the final version must be chosen before version bumps, npm publication, tagging, or release publication.

2. Create or Fetch Issue
   - If `issueNumber` is known, fetch the existing issue and use its title, body, requirements, labels, and discussion as the source request. Do not create a new issue.
   - If no existing issue is supplied, create a GitHub issue describing the requested change.
   - For new issues, include summary, requirements, expected behavior, and verification notes.
   - Record the issue number for the branch, PR body, and final report.
   - Prefer GitHub tools when available. If the GitHub CLI is unavailable and `GITHUB_TOKEN` is set, use the GitHub REST API with `curl`. Never print token values.

3. Create Branch
   - Create a branch named `issue-<number>-<short-kebab-summary>`.
   - Switch to it before editing files.

4. Implement
   - Read the relevant files before editing.
   - Update source, package metadata, and documentation for the requested behavior.
   - If `version` is known and the change is release-worthy, update version references together.
   - If `version` is pending, leave existing released version references unchanged during implementation and note the deferred version bump in the issue and PR.
   - Keep MCP tool schemas and descriptions consistent with the implemented behavior.
   - Keep README MCP client examples aligned with the published npm package name.

5. Verify Locally
   - Run the standard checks:

     ```sh
     npm run check
     npm pack --dry-run
     ```

   - For MCP behavior changes, exercise the changed tool locally when practical with representative ASN.1 input.
   - Review the dry-run output and confirm the tarball includes only expected files.

6. Commit and Push
   - Review the diff and error list before committing.
   - Commit focused changes with a concise message.
   - Push the branch to `origin`.

7. Open Pull Request
   - Create a non-draft PR targeting `main` unless the user asks for a draft.
   - Include:
     - concise summary
     - notable implementation details
     - verification commands and manual checks
     - `Fixes #<issue-number>` when appropriate
   - Report the PR URL.

8. Wait for User Confirmation
   - Ask the user to confirm their own manual check before merge, npm publication, tagging, or GitHub Release publication.
   - If `version` is pending, ask the user to choose the final release version before continuing to release steps that require version metadata.
   - When they say to proceed, continue.

9. Merge PR
   - Re-check PR status, review requirements, and local working tree.
   - Merge using the repository's preferred style. If no preference is known, use squash merge.
   - Confirm the issue closes automatically or report if it does not.

10. Prepare Main for Release
    - Switch to `main`, fetch, and fast-forward pull.
    - Confirm the package version is the intended `X.Y.Z`.
    - If `version` was pending, stop and ask for the final version before changing files, publishing npm, tagging, or publishing a release.
    - Once the final version is chosen, normalize it to both `X.Y.Z` and `vX.Y.Z` forms and check that the npm version and git tag do not already exist.
    - If version references were deferred, create a focused version bump commit on `main` or on a release-prep branch/PR if the user wants review before publication.

11. Publish to npm
      - Prefer token-based authentication so the release does not require repeated browser-based 2FA approval. If neither `NODE_AUTH_TOKEN` nor `NPM_TOKEN` is available, stop and ask the user whether to provide an npm automation token, use GitHub Actions, or proceed with interactive `npm login`.
      - If running in GitHub Actions or another CI environment, use `NODE_AUTH_TOKEN` with `actions/setup-node` configured for `https://registry.npmjs.org`. Prefer an npm automation token stored as `NPM_TOKEN`, or npm trusted publishing if it has been configured for this package.
      - For local token-based publication, create a temporary npm user config outside the repository, use it for all npm auth and publish commands, then remove it before the final response:

         ```sh
         NPM_AUTH_TOKEN="${NODE_AUTH_TOKEN:-${NPM_TOKEN:-}}"
         if [[ -z "$NPM_AUTH_TOKEN" ]]; then
            echo "Set NODE_AUTH_TOKEN or NPM_TOKEN before publishing."
            exit 1
         fi

         NPM_USERCONFIG="$(mktemp)"
         trap 'rm -f "$NPM_USERCONFIG"' EXIT
         printf '//registry.npmjs.org/:_authToken=%s\n' "$NPM_AUTH_TOKEN" > "$NPM_USERCONFIG"

         npm whoami --userconfig "$NPM_USERCONFIG"
         npm access get status @pkistudio/pkistudiomcp --userconfig "$NPM_USERCONFIG"
         ```

      - Run final local checks immediately before publishing:

         ```sh
         npm run check
         npm pack --dry-run
         ```

      - Publish the package publicly:

         ```sh
         npm publish --access public --userconfig "$NPM_USERCONFIG"
         ```

      - Remove the temporary npm user config immediately after publish and before the final response:

         ```sh
         rm -f "$NPM_USERCONFIG"
         trap - EXIT
         unset NPM_AUTH_TOKEN NPM_USERCONFIG
         ```

      - Verify npm registry state:

         ```sh
         npm view @pkistudio/pkistudiomcp version dist-tags.latest --prefer-online
         npm view @pkistudio/pkistudiomcp@X.Y.Z name version dist-tags.latest --prefer-online
         ```

      - If `npm publish` reports that the version already exists, do not retry with changed package contents. Stop and report the conflict.

12. Tag and GitHub Release
    - Create an annotated tag `vX.Y.Z` on the released `main` commit.
    - Push the tag.
    - Create a GitHub Release named `vX.Y.Z` with release notes summarizing user-facing changes, npm package information, and issue or PR references.
    - Mark it as the latest stable release, not draft and not prerelease, unless instructed otherwise.

13. Confirm Final State
    - Verify:
      - PR is merged and closed.
      - issue is closed as completed or its remaining state is reported.
      - npm `latest` points to `X.Y.Z`.
      - tag exists on `main` HEAD.
      - GitHub Release is published.
      - relevant GitHub Actions completed or are still running.
    - Final response must include issue, PR, npm package version, release, tag, verification summary, and any Actions status.

## Final Response Format

Keep the final response concise and include:

- Issue link and state
- PR link and merge state
- npm package link and published version
- Release link and tag
- Verification summary
- Actions status
- Any follow-up needed
