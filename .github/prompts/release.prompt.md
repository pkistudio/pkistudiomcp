---
description: "Use when: running the pkistudiomcp issue-to-release workflow, including issue creation, branch work, PR, merge, npm publish, Docker publish, tag, GitHub Release, post-release Azure deployment reminder, and verification checks."
name: "pkistudiomcp release workflow"
argument-hint: "[version|TBD] [#issue] <short feature or fix summary>"
agent: "agent"
---

# pkistudiomcp Release Workflow

Run the standard `pkistudio/pkistudiomcp` release workflow from issue creation through GitHub Release publication, npm publication, Docker publication, post-release Azure deployment reminder, and post-release verification.

Expected invocation examples:

```text
/release 0.0.4 "Add a new ASN.1 MCP tool"
/release v0.0.4 "Fix MCP input validation"
/release TBD "Improve OID lookup output"
/release "Refresh MCP release automation"
/release TBD #12
/release 0.0.5 #12 "Implement requested parsing option"
```

The release version may be omitted or set to `TBD` when development should proceed before the final version is known. If an existing issue number is supplied, use that issue instead of creating a duplicate issue. If the feature summary, desired release scope, issue reference, or whether a known-looking first argument is a version is unclear, ask concise clarifying questions before making changes. Otherwise proceed proactively.

## Default Operating Mode

When this prompt is invoked, proceed through the workflow without restating the full release procedure to the user. Treat the issue-to-release flow as the standard path and keep progress updates brief.

Default assumptions:

- If no issue number is supplied, create a tracking issue first.
- If an issue number is supplied, use that issue as the source of truth.
- Create a branch from the issue, implement the requested change, verify it, push it, and open a PR.
- Use the issue body, issue comments, and PR body to preserve the release rationale, release notes draft, verification results, npm status, Docker status, Azure deployment reminder status, and publication status.
- Do not merge, tag, publish, or create a GitHub Release until the user explicitly says to proceed.

Ask only when:

- The requested version is missing and the workflow has reached a version-required step.
- The working tree has unrelated uncommitted changes.
- npm or GitHub permissions block progress.
- The issue requirements are ambiguous enough that implementation could go in the wrong direction.

Confirmation gates:

- Gate 1: PR merge.
- Gate 2: version bump, tag push, GitHub Release creation, and the automatic npm and Docker publish triggers caused by the tag.
- Gate 3: npm or Docker workflow rerun, or manual npm publication if the tag-triggered publication needs intervention.
- Gate 4: post-publication registry, fresh-install, MCP startup, Docker image, Actions verification, and a chat reminder telling the user to manually run the Azure deployment workflow when they are ready.

## Required Safety Rules

- This prompt is a workflow guide only and does not grant repository permissions.
- Push, tag, release, merge, and secret-backed Actions operations are possible only for users or tokens with the required repository permissions.
- npm publication requires npm package ownership or a configured npm Trusted Publisher for `@pkistudio/pkistudiomcp` and `.github/workflows/publish-npm.yml`.
- Docker publication requires Docker Hub credentials configured for `.github/workflows/publish-docker.yml`.
- Azure deployment is intentionally manual and requires GitHub Actions OpenID Connect credentials and repository variables configured for `.github/workflows/deploy-azure.yml`.
- Work in the current repository only.
- Confirm the repository is `pkistudio/pkistudiomcp` unless the user intentionally targets another repo.
- Check the current branch, remote, and working tree before making changes.
- Never discard uncommitted user changes.
- If unrelated local changes exist, stop and ask how to proceed.
- Create implementation work on a feature branch, never directly on `main`.
- Use existing repository patterns and keep changes focused on the requested issue.
- Preserve existing `package.json` package metadata unless the release requires a focused change. Do not add `private: true` only to prevent npm publication.
- Use non-interactive git commands.
- Never print npm tokens, GitHub tokens, or secret values.

## Inputs

Derive these from the invocation when possible:

- `version`: release version, normalized to both `X.Y.Z` and `vX.Y.Z` forms when known. If omitted or `TBD`, treat it as pending and do not publish npm packages, create tags, publish releases, or make final version bumps until the release step.
- `issueNumber`: existing GitHub issue number when the invocation includes a `#<number>` reference or an unambiguous issue URL.
- `summary`: short feature or fix summary.
- `issueBody`: issue requirements. If the user supplied detailed requirements, preserve them.
- `verificationPlan`: expected local checks. If not supplied, infer from the changed area.

## Standard Record Templates

Use these headings for new release tracking issues unless the issue already has a better structure:

```md
## Background
## Scope
## Release notes draft
## Verification
## Publication status
```

Use this shape for PR bodies:

```md
Summary:
- ...

Release notes draft:
...

Verification:
- `npm run check`
- `npm run smoke`
- `npm pack --dry-run`

Closes #<issue-number>
```

## Repository Facts

- npm package name: `@pkistudio/pkistudiomcp`
- npm package access: public
- npm publish command used by the release workflow: `npm publish --provenance --access public`
- npm publication path: push an annotated `vX.Y.Z` tag and let `.github/workflows/publish-npm.yml` publish through npm Trusted Publishing.
- Docker publication path: push an annotated `vX.Y.Z` tag and let `.github/workflows/publish-docker.yml` publish `docker.io/pkistudio/pkistudiomcp:X.Y.Z` and `docker.io/pkistudio/pkistudiomcp:latest`.
- Azure deployment path: manually run `.github/workflows/deploy-azure.yml` after the release if the public Azure Container Apps deployment should be updated.
- Azure deployment workflow manual command: `gh workflow run deploy-azure.yml -f tag=X.Y.Z --ref main`.
- Azure deployment required secrets: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_SUBSCRIPTION_ID`.
- Azure deployment required repository variable: `AZURE_RESOURCE_GROUP`.
- Azure deployment optional repository variables: `AZURE_CONTAINER_APP_NAME` and `AZURE_HEALTH_URL`.
- Azure public health check URL: `https://pkistudiomcp.blackfield-fee115fa.japaneast.azurecontainerapps.io/healthz`.
- Runtime command after publish: `npx -y @pkistudio/pkistudiomcp`
- Main verification command: `npm run check`
- Smoke verification command: `npm run smoke`
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

11. Tag, GitHub Release, npm, and Docker Publication
   - Create an annotated tag `vX.Y.Z` on the released `main` commit.
   - Push the tag only after the user has approved Gate 2.
   - The `Publish npm package` workflow runs on `v*` tag pushes and publishes with npm Trusted Publishing. It expects:
     - npm package name: `@pkistudio/pkistudiomcp`
     - GitHub owner/repository: `pkistudio/pkistudiomcp`
     - workflow filename: `publish-npm.yml`
     - npm Trusted Publishing environment: none / blank, unless the workflow is later changed to use one
   - The `Publish Docker image` workflow runs on `v*` tag pushes and publishes the versioned image and `latest` image to Docker Hub. It expects:
     - Docker image name: `docker.io/pkistudio/pkistudiomcp`
     - Docker Hub credentials: `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`
     - workflow filename: `publish-docker.yml`
   - For scoped npm packages, `E404` during publish can mean the package does not exist yet or the workflow/account lacks scope permission.
   - If npm publish fails with `E404` or `no permission`, explain that npm Trusted Publishing or initial package ownership is not configured. Do not keep rerunning the same job until npm permissions are fixed.
   - Do not create a new tag just to retry npm publication when the version and tag are already correct. After fixing npm permissions or Trusted Publishing, rerun the failed publish workflow or publish manually from an authorized npm account.
   - If the version was already published manually, do not rerun the publish job for the same tag/version; npm versions are immutable and the rerun will fail.
   - Do not create a new tag just to retry Docker publication when the version and tag are already correct. After fixing Docker configuration, rerun the failed workflow.
   - Create a GitHub Release named `vX.Y.Z` with release notes summarizing user-facing changes, npm package information, and issue or PR references.
   - Mark it as the latest stable release, not draft and not prerelease, unless instructed otherwise.
   - After publication, verify `npm view @pkistudio/pkistudiomcp@X.Y.Z version dist-tags dist.tarball --json`, inspect Docker manifests for `docker.io/pkistudio/pkistudiomcp:X.Y.Z` and `docker.io/pkistudio/pkistudiomcp:latest`, and, when practical, perform a fresh temporary install from npm and run the CLI entry point.
   - In the chat final response, remind the user that Azure Container Apps deployment is manual and can be triggered with `gh workflow run deploy-azure.yml -f tag=X.Y.Z --ref main` or from the GitHub Actions UI.

12. Confirm Final State
   - Verify:
     - PR is merged and closed.
     - issue is closed as completed or its remaining state is reported.
     - npm `latest` points to `X.Y.Z`.
     - Docker Hub has `X.Y.Z` and `latest` images.
     - tag exists on `main` HEAD.
     - GitHub Release is published.
     - relevant GitHub Actions completed or are still running.
   - Final response must include issue, PR, npm package version, Docker image status, release, tag, verification summary, Actions status, and the manual Azure deployment reminder.

## Final Response Format

Keep the final response concise and include:

- Issue link and state
- PR link and merge state
- npm package link and published version
- Docker image publication state
- Release link and tag
- Verification summary
- Actions status
- Manual Azure deployment reminder
- Any follow-up needed
