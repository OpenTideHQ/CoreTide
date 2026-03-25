---
description: "Use when creating commits, branches, pull requests, issues, or any Git/GitHub workflow operations. Covers conventional commits, branching strategy, PR standards, and issue management."
applyTo: ""
---

# Git Workflow & Conventional Commits

## Branching Strategy

- **`development`** is the default and primary integration branch
- Feature branches are created from `development` and merged back via pull request
- Branch naming follows the pattern: `<type>/<short-description>`
  - `feat/sentinel-mdrv4` — new feature work
  - `fix/query-validation-edge-case` — bug fixes
  - `refactor/deployment-pipeline` — code restructuring
  - `docs/wiki-navigation` — documentation changes
  - `chore/update-dependencies` — maintenance tasks

## Conventional Commits

All commit messages **must** follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | When to Use |
|------|-------------|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `refactor` | Code restructuring without behaviour change |
| `docs` | Documentation only |
| `chore` | Maintenance, dependencies, CI config |
| `style` | Formatting, whitespace (no logic change) |
| `test` | Adding or updating tests/validation |
| `perf` | Performance improvements |
| `ci` | CI/CD pipeline changes |
| `revert` | Reverting a previous commit |

### Scopes

Scopes reflect the detection system or module affected:

- **System scopes**: `sentinel`, `splunk`, `crowdstrike`, `defender`, `carbon-black`, `sentinel-one`, `harfanglab`
- **Module scopes**: `indexing`, `validation`, `deployment`, `documentation`, `framework`, `mutation`, `export`
- **Config scopes**: `models`, `tide`, `plugins`, `errors`

### Examples

```
feat(carbon-black): migrate deployer to MDRv4 typed framework
fix(sentinel): resolve KQL exclusion filter ordering
refactor(deployment): extract shared tenant resolution logic
docs(wiki): add Carbon Black Cloud deployment guide
chore(deps): update cbc-sdk to 1.5.x
```

### Breaking Changes

- Use `!` after the type/scope for breaking changes: `feat(models)!: restructure TideConfigs hierarchy`
- Or include `BREAKING CHANGE:` in the commit footer

## Pull Request Standards

### Title

PR titles follow the same conventional commit format: `<type>(<scope>): <description>`

### Description Template

PRs should include:
1. **Summary** — what this PR does and why
2. **Changes** — file-by-file or module-level breakdown
3. **Backwards Compatibility** — any breaking changes and migration guidance
4. **Testing** — how the changes were validated
5. **Related Issues** — linked via `Closes #N` or `Relates to #N`

### Draft PRs

Use draft PRs for work-in-progress that needs early visibility or review. Convert to ready when all changes are complete.

## Issue Standards

### Title

Issue titles should be descriptive and follow: `<type>: <description>`
- `feat: Migrate Carbon Black Cloud to MDRv4 typed framework`
- `bug: Query validator fails on nested parentheses`

### Labels

Apply relevant labels:
- `enhancement` — new features
- `bug` — defects
- `documentation` — docs improvements
- `refactor` — code restructuring
- `system:<name>` — system-specific issues

### Checklists

Include acceptance criteria as task lists:
```markdown
- [ ] Typed dataclass hierarchy in models.py
- [ ] SystemLoader method in tide.py
- [ ] Backwards-compatible TOML config
- [ ] Deployer updated with dual signature
```

## Code Review

- All PRs require review before merging to `development`
- Reviewers check for: correctness, convention adherence, backwards compatibility
- Address all review comments before merging
- Use "Resolve conversation" after implementing feedback
