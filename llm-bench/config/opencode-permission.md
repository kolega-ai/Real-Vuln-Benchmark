# `opencode-permission.json` — permission policy for headless benchmark runs

`run_agentic.py` injects this file into every `opencode run` it launches, as the
`OPENCODE_PERMISSION` environment variable (opencode merges it over its config), and
also sets `OPENCODE_DISABLE_PROJECT_CONFIG=1`.

## Why it exists

Headless `opencode run` **auto-rejects every permission prompt**, and in opencode a
rejection **halts the session** (`PermissionNext.RejectedError`: "halts execution").
opencode's built-in defaults prompt on three things a security scanner does routinely:

| default rule | what the agent was doing |
|---|---|
| `read` of `*.env` / `*.env.*` → ask | reading the app's `.env` — where hardcoded-credential findings live |
| `external_directory` → ask | writing a scratch file to `/tmp`, or `cd ..` |
| `doom_loop` → ask | re-reading the same files while it works through a repo |

In the September 2026 GLM-5.3 and DeepSeek V4.1 Flash campaigns, **25 of 28 failed
runs** had exactly one of these denials as their last tool call, after which the
session ended with no findings written. The repositories were not large and the model
had not run out of context; it was cut off mid-read. Each retry pass recovered about
half of them, which is what a random cut-off looks like.

## What the policy does

- **Allows** reading `.env` files and using `/tmp` (and macOS's `/private/tmp`,
  `/var/folders`) for scratch output.
- **Denies** editing anything inside the repository, leaving the repository (a `cd ..`
  could reach the ground truth), and destructive / network / VCS-mutating shell
  commands (`rm`, `mv`, `chmod`, `sudo`, `git push|commit|reset|checkout|clean|stash`,
  `curl`, `wget`, package installs, `docker`), plus web fetch/search.
- Sets `doom_loop` to allow — the per-run timeout bounds the cost instead.

A **deny still halts the run**. That is intentional for this list: a run that tries to
modify the repo or leave it is not a run we want scored. Anything a scanner
legitimately does is now an explicit allow, so the halt only fires on real violations.

## Pattern semantics (from opencode's source)

`*` matches anything including `/`, patterns are anchored, and a trailing `" *"` is
optional — so `"rm *"` matches both `rm` and `rm -rf x`. Bash rules match the full
command text of each sub-command; `external_directory` rules match `<dir>/*`. Later
rules win, which is why `edit` lists `"*": "deny"` first and the `/tmp` allows after.

## `OPENCODE_DISABLE_PROJECT_CONFIG=1`

opencode also loads `opencode.json` from the *scanned repository's* directory. Thirteen
corpus checkouts carried a stray one that silently rerouted the `zai`, `claude` and
`kimi` providers through a dead LiteLLM proxy, failing every run on those repos.
Disabling project config makes the harness immune to whatever a scanned repo contains.
