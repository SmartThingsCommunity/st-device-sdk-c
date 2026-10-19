# STDK Agent Skills

This directory contains **Agent Skills** for the SmartThings Device SDK (STDK).
A skill is a folder with a `SKILL.md` file that teaches an AI coding agent how to
handle a specific STDK task: looking up an error code, reading a device log,
finding the right document, and so on.

The skills use the open [Agent Skills](https://agentskills.io) format
(`SKILL.md` with `name` / `description` front matter). They are **not tied to one
vendor**. The same folder works with Claude Code, OpenAI Codex, Gemini CLI, and
any other agent that supports the format. Agents that do not support skills
natively can still use the content as plain context (see
[Other agents](#other-agents-or-no-skill-support)).

All skills fetch their facts live from the public GitHub repositories
[st-device-sdk-c](https://github.com/SmartThingsCommunity/st-device-sdk-c) and
[st-device-sdk-c-ref](https://github.com/SmartThingsCommunity/st-device-sdk-c-ref),
so the agent needs outbound access to `github.com` / `raw.githubusercontent.com`.

## Available skills

| Skill | What it does | Ask it things like |
|-------|--------------|--------------------|
| [`stdk-docs-reference`](./stdk-docs-reference/SKILL.md) | Fetches and synthesizes the official STDK docs (getting started, APIs, onboarding sequence, device states, porting, key/QR generation, commercialization) and answers with code examples and source links. | "Explain the 5-phase onboarding flow between device, app and cloud." / "What is the call sequence from `st_conn_init` to `st_conn_start`?" / "What fields does `onboarding_config.json` need?" |
| [`stdk-error-lookup`](./stdk-error-lookup/SKILL.md) | Looks up mobile app error codes (`81-001`, `04-100`, ...) from `doc/mobile_error_codes_guide.md` and SDK internal codes (`NE01`, `CE01`, `EE01`, ...) from `src/include/iot_main.h`. Returns meaning, likely causes, and a developer checklist. Tells you how to escalate if the code is unknown. | "What does error 38-100 mean?" / "My log shows CE20. What should I check?" |
| [`stdk-log-analysis`](./stdk-log-analysis/SKILL.md) | Parses STDK device logs (`[I]/[D]/[W]/[E] tag: message`), reconstructs the boot → onboarding → Wi-Fi → MQTT → runtime timeline, classifies issues by severity, and gives root cause and fix per issue. Knows the EasySetup `cmd:N` steps for both BLE and SoftAP, and cloud rejection errors such as `ConstraintViolationError`. | "Here is my device log. Why does onboarding stop after cmd:3?" / "Why is my attribute publish rejected with `NotValidValue`?" |
| [`stdk-github-search`](./stdk-github-search/SKILL.md) | Knows the layout of both STDK repositories (`doc/`, `src/`, `example/`, `tools/`) and how to fetch files, search issues, or clone them. Picks the right document or source file for a question type (API, porting, security, onboarding, cloud). | "Where is the BLE onboarding implemented?" / "Find open issues about MQTT reconnect." |

The skills reference each other. For example `stdk-log-analysis` will hand an
unknown error code to `stdk-error-lookup`. Installing all four together gives the
best result.

Each skill folder also contains a Node.js helper module (`*.js`, Node 18+). The
modules are optional reference code for fetching and parsing; the agent can work
from `SKILL.md` alone.

## Installation

### Get the files

Clone the repository, or download only this directory:

```bash
git clone https://github.com/SmartThingsCommunity/st-device-sdk-c.git
cd st-device-sdk-c/skills
```

The commands below assume you are inside `st-device-sdk-c/skills`. Replace
`cp -r` with `Copy-Item -Recurse` on Windows PowerShell.

### Claude Code

Claude Code loads skills from `~/.claude/skills/` (all projects) or
`<project>/.claude/skills/` (one project).

```bash
# For every project on this machine
mkdir -p ~/.claude/skills
cp -r stdk-* ~/.claude/skills/

# Or, for one project only
mkdir -p /path/to/your/project/.claude/skills
cp -r stdk-* /path/to/your/project/.claude/skills/
```

Restart Claude Code. Claude picks a skill automatically based on your question,
or you can call one explicitly:

```
/stdk-log-analysis  analyze the log in ./device.log
/stdk-error-lookup  81-001
```

### OpenAI Codex (CLI / IDE extension)

Codex loads skills from `~/.codex/skills/` (all projects) or
`<project>/.agents/skills/` (one project).

```bash
# For every project on this machine
mkdir -p ~/.codex/skills
cp -r stdk-* ~/.codex/skills/

# Or, for one project only
mkdir -p /path/to/your/project/.agents/skills
cp -r stdk-* /path/to/your/project/.agents/skills/
```

Restart Codex. Type `/skills` to confirm the four `stdk-*` entries are listed.
Codex applies a skill when the request matches its description, or you can name
it directly with `$`:

```
$stdk-error-lookup what does CE01 mean?
```

### Gemini CLI

Recent Gemini CLI versions support Agent Skills from `~/.gemini/skills/` (all
projects) or `<project>/.gemini/skills/` (one project).

```bash
# For every project on this machine
mkdir -p ~/.gemini/skills
cp -r stdk-* ~/.gemini/skills/

# Or, for one project only
mkdir -p /path/to/your/project/.gemini/skills
cp -r stdk-* /path/to/your/project/.gemini/skills/
```

Restart Gemini CLI and run `/skills list` to confirm they are loaded. If your
version does not list them, skills may still be behind an experimental flag;
check the Gemini CLI documentation for your version, or use the fallback below.

### Other agents, or no skill support

Any agent that reads a project instruction file can use the skills as plain
context:

- **Cursor**: copy the folders to `<project>/.cursor/skills/`.
- **GitHub Copilot**: copy the folders to `<project>/.github/skills/`.
- **Anything else** (Gemini CLI without skills, Windsurf, Aider, a chat UI):
  reference or paste the relevant `SKILL.md` in your instruction file
  (`AGENTS.md`, `GEMINI.md`, `.cursorrules`, ...). For example in `AGENTS.md`:

  ```markdown
  ## STDK support skills
  When the user asks about SmartThings Device SDK error codes, read
  skills/stdk-error-lookup/SKILL.md and follow it.
  When the user shares an STDK device log, read
  skills/stdk-log-analysis/SKILL.md and follow it.
  ```

  Or simply attach the `SKILL.md` file to your prompt.

## Verifying the install

Ask your agent:

```
What does STDK mobile error code 81-001 mean and how do I fix it?
```

A working install answers from `doc/mobile_error_codes_guide.md` in the public
repository, names the category (Identity / device authentication), and gives a
checklist rather than a generic reply.

## Tips

- **Give the agent the log file, not a screenshot.** `stdk-log-analysis` works on
  the raw text and reconstructs the timeline from `cmd:N` and `[E]` lines.
- **Quote error codes exactly** (`NE11-3`, `04-100`). The lookup skill selects the
  source file from the code format.
- **Ask for the source.** Every skill is written to cite the GitHub file it used.
  If an answer has no citation, ask "which file is that from?".
- **Network access is required.** The skills deliberately do not embed SDK facts,
  so the answer always reflects the current `main` branch.

## Updating

The skills are versioned with the SDK. To update, pull the repository and copy
the folders again, overwriting the old ones.

## Feedback

If a skill gives a wrong answer, or you want a new one, open an issue on
[st-device-sdk-c](https://github.com/SmartThingsCommunity/st-device-sdk-c/issues)
and attach the question you asked and the agent's answer.
