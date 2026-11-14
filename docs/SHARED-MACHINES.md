# Shared machines: GitHub sign-in

## What this is

Some makerspace computers share one operating-system login. On those
machines a member runs `treehouse-git signin` to sign in to GitHub as
themself, so their commits are attributed to them. The sign-in ends at OS
logout or login, on `treehouse-git signout`, and 36 hours after sign-in by
default. This is opt-in per machine.

## Admin: enable on a shared machine

**Linux**

1. Add `SHARED_MACHINE=1` to `/etc/facility-cache/config`.
2. Run `sudo facility-cache apply`.
3. Everyone must log out and back in once.

**Windows**

1. Add `"SharedMachine": true` to `%ProgramData%\FacilityCache\config.json`.
2. It takes effect within 5 minutes, or run `FacilityCache-Apply.ps1` as admin.
3. Everyone must log out and back in once.

**Session length:** set `GH_SESSION_HOURS` (Linux) or `GhSessionHours`
(Windows). The default is 36.

**Sign-in window at login:** on by default. Turn it off with
`SIGNIN_PROMPT_AT_LOGIN=0` (Linux) or `"SignInPromptAtLogin": false`
(Windows).

**Windows needs Git for Windows installed machine-wide.** Without it,
`treehouse-git signin` refuses and the installer warns.

Both config files survive client updates.

**Do not enable this on personal machines.** It clears saved GitHub
credentials for the account.

## Members: signing in

You need a GitHub account and your phone.

1. When you log in to the desktop, a terminal window opens. It says you
   are not signed in to GitHub. Press Enter to sign in, or close the window
   to skip. Later, run `treehouse-git signin` in any terminal: bash, Git Bash,
   PowerShell or cmd.
2. It shows a one-time code.
3. On **your phone**, open https://github.com/login/device, sign in, enter
   the code, and approve.

New bash and Git Bash terminals print one line: `Signed in to GitHub as
<login> (Xh Ym left)` or `Not signed in to GitHub. Run: treehouse-git
signin`. When git needs GitHub credentials and nobody is signed in, it
prints that same hint before asking for a password.

Do not sign in to github.com in the shared computer's browser. That leaves
your whole GitHub account open for the next person.

Then use git normally. HTTPS and SSH-style GitHub remotes both work.

- `treehouse-git status` shows who is signed in and the time left.
- `treehouse-git signout` when you leave.

## When you get signed out

| Event | Signed out? |
|---|---|
| OS logout or reboot | Yes |
| `treehouse-git signout` | Yes |
| 36 hours after sign-in | Yes |
| Screen lock / idle | **No** |

Because screen lock does not sign you out, run `treehouse-git signout`
before walking away.

## What it changes on the machine

- Git gets GitHub credentials only from the session. Git Credential Manager
  and stored credentials are bypassed.
- Commits fail with "please tell me who you are" until someone signs in.
- Commit email is `<id>+<login>@users.noreply.github.com`.
- Linux: the session lives in `$XDG_RUNTIME_DIR/treehouse-gh`. At login,
  `~/.git-credentials` and `~/.config/gh/hosts.yml` are deleted.
- Windows: the session lives in each account's own profile, under
  `%LOCALAPPDATA%\FacilityCache\gh-session`. A SYSTEM task wipes it at
  startup, logon, logoff and expiry. `GH_CONFIG_DIR` and `GIT_CONFIG_GLOBAL`
  are set per account (user scope), so they reach an account at its next
  logon.
- The login window and terminal hints are installed root/admin-owned, so a
  member cannot change what the next login runs.
  - Linux: `/etc/xdg/autostart/treehouse-git-welcome.desktop` (desktop
    logins only) and `/etc/bash_completion.d/treehouse-git` (interactive
    bash).
  - Windows: the HKLM `Run` value `FacilityCacheGitHubSignIn` (desktop
    logons only, not SSH or unlock) and
    `<Git>\etc\profile.d\treehouse-git.sh` (interactive Git Bash).
  - Windows PowerShell and cmd get no hint, on purpose. A machine-wide
    PowerShell profile lives under System32 and fails under the default
    Restricted policy, and cmd AutoRun runs for every script.

## VS Code and other apps: do not sign in to GitHub inside them

- VS Code's Source Control panel and integrated terminal are fine. They call
  git, which uses your `treehouse-git` session.
- **Do not** use the Accounts menu (person icon, bottom-left) or any "Sign in
  with GitHub" prompt. Do not use extensions that need a GitHub sign-in:
  GitHub Pull Requests, GitHub Copilot, GitHub Repositories / Remote
  Repositories, Settings Sync. They store their own token in the operating
  system keychain. That token survives logout, is not removed by
  `treehouse-git signout`, and never expires.
- If VS Code asks "The extension 'GitHub' wants to sign in using GitHub",
  choose **Cancel** and run `treehouse-git signin` in the terminal instead.
- Admins can stop that prompt with these VS Code settings:
  `"github.gitAuthentication": false` and `"git.terminalAuthentication": false`.
- If you already signed in: Accounts menu → Sign Out, then revoke the app at
  https://github.com/settings/applications (Authorized OAuth Apps).
- The same applies to GitHub Desktop, JetBrains IDE GitHub accounts, and the
  web browser.

## Limits

- `gh` itself (not git) still falls back to a token in the account's OS
  keyring when nobody is signed in. Such a token exists if anyone ran a
  plain `gh auth login` on the shared account. Git is protected: its
  credential helper asks `gh` only while a session exists. Never run
  `gh auth login` directly on a shared machine; use `treehouse-git signin`.

- A repository that has its own `user.email` set locally overrides your
  identity. `treehouse-git status` warns about this. Fix it with
  `git config --local --unset user.email`.
- **Signing out does not revoke the token on GitHub.** Signout, logout,
  reboot and the 36-hour limit all delete the token from the computer. The
  token itself stays valid on GitHub.
  - Why: on 2026-11-14, revoking one session token through GitHub's
    credential-revocation API also signed the same person out of `gh` on
    their other computers. Every GitHub CLI login of that user stopped
    working within seconds.
  - If you think someone copied your session token, revoke **GitHub CLI** at
    https://github.com/settings/applications (Authorized OAuth Apps). That
    signs `gh` out on all your devices.
  - Planned fix: a dedicated Innovation Treehouse GitHub App for this
    sign-in. Its user tokens expire on their own after a few hours, and
    revoking them would not touch your own `gh` logins.
- Anyone at the keyboard while you are signed in can act as you. Sign out
  when you leave.
