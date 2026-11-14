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

Both config files survive client updates.

**Do not enable this on personal machines.** It clears saved GitHub
credentials for the account.

## Members: signing in

You need a GitHub account and your phone.

1. Open a terminal and run `treehouse-git signin`. In Git Bash on Windows,
   type `treehouse-git.cmd signin`.
2. It shows a one-time code.
3. On **your phone**, open https://github.com/login/device, sign in, enter
   the code, and approve.

Do not sign in to github.com in the shared computer's browser. That leaves
your whole GitHub account open for the next person.

Then use git normally. HTTPS and SSH-style GitHub remotes both work.

- `treehouse-git status` shows who is signed in and the time left.
- `treehouse-git signout` when you leave.

## When you get signed out

| Event | Signed out? |
|---|---|
| OS logout or reboot | Yes (Windows also revokes the token on GitHub) |
| `treehouse-git signout` | Yes (token revoked on GitHub) |
| 36 hours after sign-in | Yes (token revoked on GitHub) |
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
- Windows: the session lives in a per-session folder that is wiped at
  logon, logoff and expiry.

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

- A repository that has its own `user.email` set locally overrides your
  identity. `treehouse-git status` warns about this. Fix it with
  `git config --local --unset user.email`.
- On Linux, logout wipes the token but does not revoke it on GitHub. Signout
  and the 36-hour limit do revoke it.
- Anyone at the keyboard while you are signed in can act as you. Sign out
  when you leave.
