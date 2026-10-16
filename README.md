# vaultkit — password health for your KeePassXC vault

[![tests](https://github.com/MisterSkullington/vaultkit/actions/workflows/tests.yml/badge.svg)](https://github.com/MisterSkullington/vaultkit/actions/workflows/tests.yml)

KeePassXC is the vault: it stores your passwords, and its browser extension fills them in.
vaultkit installs and sets up KeePassXC the recommended way, checks your passwords (breached,
weak, reused, near-identical, old, and sites that were breached), gives the vault a health
score, and walks you through changing the bad ones.
Everything runs on your PC. What leaves it: the first 5 characters of each password's SHA-1
hash, to the free Pwned Passwords service (the match happens locally), and a once-a-day
download of Have I Been Pwned's public list of breached websites, which is matched locally
too, so nobody learns which sites you use.

Everything lives in one folder:

```
C:\Users\<you>\vaultkit\
    Open vaultkit       shortcut that starts the app
    app\                this program (updates only ever replace files in here)
    vault\              main.kdbx and KeePassXC's backups of it
    old-downloads\      earlier vaultkit zips
    source\             your copy of the GitHub repo (releases are signed from here)
```
The vault is deliberately outside `app\`: never delete or replace `app\` with the vault in it.

Inside `app\`:
```
app.py              the desktop app (PySide6)
launcher.py         starts the app; installs a verified update first if one is waiting
Open vaultkit.cmd   double-click to open the app (runs launcher.py)
updater.py          signed self-updates from your GitHub repo's releases
autostart.py        "Start with Windows" (per-user Run key, no admin rights)
shortcuts.py        the Start-menu entry and 'Open vaultkit', kept up to date by the app
uninstall.py        `launcher.py --uninstall`
install.ps1         installs vaultkit on another PC from your latest signed release
tools/release.py    signs and publishes a release (run on your PC; the key stays there)
vaultkit.py         the command-line tool (same core the app uses)
vaultkit.cmd        lets you type `vaultkit ...` instead of `py vaultkit.py ...`
secretstore.py      optional saved password for unattended checks (Windows DPAPI)
kpsetup.py          finds, installs and sets up KeePassXC (also: py -3.13 kpsetup.py check)
backup.py           copies of the vault in OneDrive, made when it changes
breaches.py         which of your sites had a breach, and was it after your last change
strength.py         weak and near-identical password checks (nothing leaves the PC)
tests/              137 tests, incl. headless GUI tests against a fake keepassxc-cli;
                    run on real Windows by GitHub Actions on every push, followed by a
                    real KeePassXC download, signature check, install and vault test
```

Needs: Windows 10/11 and 64-bit Python 3.10+ (PySide6 has no 32-bit Windows build; the
launcher uses `pyw -3.13`). KeePassXC is installed for you if it's missing (*Setup*, below),
and it doesn't need to be on PATH.

---

## The app

One-time install of the UI toolkit, from PowerShell inside this folder:

```powershell
py -3.13 -m pip install -r requirements.txt
```

Then double-click **Open vaultkit.cmd**. Pin it to Start for quick access (right-click → Pin to Start).

- **Unlock:** choose your `.kdbx`, type the master password. It's held in memory only. If
  KeePassXC isn't installed, a notice offers **Set up KeePassXC**.
- **Setup** (bottom left of the unlock screen, top bar of the dashboard): a list of green
  ticks, with a button next to anything that isn't done:
  - **KeePassXC:** installs the latest version from KeePassXC's official GitHub releases. Before
    it runs, the download must match KeePassXC's published checksum **and** Windows must confirm
    it's signed by *DroidMonkey Apps, LLC* (KeePassXC's signing company); otherwise nothing is
    installed. One Windows permission prompt, which should name that publisher.
  - **Recommended settings:** back up before each save, lock after 5 minutes and when Windows
    locks, clear copied passwords after 10 s, Windows Hello unlock, tray icon, browser
    integration, and giving logins to the browser without asking each time (the browser still
    only gets logins for the site you're on). Only settings that differ are changed, and a
    stricter choice of yours (say, locking after 2 minutes) is kept. KeePassXC must be closed,
    because it rewrites its settings when it quits; the old file is backed up next to it.
  - **Browser connection:** registers KeePassXC for Chrome-based browsers, Opera GX included,
    exactly as KeePassXC's own *Chrome* checkbox does.
  - **KeePassXC starts with Windows**, so auto-fill is ready when you log in.
  - **Vault security:** reads your vault file's unencrypted header (no password needed) and
    checks it uses KDBX 4, **Argon2id** and at least 256 MiB. If not, **Show me how** lists
    the one KeePassXC screen that fixes it.
  - **KeePassXC-Browser in Opera GX:** opens the extension's page. Adding it, pressing
    *Connect* and naming the connection are yours to do: that handshake is the security boundary.
- **Names shared by several entries** (say, three `accounts.google.com` logins): vaultkit
  can't tell them apart, so it can't fix them one by one. Double-click one of those rows and
  each gets its own name, `accounts.google.com (username)`. Only the names change; the
  entries, passwords and history stay as they are.
- **Backups to OneDrive:** whenever the vault changes, vaultkit copies it to
  `OneDrive\vaultkit backups` (checked against the original, newest 30 kept). It needs no
  password, because the vault file is already encrypted; OneDrive adds its own version
  history. Shown, with **Back up now**, on the Setup page. To restore: close KeePassXC, copy
  the backup you want over `vaultkit\vault\main.kdbx`, and open it as usual.
- **Create a vault** (*No vault yet? Create one* on the unlock screen): choose where, type a
  master password twice (12+ characters, no common patterns, not in known breaches), and tick
  that it's written on paper. KeePassXC's command-line tool can only make an older-format vault
  (KDBX 3.1, AES-KDF), so Setup then shows the one-minute switch to Argon2id + 256 MiB.
- **Dashboard:** checks automatically after unlocking. Shows how many passwords need
  changing, a **health score** out of 100 with its trend over the last 30 days, a bar of
  breached / at risk / safe, and a list of each problem (see *What the check looks for*).
- **Fix passwords:** walks through every entry with a problem, most serious first, one site at a time
  (double-click a row to fix just that one):
  1. a new password is made and **saved in your vault first**, then copied for 45 s
     (kept out of Windows clipboard history);
  2. **Open change page** takes you to the site's change-password page;
  3. once you've logged back in with it, press **The site accepted it**. The old password
     stays in the entry's History in KeePassXC.

  **The site rejected it** discards the new one and opens that site's password rules
  (length, allowed symbols, change page, two-step login). Set what the site allows, then
  **Save rules and make a new password**. **Skip for now** keeps the new password for next
  time. Afterwards the dashboard re-checks automatically.

  If the app auto-locks while you're on a website, nothing is lost: unlock and press
  Fix passwords again, and it picks up the saved new password.
- **Auto-lock:** after 5 minutes with no mouse or keyboard activity, the password is dropped
  and you're back at the unlock screen.
- **Remember on this PC for daily checks:** optional. See *Saved password* below.
- **Tray:** closing the window locks the vault and keeps vaultkit by the clock. Right-click
  the icon for *Open*, *Check now*, *Daily check*, *Start with Windows*, *Theme* and *Quit*.
  The icon gets a red dot when a password is breached, amber when some need changing.
- **Daily check:** runs once a day in the background. With *Remember on this PC* it runs on
  its own; otherwise you get one reminder a day to unlock. You're notified when a password is
  **newly** found in a breach, and reminded weekly while problems remain. Notifications never
  name sites, because Windows can show them on the lock screen.
- **Start with Windows:** tick it in the tray menu. It starts quietly in the tray (no window)
  and replaces the older `vaultkit check` Startup shortcut, which it removes.
- **Themes:** *Theme* (top right, or in the tray menu): Match Windows (default), Mist,
  Slate (dark), Ember (dark, warm), Heather, High contrast. All meet WCAG AA contrast.
- Opening vaultkit while it's already running just brings the existing window forward.
- **Version:** shown in the window title, at the bottom of the unlock screen and dashboard,
  and at the top of the tray menu.
- **Start menu:** the app adds itself the first time it runs: press the Windows key and type
  *vaultkit*. It also keeps *Open vaultkit* in the project folder pointing at the right place,
  with the vaultkit icon and no console window flashing up.

## What the check looks for

Most serious first. An entry with several problems is listed once, under the worst.

| | Problem | Why it matters |
|---|---|---|
| Breached | The password itself is in Pwned Passwords | Attackers try every leaked password first |
| Breached | Its website had a breach that exposed passwords **after** vaultkit last changed it | That password may be in someone's hands |
| At risk | Its website had such a breach, and vaultkit doesn't know when the password was set | Change it if you haven't since the breach |
| At risk | Same password as another entry | One leak opens every account that shares it |
| At risk | Weak: short, a keyboard run, a word plus numbers (*Summer2024!*), a dressed-up word (*Tr0ub4dor&3*) | Cracked in minutes, offline |
| At risk | Nearly the same as another entry (*Summer2023!* / *Summer2024!*) | One leak gives the others away |
| At risk | Not changed in 3+ years | More time to have leaked somewhere |

**Health score:** 100 minus a share for each entry with a problem, scaled by how serious
(a breached password counts fully, an old one a fifth). It's shown in amber, never green,
while any password is breached. One point a day is kept in `history.json` (scores and
counts only, never names) for the trend line.

**Password dates.** KeePassXC's *Last Modified* moves on any edit (notes, URL, password
rules), so vaultkit can't use it to judge whether a password predates a breach. Instead it
writes `changed: YYYY-MM-DD` into the entry's vaultkit notes block whenever it sets a new
password. Passwords you imported or changed in KeePassXC by hand have no such date, so a
breach of their site stays listed as *At risk* until you change them through vaultkit.

## Another PC

On your main PC, get your public key (it's not secret):
```powershell
py -3.13 tools\release.py show-key
```
On the other PC, download `install.ps1` from the repo (github.com/MisterSkullington/vaultkit,
open the file, *Download raw file*) and run it from a normal PowerShell window:
```powershell
powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\install.ps1" -PublicKey PASTE_KEY_HERE
```
It doesn't need winget. It installs 64-bit Python from python.org if it's missing (just for
you, no admin, only after Windows confirms the installer is signed by the Python Software
Foundation) and the two Python packages, downloads your latest release, **checks its signature
against your key before unpacking anything**, pins the key for future updates, then installs and
sets up KeePassXC as *Setup* does, and starts vaultkit. Your vault isn't downloaded: copy
`main.kdbx` into `vaultkit\vault` yourself, or create a new one. Only your main PC can publish
releases.

## Uninstall

Quit vaultkit from its tray icon, then:
```powershell
cd $env:USERPROFILE\vaultkit\app
py -3.13 launcher.py --uninstall
```
It removes Start with Windows, the shortcuts, the saved master password, settings and update
files, then tells you which folder to delete. It never touches your vault, and on the PC you
publish from it keeps your signing key.

## Command line

| Command | What it does |
|---|---|
| `vaultkit check` | Every check over the whole vault, with the health score |
| `vaultkit fix` | Walks through each entry with a problem, breached first (see below) |
| `vaultkit fix "Web/github"` | Just that entry |
| `vaultkit profile "Web/github" --length 64 --symbols none --2fa totp` | Per-site rules for new passwords |
| `vaultkit rotate list` | Rotations started but not finished |
| `vaultkit remember` / `vaultkit forget` | Save / delete the master password for unattended checks |
| `vaultkit shred FILE` | Overwrite and delete an exported CSV |
| `vaultkit names` | Give entries that share a title their own names |
| `vaultkit backup [--to FOLDER]` | Copy the vault to OneDrive now (only if it changed) |
| `vaultkit --version` | Should say 1.10.0 |
| `py -3.13 kpsetup.py check --db <vault>` | The Setup list, in text |
| `py -3.13 kpsetup.py install` | Install KeePassXC if needed, then the recommended setup |

`vaultkit` works from any PowerShell window once this folder is on your PATH (one time):
```powershell
$p = [Environment]::GetEnvironmentVariable("Path","User"); [Environment]::SetEnvironmentVariable("Path", "$p;$env:USERPROFILE\vaultkit\app", "User")
```
Otherwise use `py vaultkit.py ...` from inside this folder. Set `VAULTKIT_DB` to your vault
path so you don't need `--db` each time.

### How `fix` keeps you from getting locked out

For each site: the new password is **saved in the vault first**, then the site's
change-password page opens in your browser (the site profile's URL, or the site's standard
`/.well-known/change-password` link), and the new password goes on your clipboard for 45 s.
You then answer:

- **y** — the site accepted it *and* you logged back in with it. The entry is updated; the old
  password stays in the entry's History tab in KeePassXC.
- **n** — the site rejected it. The new password is discarded; nothing changes.
  Set a profile (shorter, no symbols) and try again.
- **c** copy again · **s** skip (the new password is kept for next time) · **q** quit.

Quitting or crashing at any point is safe: both old and new passwords stay in the vault.
Entries that share a title (e.g. two `google.com` logins) are skipped, because they can't be
targeted safely. Rename them in KeePassXC first.

Save any edits in the KeePassXC window before running `fix`; both write the same file.

### Saved password (unattended daily checks)

Opt-in. `vaultkit remember` (or the checkbox in the app) encrypts the master password with
Windows DPAPI, tied to your Windows login on this PC. Another user or a copied disk can't
read it; programs running as you while you're logged in can. That's the trade-off for
checks that run while you're away. `vaultkit forget` deletes it.

Daily checks are run by the app from the tray (see *Tray* above). Turn on *Start with
Windows* in the tray menu so they happen without opening anything.

## Updates

The app checks your GitHub repo's latest release when it starts and once a day. A new
version is downloaded, **verified against your signing key**, and installed the next time
the app starts (a banner offers **Restart now**). Off until you run `release.py init`.

Why signed: auto-updating a password tool means running whatever the update contains, with
your master password in memory. So releases are signed with a key that exists only on your
PC (encrypted to your Windows login), and the app checks that signature against a public key
pinned in `%LOCALAPPDATA%\vaultkit\update.json`, outside the app folder, where an update
can't replace it. Someone who got into your GitHub account still couldn't push an update:
the app would show a red warning and install nothing. It also refuses older versions, file
names outside the app folder, and files that don't match the signed manifest.

**One-time setup.** Keep a copy of the repo in the project folder; releases are built and
signed from it:
```powershell
cd $env:USERPROFILE\vaultkit
gh repo clone MisterSkullington/vaultkit source
cd source
py -3.13 tools\release.py init --repo MisterSkullington/vaultkit
```

**Publishing a new version** (after new code has been pushed to the repo):
```powershell
cd $env:USERPROFILE\vaultkit\source
git pull
git log --oneline -5
py -3.13 tools\release.py publish --notes "What changed"
```
`git log` shows what you're about to sign: only publish changes you expect. Publishing needs
the GitHub CLI signed in once (`gh auth login`). The app then installs it on its next start.

**Going back:** `py -3.13 launcher.py --rollback` restores the previous version and won't
reinstall the one you left. The last 3 versions are kept in `%LOCALAPPDATA%\vaultkit\backups`.

**Other PCs:** install vaultkit, then copy `update.json` from this PC's
`%LOCALAPPDATA%\vaultkit\` to the same place on the other PC. Only this PC can publish.

The repo must be **public** (the updater reads releases without a GitHub login). It holds
only the app's code: no passwords, no vault, no settings. `.gitignore` blocks `*.kdbx` and
`*.csv` so a vault or password export can't be committed by accident.

---

## One-time setup (done once, for reference)

*Setup* in the app now does the settings, browser connection and autostart parts of this, and
checks the vault's encryption. The manual steps, for reference:

**Vault:** KeePassXC → New Database → Advanced Settings: KDBX 4, **Argon2id**, 256 MiB, threads =
CPU cores, ~1 s decryption. Settings → Security: lock after 300 s, lock with Windows, clear
clipboard after 10 s, enable Windows Hello quick unlock. Settings → General: auto-save and
*Backup database file before saving*. Keep the master passphrase on paper somewhere safe.

**Import from Opera GX:** `opera://settings/passwords` → ⋮ → Export passwords → import in
KeePassXC (Database → Import → CSV) → `vaultkit shred "<the csv>"` → empty the Recycle Bin.
Then in Opera turn off *Offer to save passwords* and delete the saved ones.

**Auto sign-in:** KeePassXC → Settings → Browser Integration → enable, tick Chrome (Opera uses
Chrome's connector on Windows) → Advanced → *Never ask before accessing credentials*. Install
KeePassXC-Browser in Opera GX from the Chrome Web Store → Connect. In the extension's options,
turn on auto-fill for single credentials and auto-submit.

## Gotchas

- Each keepassxc-cli call takes ~1 s by design (Argon2). A check is one unlock; a rotation is a few.
- The list of breached websites is cached for a day in `%LOCALAPPDATA%\vaultkit`. If it can't be
  downloaded, that one check is skipped and the dashboard says so; everything else still runs.
- Python can't wipe strings from memory; the master password lives in the app's memory until
  lock or exit. Auto-lock limits that window.
- KeePassXC's own default for new vaults is Argon2d with 64 MiB; *Setup* flags that too.
  Argon2d is fine for a file on your PC, but Argon2id with 256 MiB is the stronger, recommended
  setting.
- Run the tests: `py -m unittest discover -s tests`
