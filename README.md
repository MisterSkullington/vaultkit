# vaultkit — password health for your KeePassXC vault

KeePassXC is the vault: it stores your passwords, and its browser extension fills them in.
vaultkit checks them for breaches and reuse, and walks you through changing the bad ones.
Everything runs on your PC. The only thing sent anywhere is the first 5 characters of each
password's SHA-1 hash, to the free Pwned Passwords service; the match happens locally.

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
tests/              65 tests, incl. headless GUI tests against a fake keepassxc-cli
```

Needs: Windows 10/11, KeePassXC (with `C:\Program Files\KeePassXC` on PATH), Python 3.10+. The app needs **64-bit** Python (PySide6 has no 32-bit Windows build); the launcher uses `pyw -3.13`.

---

## The app

One-time install of the UI toolkit, from PowerShell inside this folder:

```powershell
py -3.13 -m pip install -r requirements.txt
```

Then double-click **Open vaultkit.cmd**. Pin it to Start for quick access (right-click → Pin to Start).

- **Unlock:** choose your `.kdbx`, type the master password. It's held in memory only.
- **Dashboard:** checks automatically after unlocking. Shows how many passwords need
  changing, a bar of breached / reused / safe, and a list of each problem.
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
- **Start menu:** the app adds itself the first time it runs: press the Windows key and type
  *vaultkit*. It also keeps *Open vaultkit* in the project folder pointing at the right place,
  with the vaultkit icon and no console window flashing up.

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
It installs anything missing (64-bit Python, KeePassXC, the two Python packages), downloads
your latest release, **checks its signature against your key before unpacking anything**, pins
the key for future updates and starts vaultkit. Your vault isn't downloaded: copy `main.kdbx`
into `vaultkit\vault` yourself. Only your main PC can publish releases.

## Uninstall

Quit vaultkit from its tray icon, then:
```powershell
cd $env:USERPROFILE\vaultkit\app
py -3.13 launcher.py --uninstall
```
It removes Start with Windows, the shortcuts, the saved master password, settings and update
files, then tells you which folder to delete. It never touches your vault, and on the PC you
publish from it keeps your signing key.
- **Fix passwords:** walks through every breached or reused entry, one site at a time
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

## Command line

| Command | What it does |
|---|---|
| `vaultkit check` | Breach + reuse check over the whole vault |
| `vaultkit fix` | Walks through each breached/reused entry (see below) |
| `vaultkit fix "Web/github"` | Just that entry |
| `vaultkit profile "Web/github" --length 64 --symbols none --2fa totp` | Per-site rules for new passwords |
| `vaultkit rotate list` | Rotations started but not finished |
| `vaultkit remember` / `vaultkit forget` | Save / delete the master password for unattended checks |
| `vaultkit shred FILE` | Overwrite and delete an exported CSV |
| `vaultkit --version` | Should say 1.7.0 |

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
- Python can't wipe strings from memory; the master password lives in the app's memory until
  lock or exit. Auto-lock limits that window.
- Run the tests: `py -m unittest discover -s tests`
