<#
.SYNOPSIS
  Installs vaultkit on this PC from your latest SIGNED GitHub release.

  On your main PC, get your public key:   py -3.13 tools\release.py show-key
  On the new PC (normal PowerShell, not admin):
    powershell -ExecutionPolicy Bypass -File install.ps1 -PublicKey <that key>

  What it does:
    1. Installs 64-bit Python 3.13 if it's missing, straight from python.org (just for you, no
       admin), after Windows confirms the installer is signed by the Python Software Foundation.
       Then the PySide6 and cryptography packages.
    2. Downloads the latest vaultkit release and checks its signature against YOUR key before
       unpacking anything. A release that doesn't match is never unpacked or run.
    3. Unpacks to <you>\vaultkit\app, makes <you>\vaultkit\vault, pins your key for future updates.
    4. Installs KeePassXC if it's missing (kpsetup.py: official installer, checksum and
       signature checked, one Windows prompt) and sets it up the recommended way.
    5. Starts vaultkit. It adds its own Start-menu entry; its Setup page shows what's left.

  winget isn't needed. Your vault is never downloaded: copy main.kdbx into vaultkit\vault
  yourself, or create a new one from vaultkit's unlock screen.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PublicKey,
    [string]$Repo = 'MisterSkullington/vaultkit',
    [string]$Root = (Join-Path $env:USERPROFILE 'vaultkit'),
    [string]$ReleaseZip = '',      # install from downloaded files instead of fetching
    [string]$ReleaseSig = '',
    [string]$Python = '',          # interpreter to use; default: finds or installs 64-bit Python
    [switch]$SkipPrerequisites,    # don't install Python/KeePassXC/packages (testing)
    [switch]$NoLaunch,
    [switch]$CheckDownloadsOnly    # just download + verify the Python installer, install nothing
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2
$App = Join-Path $Root 'app'
$VaultDir = Join-Path $Root 'vault'

function Say([string]$t) { Write-Host $t }
function Fail([string]$t) { Write-Host $t -ForegroundColor Yellow; exit 1 }

if ($PublicKey -notmatch '^[0-9a-f]{64}$') {
    Fail "That doesn't look like a vaultkit public key (64 characters, 0-9 and a-f). Get it on your main PC with: py -3.13 tools\release.py show-key"
}
if (Test-Path -LiteralPath (Join-Path $App 'vaultkit.py')) {
    Fail "vaultkit is already installed in $App. It updates itself; nothing to do."
}

# ---------------------------------------------------------------- prerequisites
function Refresh-Path {
    $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
}
function Find-Python {
    $launchers = @()
    $cmd = Get-Command py -ErrorAction SilentlyContinue
    if ($cmd) { $launchers += $cmd.Source }
    $userLauncher = Join-Path $env:LOCALAPPDATA 'Programs\Python\Launcher\py.exe'
    if (Test-Path -LiteralPath $userLauncher) { $launchers += $userLauncher }
    foreach ($py in $launchers) {
        foreach ($v in '-3.13', '-3.12', '-3.11', '-3.10') {
            $out = & $py $v -c "import struct,sys;print(struct.calcsize('P')*8);print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $out -and $out[0] -eq '64') { return $out[1] }
        }
    }
    foreach ($exe in (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python313\python.exe'),
                     (Join-Path $env:ProgramFiles 'Python313\python.exe')) {
        if (Test-Path -LiteralPath $exe) { return $exe }
    }
    return $null
}

$PythonSigner = 'Python Software Foundation'
function Get-Signer([string]$Path) {
    $s = Get-AuthenticodeSignature -LiteralPath $Path
    $name = ''
    if ($s.SignerCertificate) {
        $name = $s.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    }
    return @([string]$s.Status, $name)
}
function Get-PythonInstaller([string]$Folder) {
    # newest 3.13.x that has a Windows installer, from python.org itself
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $headers = @{ 'User-Agent' = 'vaultkit-installer' }
    $listing = (Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/' -UseBasicParsing -Headers $headers).Content
    $found = [regex]::Matches($listing, 'href="(3\.13\.(\d+))/"') |
        ForEach-Object { [pscustomobject]@{ Version = $_.Groups[1].Value; Patch = [int]$_.Groups[2].Value } } |
        Sort-Object Patch -Descending
    foreach ($v in $found) {
        $url = "https://www.python.org/ftp/python/$($v.Version)/python-$($v.Version)-amd64.exe"
        try { Invoke-WebRequest -Uri $url -Method Head -UseBasicParsing -Headers $headers | Out-Null } catch { continue }
        $exe = Join-Path $Folder "python-$($v.Version)-amd64.exe"
        Say "Downloading Python $($v.Version) from python.org ..."
        Invoke-WebRequest -Uri $url -OutFile $exe -UseBasicParsing -Headers $headers
        $status, $signer = Get-Signer $exe
        if ($status -ne 'Valid' -or $signer -ne $PythonSigner) {
            Remove-Item -LiteralPath $exe -Force -ErrorAction SilentlyContinue
            Fail "STOPPED: that Python installer isn't signed by $PythonSigner (Windows says: $status, signed by '$signer'). Nothing was installed."
        }
        return $exe
    }
    Fail "Couldn't find a Python 3.13 installer on python.org. Install 64-bit Python 3.13 yourself, then run this again."
}
function Install-Python {
    $folder = Join-Path ([IO.Path]::GetTempPath()) ("vaultkit-python-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $folder | Out-Null
    try {
        $exe = Get-PythonInstaller $folder
        Say "Installing Python (just for you: no admin needed) ..."
        $p = Start-Process -FilePath $exe -PassThru -ArgumentList '/quiet', 'InstallAllUsers=0',
            'Include_launcher=1', 'InstallLauncherAllUsers=0', 'PrependPath=0', 'Include_test=0', 'Shortcuts=0'
        $null = $p.Handle
        $p.WaitForExit()
        if ($p.ExitCode -ne 0) { Fail "The Python installer stopped (code $($p.ExitCode)). Nothing else was changed." }
    } finally {
        Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
    }
    Refresh-Path
}

if ($CheckDownloadsOnly) {
    $folder = Join-Path ([IO.Path]::GetTempPath()) ("vaultkit-check-" + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $folder | Out-Null
    try {
        $exe = Get-PythonInstaller $folder
        Say "OK: $(Split-Path $exe -Leaf) is signed by $PythonSigner."
    } finally {
        Remove-Item -LiteralPath $folder -Recurse -Force -ErrorAction SilentlyContinue
    }
    exit 0
}

if (-not $SkipPrerequisites) {
    Say "Checking what's installed ..."
    if (-not $Python) {
        $Python = Find-Python
        if (-not $Python) { Install-Python; $Python = Find-Python }
        if (-not $Python) { Fail "Couldn't find 64-bit Python after installing it. Open a new PowerShell window and run this again." }
    }
    Say "Installing the Python packages vaultkit uses ..."
    & $Python -m pip install --user --upgrade --disable-pip-version-check 'PySide6>=6.7' 'cryptography>=42'
    if ($LASTEXITCODE -ne 0) { Fail "pip couldn't install PySide6/cryptography (see above)." }
}
if (-not $Python) { Fail "No Python interpreter given or found." }

# ---------------------------------------------------------------- get the release
$work = Join-Path ([IO.Path]::GetTempPath()) ("vaultkit-install-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    if ($ReleaseZip) {
        if (-not $ReleaseSig) { $ReleaseSig = "$ReleaseZip.sig" }
        $zip = $ReleaseZip; $sig = $ReleaseSig
        $version = ([IO.Path]::GetFileNameWithoutExtension($zip)) -replace '^vaultkit-', ''
    } else {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $headers = @{ 'User-Agent' = 'vaultkit-installer'; 'Accept' = 'application/vnd.github+json' }
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers $headers
        $version = ($rel.tag_name -replace '^[vV]', '')
        $zipName = "vaultkit-$version.zip"
        $zipAsset = $rel.assets | Where-Object { $_.name -eq $zipName } | Select-Object -First 1
        $sigAsset = $rel.assets | Where-Object { $_.name -eq "$zipName.sig" } | Select-Object -First 1
        if (-not $zipAsset -or -not $sigAsset) { Fail "Release $($rel.tag_name) on $Repo has no $zipName and signature." }
        $zip = Join-Path $work $zipName; $sig = "$zip.sig"
        Say "Downloading vaultkit $version ..."
        Invoke-WebRequest -Uri $zipAsset.browser_download_url -OutFile $zip -UseBasicParsing -Headers @{ 'User-Agent' = 'vaultkit-installer' }
        Invoke-WebRequest -Uri $sigAsset.browser_download_url -OutFile $sig -UseBasicParsing -Headers @{ 'User-Agent' = 'vaultkit-installer' }
    }

    # ------------------------------------------------------------ verify BEFORE unpacking
    $check = Join-Path $work 'verify.py'
    @'
import sys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
key, zip_path, sig_path = sys.argv[1:4]
with open(zip_path, 'rb') as z, open(sig_path, 'rb') as s:
    data, sig = z.read(), s.read()
try:
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(sig, data)
except InvalidSignature:
    sys.exit(2)
'@ | Set-Content -LiteralPath $check -Encoding ASCII
    & $Python -I -B $check $PublicKey $zip $sig
    if ($LASTEXITCODE -eq 2) { Fail "STOPPED: this release's signature doesn't match your key. Nothing was installed. If you didn't publish it, check your GitHub account." }
    if ($LASTEXITCODE -ne 0) { Fail "Couldn't check the signature (is the cryptography package installed?). Nothing was installed." }
    Say "Signature checked: this release was signed with your key."

    # ------------------------------------------------------------ unpack, pin trust
    $unpacked = Join-Path $work 'unpacked'
    Expand-Archive -LiteralPath $zip -DestinationPath $unpacked
    Remove-Item -LiteralPath (Join-Path $unpacked 'manifest.json') -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Path $App -Force | Out-Null
    New-Item -ItemType Directory -Path $VaultDir -Force | Out-Null
    Copy-Item -Path (Join-Path $unpacked '*') -Destination $App -Recurse -Force
    & $Python -I -B -c "import sys;sys.path.insert(0,sys.argv[1]);import updater;updater.save_trust(sys.argv[2],sys.argv[3])" $App $Repo $PublicKey
    if ($LASTEXITCODE -ne 0) { Fail "Installed, but couldn't save your update key. Run: py -3.13 tools\release.py init --repo $Repo (on a PC that has the signing key)." }
} finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------- KeePassXC
$kpNote = ''
if (-not $SkipPrerequisites) {
    Say ""
    Say "Setting up KeePassXC ..."
    & $Python -I -B (Join-Path $App 'kpsetup.py') install
    if ($LASTEXITCODE -ne 0) { $kpNote = "KeePassXC isn't fully set up yet: open vaultkit and press Setup to finish." }
}

Say ""
Say "vaultkit $version is installed in $App and will keep itself up to date."
Say "Put your vault in $VaultDir (copy main.kdbx from your main PC), or create one from vaultkit's unlock screen."
if ($kpNote) { Write-Host $kpNote -ForegroundColor Yellow }
if (-not $NoLaunch) {
    $pyw = Join-Path (Split-Path $Python -Parent) 'pythonw.exe'
    if (-not (Test-Path -LiteralPath $pyw)) { $pyw = $Python }
    Start-Process -FilePath $pyw -ArgumentList ('"' + (Join-Path $App 'launcher.py') + '"') -WorkingDirectory $App
    Say "Starting vaultkit. Next time, press the Windows key and type vaultkit."
}
