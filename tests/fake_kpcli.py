#!/usr/bin/env python3
"""Minimal stand-in for keepassxc-cli used by the test suite. State lives in $FAKE_KP_STATE.

Entries sharing a title are stored as "Group/Title#2", "#3"...: the suffix is invisible to
commands, and a path always means the FIRST matching entry, as in KeePassXC
(Group::findEntryByPath)."""
import csv, io, json, os, sys
from datetime import datetime, timedelta, timezone

sys.stdout.reconfigure(encoding="utf-8")
sys.stdin.reconfigure(encoding="utf-8")

if sys.argv[1:] == ["--version"]:
    print("2.7.12"); sys.exit(0)
if sys.argv[1] == "db-create":  # like the real one: password twice on stdin, KDBX 3.1 + AES-KDF
    path = sys.argv[-1]
    pw = sys.stdin.read().split("\n")
    if os.path.exists(path):
        print(f"File {path} already exists.", file=sys.stderr); sys.exit(1)
    if len(pw) < 2 or pw[0] != pw[1] or not pw[0]:
        print("Failed to set database password.", file=sys.stderr); sys.exit(1)
    import struct
    aes_kdf, aes256 = (bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea"),
                       bytes.fromhex("31c1f2e6bf714350be5805216afc5aff"))
    head = struct.pack("<III", 0x9AA2D903, 0xB54BFB67, 0x00030001)
    for fid, data in ((2, aes256), (6, struct.pack("<Q", 60000)), (0, b"\r\n\r\n")):
        head += bytes([fid]) + struct.pack("<H", len(data)) + data
    open(path, "wb").write(head + os.urandom(64))
    if os.environ.get("FAKE_KP_STATE"):
        json.dump({"master": pw[0], "groups": [], "entries": {}}, open(os.environ["FAKE_KP_STATE"], "w"))
    sys.exit(0)

state_path = os.environ["FAKE_KP_STATE"]
st = json.load(open(state_path))
lines = sys.stdin.read().split("\n")
if lines[0] != st["master"]:
    print("Error: invalid credentials", file=sys.stderr); sys.exit(1)
extra = lines[1:]

cmd, rest = sys.argv[1], sys.argv[2:]
opts, pos, i = {}, [], 0
while i < len(rest):
    a = rest[i]
    if a in ("-q", "-s", "-p", "--no-password"):
        opts[a] = True
    elif a in ("-a", "-f", "-u", "--url", "--notes", "-k", "-t"):
        opts[a] = rest[i + 1]; i += 1
    else:
        pos.append(a)
    i += 1
db, target = pos[0], (pos[1] if len(pos) > 1 else None)
E = st["entries"]

def save(): json.dump(st, open(state_path, "w"))
def stamp(days): return (datetime.now(timezone.utc) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
def path_of(key): return key.split("#", 1)[0]
def find(p):
    return next((k for k in E if path_of(k) == p), None)
def need(p):
    key = find(p)
    if key is None: print(f"Could not find entry with path {p}.", file=sys.stderr); sys.exit(1)
    return key

if cmd == "export":
    buf = io.StringIO(); w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    # same columns, same order as the real CLI (CsvExporter: ... TOTP, Icon, Last Modified, Created)
    w.writerow(["Group", "Title", "Username", "Password", "URL", "Notes", "TOTP", "Icon",
                "Last Modified", "Created"])
    for key, e in E.items():
        g, _, t = path_of(key).rpartition("/")
        created = e.get("Created", stamp(-15))  # default: imported a fortnight ago
        w.writerow(["Root" + ("/" + g if g else ""), t, e["UserName"], e["Password"], e["URL"],
                    e["Notes"], "", "0", e.get("Modified", created), created])
    print(buf.getvalue(), end="")
elif cmd == "show":
    key = need(target)
    if "-a" in opts:
        print(E[key][opts["-a"]])
    else:  # real CLI prints a summary of the entry
        print(f"Title: {target.rsplit('/', 1)[-1]}\nUserName: {E[key]['UserName']}")
elif cmd == "edit":
    key = need(target)
    if "--notes" in opts: E[key]["Notes"] = opts["--notes"]
    if opts.get("-p"):
        E[key].setdefault("History", []).append(E[key]["Password"])
        E[key]["Password"] = extra[0]
    E[key]["Modified"] = stamp(0)  # like KeePassXC: ANY edit moves Last Modified
    if "-t" in opts:  # a new title; the entry keeps its place, like in KeePassXC
        g = path_of(key).rpartition("/")[0]
        new = (g + "/" if g else "") + opts["-t"]
        n, unique = 2, new
        while unique in E:
            unique, n = f"{new}#{n}", n + 1
        st["entries"] = E = {(unique if k == key else k): v for k, v in E.items()}
    save()
elif cmd == "add":
    if find(target) is not None: print("entry exists", file=sys.stderr); sys.exit(1)
    E[target] = {"UserName": opts.get("-u", ""), "URL": opts.get("--url", ""),
                 "Notes": opts.get("--notes", ""), "Password": extra[0] if opts.get("-p") else ""}
    save()
elif cmd == "mkdir":
    if target in st["groups"]: print("Group already exists!", file=sys.stderr); sys.exit(1)
    st["groups"].append(target); save()
elif cmd == "rm":
    key = need(target); E["Recycle Bin/" + target.split("/")[-1]] = E.pop(key); save()
elif cmd == "ls" and target is None:  # root listing, like the real CLI
    for top in sorted({path_of(p).split("/")[0] + ("/" if "/" in p else "") for p in E}):
        print(top)
elif cmd == "ls":
    if target not in st["groups"]: print("Cannot find group", file=sys.stderr); sys.exit(1)
    for p in map(path_of, E):
        if p.startswith(target + "/"): print(p[len(target) + 1:])
elif cmd == "clip":
    need(target)  # read-only: real clip runs detached, so it must not race later writes
else:
    print(f"unknown command {cmd}", file=sys.stderr); sys.exit(1)
