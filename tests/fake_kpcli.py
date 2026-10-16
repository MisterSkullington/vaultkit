#!/usr/bin/env python3
"""Minimal stand-in for keepassxc-cli used by the test suite. State lives in $FAKE_KP_STATE."""
import csv, io, json, os, sys

sys.stdout.reconfigure(encoding="utf-8")
sys.stdin.reconfigure(encoding="utf-8")

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
    elif a in ("-a", "-f", "-u", "--url", "--notes", "-k"):
        opts[a] = rest[i + 1]; i += 1
    else:
        pos.append(a)
    i += 1
db, target = pos[0], (pos[1] if len(pos) > 1 else None)
E = st["entries"]

def save(): json.dump(st, open(state_path, "w"))
def need(p):
    if p not in E: print(f"Could not find entry with path {p}.", file=sys.stderr); sys.exit(1)

if cmd == "export":
    buf = io.StringIO(); w = csv.writer(buf, quoting=csv.QUOTE_ALL)
    w.writerow(["Group", "Title", "Username", "Password", "URL", "Notes"])
    for p, e in E.items():
        g, _, t = p.rpartition("/")
        w.writerow(["Root" + ("/" + g if g else ""), t, e["UserName"], e["Password"], e["URL"], e["Notes"]])
    print(buf.getvalue(), end="")
elif cmd == "show":
    need(target)
    if "-a" in opts:
        print(E[target][opts["-a"]])
    else:  # real CLI prints a summary of the entry
        print(f"Title: {target.rsplit('/', 1)[-1]}\nUserName: {E[target]['UserName']}")
elif cmd == "edit":
    need(target)
    if "--notes" in opts: E[target]["Notes"] = opts["--notes"]
    if opts.get("-p"):
        E[target].setdefault("History", []).append(E[target]["Password"])
        E[target]["Password"] = extra[0]
    save()
elif cmd == "add":
    if target in E: print("entry exists", file=sys.stderr); sys.exit(1)
    E[target] = {"UserName": opts.get("-u", ""), "URL": opts.get("--url", ""),
                 "Notes": opts.get("--notes", ""), "Password": extra[0] if opts.get("-p") else ""}
    save()
elif cmd == "mkdir":
    if target in st["groups"]: print("Group already exists!", file=sys.stderr); sys.exit(1)
    st["groups"].append(target); save()
elif cmd == "rm":
    need(target); E["Recycle Bin/" + target.split("/")[-1]] = E.pop(target); save()
elif cmd == "ls" and target is None:  # root listing, like the real CLI
    for top in sorted({p.split("/")[0] + ("/" if "/" in p else "") for p in E}):
        print(top)
elif cmd == "ls":
    if target not in st["groups"]: print("Cannot find group", file=sys.stderr); sys.exit(1)
    for p in E:
        if p.startswith(target + "/"): print(p[len(target) + 1:])
elif cmd == "clip":
    need(target)  # read-only: real clip runs detached, so it must not race later writes
else:
    print(f"unknown command {cmd}", file=sys.stderr); sys.exit(1)
