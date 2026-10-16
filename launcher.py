#!/usr/bin/env python3
"""Start vaultkit: install a verified, staged update first (if there is one), then open the app.

  pyw -3.13 launcher.py               normal start (what "Open vaultkit.cmd" runs)
  pyw -3.13 launcher.py --tray        start hidden in the tray (Start with Windows uses this)
  py  -3.13 launcher.py --rollback    go back to the previous version and don't reinstall this one
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))


def main() -> int:
    import updater  # never imports app/vaultkit, so both can be replaced before they load

    if "--rollback" in sys.argv:
        try:
            version = updater.rollback(HERE)
        except updater.UpdateError as e:
            print(f"Rollback not possible: {e}")
            return 1
        print(f"Back on vaultkit {version}. The version you left won't be installed again "
              "automatically; a newer one will.")
        return 0

    note = ""
    try:
        new = updater.apply_staged(HERE, updater.installed_version(HERE))
        if new:
            note = f"Updated to vaultkit {new}."
    except Exception as e:  # a bad update must never stop the app from opening
        updater.log(f"update not installed: {e!r}")
        note = f"An update wasn't installed: {e}. You're still on the previous version."

    import app
    return app.main(startup_note=note, start_hidden="--tray" in sys.argv)


if __name__ == "__main__":
    sys.exit(main())
