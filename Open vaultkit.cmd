@echo off
rem Double-click to open the vaultkit app (no console window).
rem Installs a verified update first if one is waiting.
rem PySide6 needs 64-bit Python; 3.13 is the 64-bit install on this PC.
start "" pyw -3.13 "%~dp0launcher.py"
