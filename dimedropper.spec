# dimedropper.spec — PyInstaller build spec
# Run:  pyinstaller dimedropper.spec

block_cipher = None

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        # pystray uses a platform-specific backend loaded at runtime
        'pystray._win32',
        # Pillow tkinter bridge (needed when PIL and tkinter both present)
        'PIL._tkinter_finder',
        # Our own modules (PyInstaller usually finds these, but list them
        # explicitly in case of edge cases)
        'app',
        'monitor',
        'firewall',
        'database',
        'resolver',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='dimedropper',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,      # No console window — tray app
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,     # Windows will prompt for admin rights on launch
    icon=None,          # Replace with 'dimedropper.ico' once you have one
)
