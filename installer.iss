; Dimedropper — Inno Setup installer script
; Requires Inno Setup 6: https://jrsoftware.org/isdl.php
;
; After running build.bat, compile this with:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" installer.iss
; or open it in the Inno Setup IDE and press Ctrl+F9.

#define AppName      "Dimedropper"
#define AppVersion   "1.0.0"
#define AppPublisher "OKylieanG"
#define AppURL       "https://github.com/OKylieanG/netguard"
#define AppExeName   "dimedropper.exe"

[Setup]
AppId={{F3A2B1C0-1234-5678-ABCD-0123456789EF}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
; Output installer exe
OutputDir=installer_output
OutputBaseFilename=DimedropperSetup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; Request admin so the app can manage firewall rules
PrivilegesRequired=admin
; Min Windows version: Windows 10
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";    Description: "{cm:CreateDesktopIcon}";    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "startupicon";   Description: "Start Dimedropper when Windows starts"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
; The compiled exe from PyInstaller
Source: "dist\{#AppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}";          Filename: "{app}\{#AppExeName}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{commondesktop}\{#AppName}";   Filename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Registry]
; Auto-start with Windows (optional task)
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; \
    ValueType: string; ValueName: "{#AppName}"; \
    ValueData: """{app}\{#AppExeName}"""; \
    Flags: uninsdeletevalue; Tasks: startupicon

[Run]
; Launch after install
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchProgram,{#AppName}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallRun]
; Kill the running tray process before uninstalling
Filename: "taskkill.exe"; Parameters: "/F /IM {#AppExeName}"; Flags: runhidden; RunOnceId: "KillTray"
