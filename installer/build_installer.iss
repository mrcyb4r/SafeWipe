; SafeWipe Installer (Inno Setup)
[Setup]
AppName=SafeWipe
AppVersion=1.0
DefaultDirName={pf}\SafeWipe
DefaultGroupName=SafeWipe
OutputBaseFilename=SafeWipeInstaller
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
WizardStyle=modern

[Files]
; Include the built exe and optionally adb.exe in same folder
Source: "..\dist\safewipe.exe"; DestDir: "{app}"; Flags: ignoreversion
; If including adb.exe (check license): Source: "extra\adb.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\README.md"; DestDir: "{app}"; Flags: isreadme

[Icons]
Name: "{group}\SafeWipe"; Filename: "{app}\safewipe.exe"
Name: "{userdesktop}\SafeWipe"; Filename: "{app}\safewipe.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop icon"; GroupDescription: "Additional icons:"; Flags: unchecked
