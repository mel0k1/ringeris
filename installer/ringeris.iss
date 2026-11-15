[Setup]
AppId={{7C1E5B42-3A9D-4E1F-9C6B-2D8A4F0E5A17}
AppName=Ringeris
AppVersion=0.2.0
AppPublisher=mel0k1
DefaultDirName={autopf}\Ringeris
DefaultGroupName=Ringeris
OutputBaseFilename=Ringeris-0.2.0-setup
OutputDir=artifacts
Compression=lzma2
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
WizardStyle=modern
UninstallDisplayName=Ringeris

[Tasks]
Name: desktopicon; Description: {cm:CreateDesktopIcon}; GroupDescription: {cm:AdditionalIcons}

[Files]
Source: "{#AppRoot}\*"; DestDir: "{app}"; Flags: recursesubdirs ignoreversion
Source: "{#CoreExe}"; DestDir: "{app}\core"; Flags: ignoreversion

[Icons]
Name: "{group}\Ringeris"; Filename: "{app}\Ringeris.exe"
Name: "{group}\{cm:UninstallProgram,Ringeris}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Ringeris"; Filename: "{app}\Ringeris.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Ringeris.exe"; Description: "{cm:LaunchProgram,Ringeris}"; Flags: nowait postinstall skipifsilent
