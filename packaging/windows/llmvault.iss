; LLM Vault - Windows installer (Inno Setup 6)
; Per-user install into %LOCALAPPDATA%\Programs\LLM Vault - no administrator rights required.
; Build: packaging\windows\build-windows.ps1  (or: ISCC.exe /DAppVersion=0.1.0 llmvault.iss)

#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\..\target\release"
#endif

[Setup]
AppId={{6B1E7C2A-3F4D-4E8B-9A57-1C0D2E3F4A5B}
AppName=LLM Vault
AppVersion={#AppVersion}
AppVerName=LLM Vault {#AppVersion}
AppPublisher=bestin-it.com
AppPublisherURL=https://bestin-it.com
AppSupportURL=https://github.com/bestin-it/llm-vault/issues
AppUpdatesURL=https://bestin-it.com/llm-vault/
DefaultDirName={localappdata}\Programs\LLM Vault
DefaultGroupName=LLM Vault
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=..\..\dist
OutputBaseFilename=LLM-Vault-{#AppVersion}-windows-x64-setup
SetupIconFile=..\..\assets\llmvault.ico
UninstallDisplayIcon={app}\llmvault.exe
UninstallDisplayName=LLM Vault
LicenseFile=..\..\LICENSE
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
CloseApplications=yes
RestartApplications=no
VersionInfoVersion={#AppVersion}
VersionInfoCompany=bestin-it.com
VersionInfoDescription=LLM Vault installer
; Code signing (optional): define SignToolName in Inno Setup (Tools > Configure Sign Tools), e.g.
;   signtool sign /fd sha256 /tr http://timestamp.digicert.com /td sha256 /n "Your Publisher" $f
; and pass /DSign=1 to ISCC.
#ifdef Sign
SignTool=signtool
SignedUninstaller=yes
#endif

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "autostart"; Description: "Start LLM Vault when I sign in to Windows"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "{#SourceDir}\llmvault.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\llmvault-server.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme
Source: "..\..\THIRD-PARTY.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\..\examples\*"; DestDir: "{app}\examples"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\LLM Vault"; Filename: "{app}\llmvault.exe"
Name: "{autoprograms}\LLM Vault (demo with sample data)"; Filename: "{app}\llmvault.exe"; Parameters: "--demo"
Name: "{autodesktop}\LLM Vault"; Filename: "{app}\llmvault.exe"; Tasks: desktopicon
Name: "{userstartup}\LLM Vault"; Filename: "{app}\llmvault.exe"; Tasks: autostart

[Run]
Filename: "{app}\llmvault.exe"; Description: "{cm:LaunchProgram,LLM Vault}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /IM llmvault.exe /F"; Flags: runhidden; RunOnceId: "StopApp"

[Code]
// The uninstaller removes the program. Profiles, vault files and the audit log are kept unless
// the user explicitly chooses to delete them (requirement: "the user's vault is removed only by
// a conscious choice").
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir, ConfigDir: String;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{localappdata}\bestin-it\LLM Vault');
    ConfigDir := ExpandConstant('{userappdata}\bestin-it\LLM Vault');
    if DirExists(DataDir) or DirExists(ConfigDir) then
    begin
      if MsgBox('Do you also want to DELETE your LLM Vault profiles, vaults stored in the profile folders and the audit log?' + #13#10#13#10 +
                DataDir + #13#10 + ConfigDir + #13#10#13#10 +
                'Choose "No" to keep them (recommended). Vault files you saved elsewhere are never touched.',
                mbConfirmation, MB_YESNO or MB_DEFBUTTON2) = IDYES then
      begin
        DelTree(DataDir, True, True, True);
        DelTree(ConfigDir, True, True, True);
      end;
    end;
  end;
end;
