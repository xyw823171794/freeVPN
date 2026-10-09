; freeVPN 的 Windows 安装包
;
; 编译:  "C:\Users\<你>\AppData\Local\Programs\Inno Setup 6\ISCC.exe" installer.iss /DAppVersion=1.6.0
; 或者由 pack.py --installer 自动调用（会自己找 ISCC.exe）。
;
; 这个文件带 UTF-8 BOM —— 下面 Excludes 里有中文文件名(订阅地址.txt),
; 无 BOM 的话 Inno 可能按系统 ANSI 代码页去读, 中文会变乱码、排除规则失效。

#define AppName "freeVPN"
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#define AppPublisher "xyw823171794"
#define AppURL "https://github.com/xyw823171794/freeVPN"
#define AppExe "freeVPN.exe"
#define SrcDir "dist\freeVPN"

[Setup]
; AppId 必须固定 —— 升级/重装时靠它认出"这是同一个应用", 不然会并排装出两份
AppId={{7C4E1B93-2F5A-4D8E-9A31-6B0D5E7F2C48}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}/releases
; 默认 C:\freeVPN —— 和 README 建议的绿色版路径一致, 而且不碰系统目录
DefaultDirName=C:\freeVPN
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=freeVPN-v{#AppVersion}-setup
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; 装在 C:\freeVPN 不需要管理员权限 —— 别为了提权而提权
PrivilegesRequired=lowest
UninstallDisplayName={#AppName} {#AppVersion}
UninstallDisplayIcon={app}\{#AppExe}
SetupLogging=yes

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"

[Files]
; state\ out\ 订阅地址.txt 是**用户的运行数据**(订阅令牌、节点产物、内核缓存),
; 覆盖掉等于让他重新导入一遍订阅 —— 必须排除。
; bin\ 要装: 那是 mihomo 内核(58MB), 让用户自己下载太折腾。
Source: "{#SrcDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "state\*,out\*,订阅地址.txt"

[Icons]
Name: "{group}\freeVPN"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall freeVPN"; Filename: "{uninstallexe}"
Name: "{autodesktop}\freeVPN"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#AppExe}"; Description: "Launch freeVPN"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; 程序运行时生成的 __pycache__ 之类, 卸载时顺手清掉。
; state\ 和 out\ **不删** —— 那是用户的令牌和节点产物。
Type: filesandordirs; Name: "{app}\__pycache__"
