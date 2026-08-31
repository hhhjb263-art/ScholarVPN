; ============================================================
; ScholarVPN 客户端安装脚本（Inno Setup 6）
; 用法（三步，或直接运行 scripts\package.bat 一键完成）：
;   1) MSBuild VPN_.sln /p:Configuration=Release /p:Platform=x64
;   2) windeployqt x64\Release\ScholarVPN.exe        （收集全部 Qt 依赖）
;   3) ISCC.exe ScholarVPN.iss                       （生成 x64\Release\ScholarVPNsetup.exe）
; 目标机器无需安装任何运行环境：Qt/OpenSSL/Wintun 及插件全部随包安装。
; ============================================================

#define MyAppName "ScholarVPN"
#define MyAppVersion "1.5"
#define MyAppPublisher "ScholarVPN"
#define MyAppExeName "ScholarVPN.exe"

[Setup]
; AppId 单独标识本应用，勿与其他安装程序共用
AppId={{CECB2BA2-256E-4200-802E-FA3D2AEBB0F7}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
; 程序要建 TUN 网卡/改路由/改 DNS/写注册表，必须管理员
PrivilegesRequired=admin
; 仅 64 位
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
UsedUserAreasWarning=no
UninstallDisplayIcon={app}\{#MyAppExeName}
; 输出目录与文件名
OutputDir=x64\Release
OutputBaseFilename=ScholarVPNsetup
; 安装包图标
SetupIconFile=source\icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
; 中文版 Inno Setup：Default.isl 即简体中文
Name: "chinesesimp"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; 主程序
Source: "x64\Release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; Qt 运行库（windeployqt 收集）
Source: "x64\Release\Qt6Core.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\Qt6Gui.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\Qt6Widgets.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\Qt6Network.dll"; DestDir: "{app}"; Flags: ignoreversion
; OpenGL 软渲染回退（无显卡驱动的机器也能显示界面）
Source: "x64\Release\D3Dcompiler_47.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\opengl32sw.dll"; DestDir: "{app}"; Flags: ignoreversion
; OpenSSL 加密库 + Wintun 驱动
Source: "x64\Release\libcrypto-3-x64.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
; Qt 平台插件（缺了程序无法启动）
Source: "x64\Release\platforms\*"; DestDir: "{app}\platforms"; Flags: ignoreversion recursesubdirs createallsubdirs
; Qt 其余插件（样式/图像格式/图标引擎/TLS/网络信息）
Source: "x64\Release\styles\*"; DestDir: "{app}\styles"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "x64\Release\imageformats\*"; DestDir: "{app}\imageformats"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "x64\Release\iconengines\*"; DestDir: "{app}\iconengines"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "x64\Release\tls\*"; DestDir: "{app}\tls"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "x64\Release\networkinformation\*"; DestDir: "{app}\networkinformation"; Flags: ignoreversion recursesubdirs createallsubdirs
; 全局样式表
Source: "x64\Release\style.qss"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; 卸载默认保留 %APPDATA%\ScholarVPN（用户配置与身份密钥）；要彻底清除可去掉下一行注释：
; Type: filesandordirs; Name: "{userappdata}\ScholarVPN"
