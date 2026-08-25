; ============================================================
; ScholarVPN 客户端安装脚本（Inno Setup 6）
; 用法：
;   1) 先编译 Release：MSBuild VPN_.vcxproj /p:Configuration=Release /p:Platform=x64
;   2) 用 Inno Setup 打开本文件 → Build（或命令行 ISCC.exe 编译）
; ============================================================

#define MyAppName "ScholarVPN"
#define MyAppVersion "1.0.0"
#define MyAppPublisher "ScholarVPN"
#define MyAppExeName "ScholarVPN.exe"

[Setup]
; 安装包元信息
AppId={{8F3C1A2E-5B4D-4E7A-9C2F-3D1B6A8E5C21}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
; 需要管理员权限（程序本身要写注册表/建 TUN 网卡/改 DNS）
PrivilegesRequired=admin
; 架构：只支持 64 位（Inno Setup 6.0 用 x64；6.1+ 可换成 x64compatible）
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
; 安装到 Program Files 下
DefaultDirName={autopf}\ScholarVPN
DefaultGroupName={#MyAppName}
; 卸载程序也要求管理员
UninstallDisplayIcon={app}\{#MyAppExeName}
; 输出文件名
OutputDir=x64\Release
OutputBaseFilename=ScholarVPNSetup
; 压缩
Compression=lzma2
SolidCompression=yes
; 安装包图标（可选，有 .ico 就指定）
; SetupIconFile=app.ico
; 语言（自动检测；中文系统用简体中文）
; 若想强制中文可去掉下一行注释：
; LanguageDetectionMethod=ui

[Languages]
; 注：此 Inno Setup 为中文汉化版（界面已内置中文），无需额外语言文件。
; 若用官方英文版，可恢复下一行（需官方编译器的 Languages 目录有该文件）：
; Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; 主程序
Source: "x64\Release\ScholarVPN.exe"; DestDir: "{app}"; Flags: ignoreversion
; Qt 运行库
Source: "x64\Release\Qt6Core.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\Qt6Gui.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\Qt6Widgets.dll"; DestDir: "{app}"; Flags: ignoreversion
; 加密库 + Wintun 驱动
Source: "x64\Release\libcrypto-3-x64.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
; Qt 平台插件（必须放在 platforms 子目录，否则程序无法启动）
Source: "x64\Release\platforms\*"; DestDir: "{app}\platforms"; Flags: ignoreversion recursesubdirs
; Qt 其他插件（windeployqt 生成；缺了会在某些电脑上崩/样式异常）
Source: "x64\Release\styles\*"; DestDir: "{app}\styles"; Flags: ignoreversion recursesubdirs
Source: "x64\Release\imageformats\*"; DestDir: "{app}\imageformats"; Flags: ignoreversion recursesubdirs
Source: "x64\Release\tls\*"; DestDir: "{app}\tls"; Flags: ignoreversion recursesubdirs
Source: "x64\Release\iconengines\*"; DestDir: "{app}\iconengines"; Flags: ignoreversion recursesubdirs
; 样式文件
Source: "x64\Release\style.qss"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; 安装完成后可勾选立即运行
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; 卸载时删除配置目录（%APPDATA%\ScholarVPN）——默认不删，防止误删用户配置；
; 如需彻底删除，去掉下一行注释：
; Type: filesandordirs; Name: "{userappdata}\ScholarVPN"
