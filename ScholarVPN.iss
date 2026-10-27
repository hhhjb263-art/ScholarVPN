; ============================================================
; ScholarVPN 瀹㈡埛绔畨瑁呰剼鏈紙Inno Setup 6锛?
; 鐢ㄦ硶锛堜笁姝ワ紝鎴栫洿鎺ヨ繍琛?scripts\package.bat 涓€閿畬鎴愶級锛?
;   1) MSBuild VPN_.sln /p:Configuration=Release /p:Platform=x64
;   2) windeployqt x64\Release\ScholarVPN.exe        锛堟敹闆嗗叏閮?Qt 渚濊禆锛?
;   3) ISCC.exe ScholarVPN.iss                       锛堢敓鎴?x64\Release\ScholarVPNsetup.exe锛?
; 鐩爣鏈哄櫒鏃犻渶瀹夎浠讳綍杩愯鐜锛歈t/OpenSSL/Wintun 鍙婃彃浠跺叏閮ㄩ殢鍖呭畨瑁呫€?
; ============================================================

#define MyAppName "ScholarVPN"
#define MyAppVersion "1.7.0"
#define MyAppPublisher "ScholarVPN"
#define MyAppExeName "ScholarVPN.exe"

[Setup]
; AppId 鍗曠嫭鏍囪瘑鏈簲鐢紝鍕夸笌鍏朵粬瀹夎绋嬪簭鍏辩敤
AppId={{CECB2BA2-256E-4200-802E-FA3D2AEBB0F7}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
; 绋嬪簭瑕佸缓 TUN 缃戝崱/鏀硅矾鐢?鏀?DNS/鍐欐敞鍐岃〃锛屽繀椤荤鐞嗗憳
PrivilegesRequired=admin
; 浠?64 浣?
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
DefaultDirName={autopf}\{#MyAppName}
DisableProgramGroupPage=yes
UsedUserAreasWarning=no
UninstallDisplayIcon={app}\{#MyAppExeName}
; 杈撳嚭鐩綍涓庢枃浠跺悕
OutputDir=x64\Release
OutputBaseFilename=ScholarVPNsetup
; 瀹夎鍖呭浘鏍?
SetupIconFile=source\icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern

[Languages]
; 涓枃鐗?Inno Setup锛欴efault.isl 鍗崇畝浣撲腑鏂?
Name: "chinesesimp"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; 涓荤▼搴?
Source: "x64\Release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
; Qt 杩愯搴擄紙windeployqt 鏀堕泦锛?
Source: "x64\Release\Qt6Core.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\Qt6Gui.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\Qt6Widgets.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\Qt6Network.dll"; DestDir: "{app}"; Flags: ignoreversion
; OpenGL 杞覆鏌撳洖閫€锛堟棤鏄惧崱椹卞姩鐨勬満鍣ㄤ篃鑳芥樉绀虹晫闈級
Source: "x64\Release\D3Dcompiler_47.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\opengl32sw.dll"; DestDir: "{app}"; Flags: ignoreversion
; OpenSSL 鍔犲瘑搴?+ Wintun 椹卞姩
Source: "x64\Release\libcrypto-3-x64.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "x64\Release\wintun.dll"; DestDir: "{app}"; Flags: ignoreversion
; Qt 骞冲彴鎻掍欢锛堢己浜嗙▼搴忔棤娉曞惎鍔級
Source: "x64\Release\platforms\*"; DestDir: "{app}\platforms"; Flags: ignoreversion recursesubdirs createallsubdirs
; Qt 鍏朵綑鎻掍欢锛堟牱寮?鍥惧儚鏍煎紡/鍥炬爣寮曟搸/TLS/缃戠粶淇℃伅锛?
Source: "x64\Release\styles\*"; DestDir: "{app}\styles"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "x64\Release\imageformats\*"; DestDir: "{app}\imageformats"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "x64\Release\iconengines\*"; DestDir: "{app}\iconengines"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "x64\Release\tls\*"; DestDir: "{app}\tls"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "x64\Release\networkinformation\*"; DestDir: "{app}\networkinformation"; Flags: ignoreversion recursesubdirs createallsubdirs
; 鍏ㄥ眬鏍峰紡琛?
Source: "x64\Release\style.qss"; DestDir: "{app}"; Flags: ignoreversion
; 鎵樼洏鍥炬爣锛堢▼搴忎粠 exe 鍚岀洰褰曡鍙?icon.ico锛岀己浜嗕細閫€鍥炵郴缁熼粯璁ゅ浘鏍囷級
Source: "x64\Release\icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; 鍗歌浇榛樿淇濈暀 %APPDATA%\ScholarVPN锛堢敤鎴烽厤缃笌韬唤瀵嗛挜锛夛紱瑕佸交搴曟竻闄ゅ彲鍘绘帀涓嬩竴琛屾敞閲婏細
; Type: filesandordirs; Name: "{userappdata}\ScholarVPN"
