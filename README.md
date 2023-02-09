# Windows 11 Debloat / プライバシーガイド

## 重要事項

この[ガイド](https://youtu.be/QBp1d2uhG5M)はWindows 11のブロートウェアとテレメトリを削除したい上級者ユーザー向けの説明です。<br>

![Screenshot (1)](https://user-images.githubusercontent.com/85176292/132135816-81a16539-b8b5-4d54-aaae-aa1ea66afa77.png)

**注意 : この作業は自己責任で行なってください。万が一、データの損失や損害が発生した場合でも一切の責任を負いません。** <br>
最終テストはWindows 11で実施 22000.376

### Pros

➕ ブロートウェアの削除 <br>
➕ テレメトリの無効化 <br>
➕ パフォーマンスの向上 <br>
➕ Windows 11をゲームと生産性の両方を最適化 <br>
➕ Windows 11をベアボーンにストリップにする (以下の高度な削除を参照) <br>

### 短所

➖ Sysprepの破壊 <br>
➖ sfc/scannowコマンドは使用しないでください

## 必須条件

• NTFSアクセス <br>
• Install_Wim_Tweak.exe <br>
• DISM++ (任意ですが推奨) <br>
• WinAeroTweaker <br>
• Linux Liveまたはデュアルブート上の他のOS (ベアボーンにストリップをする場合)

## Windows 11のデブローティング (ブロートウェアの削除)

### デブロートを行なう前に!
セットアップ後にローカルアカウントを作成し、Cortanaを使用せずにプライバシー設定をすべてオフにしてください。 <br>

![Screenshot (01)](https://user-images.githubusercontent.com/85176292/132122504-1412f80f-2bac-4671-93f0-fa5204082b59.png)
![Screenshot (02)](https://user-images.githubusercontent.com/85176292/132122505-95823c80-06cc-4037-a48a-7e4a2e0a904a.png)

**後に削除をするので、一時的なアカウントでサインインをしている事を確認してください。** <br>
「install_wim_tweak.exe」を「C:\Windows\System32」にコピー&ペーストをしてください。 <br>

![Screenshot (03)](https://user-images.githubusercontent.com/85176292/132123362-f68c5829-c739-4628-94be-7ca2dc27fb54.png)

Windows 11を最近アップデートをしたまたは、インストールをしたばかりの場合はデブロートを行なう前に「/resetbase」コマンドでコンポーネントストアをクリーンアップするかDISM++を使用してWinSxS内に残っているアップデート用の一時ファイルを簡単に削除する事ができるのでオススメです。<br>

![Screenshot (04)](https://user-images.githubusercontent.com/85176292/132123367-6e2ebe05-9f93-4c18-86cf-ffb1f7cc34ea.png)

![Screenshot (05)](https://user-images.githubusercontent.com/85176292/132123387-5c0b6700-0497-4561-a01f-2ba419455c46.png)

**注意 : DISM++でコンポーネントストアのクリーンアップ中にエラーが発生した場合は以下のコマンドを実行します (管理者権限でコマンドプロンプトを実行)**

```
DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase
```
クリーンアップが完了したら、Windows 11のデブロートが可能になります。<br>
デブロートツールでデブロートを行ない[Finalizing](https://github.com/TheWorldOfPC/Windows11-Debloat-Privacy-Guide#finalizing)から更に最適化を続行する事ができます。 <br>

![Screenshot (1160)](https://user-images.githubusercontent.com/85176292/132950096-30fcdaf0-82f5-45bc-97df-7fe3f730e7de.png)

またはここから開始できます <br>

### アラームとクロック
```
Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage
Get-AppxPackage -AllUsers *people* | Remove-AppxPackage
```
エラーが発生しても無視で問題ありません。

### 電卓
PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage
```
クラシックな電卓のダウンロードは[こちら](https://winaero.com/get-calculator-from-windows-8-and-windows-7-in-windows-10/)

### メールとカレンダー...
PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage
Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage
```

### カメラ
PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage
````
Ignore any error that pops up

### 接続
コマンドプロンプトで以下を入力:
```
install_wim_tweak /o /c Microsoft-PPIProjection-Package /r
```

### Contact Support, Get Help
コマンドプロンプトで以下を入力:
```
install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r
```

### Cortana (UWPアプリ)
PowerShellで以下を入力:
```
Get-AppxPackage -allusers Microsoft.549981C3F5F10 | Remove-AppxPackage
```

### Music, TV
PowerShellで以下を入力:<br>
```
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart
```

### Grooveミュージック
PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
```

### Microsoft Solitare Collection
PowerShellで以下を入力:
```
Get-AppxPackage *Microsoft.MicrosoftSolitaireCollection* | Remove-AppxPackage
```

### Office
PowerShellで以下を入力:
```
Get-AppxPackage *Microsoft.MicrosoftOfficeHub* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Sway* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Office.Desktop* | Remove-AppxPackage
```

### Get Help
PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
```

### フィードバックHub
PowerShellで以下を入力:
```
Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage
```

### Sticky Notes
PowerShellで以下を入力:<br>
```
Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage
```

### マップ
PowerShellで以下を入力:<br>
```
Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage
```

### サービスの削除
コマンドプロンプトで以下を入力: <br>
```
sc delete MapsBroker
sc delete lfsvc
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable
```

### OneNote
PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage
```

### フォト
PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage
```
Enable Classic Photoviewer using [WinAeroTweaker](https://winaero.com/download-winaero-tweaker/)

### 天気、ニュース...
PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage
```

### ボイス レコーダー
PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage
```
Alternatives [Audacity](http://www.audacityteam.org/)

### Microsoft Quick Assist
PowerShellで以下を入力:
```
Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart
```
### OneDrive
コマンドプロンプトで以下を入力:
```
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall
rd "%UserProfile%\OneDrive" /s /q
rd "%LocalAppData%\Microsoft\OneDrive" /s /q
rd "%ProgramData%\Microsoft OneDrive" /s /q
rd "C:\OneDriveTemp" /s /q
del "%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" /s /f /q
```

### スマートフォン連携
PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *phone* | Remove-AppxPackage
```

### Hello Face
PowerShellで以下を入力:
```
Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
```

コマンドプロンプトで以下を入力:
```
schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
```

### Microsoft Store 
PowerShellで以下を入力: <br>
```
Get-AppxPackage -AllUsers *store* | Remove-AppxPackage
```
You can ignore any error that pops up.<br>

コマンドプロンプトで以下を入力: <br>
```
install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r
install_wim_tweak /o /c Microsoft-Windows-Store /r
```

### サービスの削除 (UWPアプリを使用する場合は非推奨)

コマンドプロンプトで以下を入力: <br>
```
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
sc delete PushToInstall
```

### XboxとGame DVR
PowerShellで以下を入力: <br>
```
Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage
```

### サービスの削除 (使用をする場合は非推奨)
コマンドプロンプトで以下を入力:<br>
```
sc delete XblAuthManager
sc delete XblGameSave
sc delete XboxNetApiSvc
sc delete XboxGipSvc
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
```

### Microsoft Edge (Chromium)

![Screenshot (07)](https://user-images.githubusercontent.com/85176292/132125057-ab8b2dbb-bb0a-4dc3-88c2-418f683e5332.png)

Now open powershell as Administrator and type: <br>
```
cd %PROGRAMFILES(X86)%\Microsoft\Edge\Application\9*\Installer && setup --uninstall --force-uninstall --system-level
```
Microsoft Edge is now uninstalled but you still can see a broken icon on start menu to get rid off it open command prompt and type: <br>

![Screenshot (08)](https://user-images.githubusercontent.com/85176292/132125728-0bca64ec-243b-4d22-865a-2f17ac82d478.png)

```
install_wim_tweak.exe /o /l
install_wim_tweak.exe /o /c "Microsoft-Windows-Internet-Browser-Package" /r
install_wim_tweak.exe /h /o /l
```
Restart is required after this (you can restart later when you are done debloating everything)

PowerShellで以下を入力:
```
Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
```

### Windows Defender (Windows Updatesが壊れます)
コマンドプロンプトで以下を入力:
```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
install_wim_tweak /o /c Windows-Defender /r
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
```
**Restart your PC** after that use NTFS Access and take ownership of C:\Program Files\WindowsApps\ & C:\ProgramData\Microsoft

![Screenshot (09)](https://user-images.githubusercontent.com/85176292/132126349-d91c4b65-f3c4-412e-a0c9-bba4c039ac30.png)

In WindowsApps delete the SecHealthUI folder

![Screenshot (10)](https://user-images.githubusercontent.com/85176292/132126362-c47be7df-d62f-4212-bd07-97714fd47041.png)

In ProgramData\Microsoft delete every folder related to Windows Defender

![Screenshot (11)](https://user-images.githubusercontent.com/85176292/132126653-1cbec29b-4c31-49f0-b596-b230913f4f30.png)

### Windows Defender (Windows Updatesを維持)

Just take the ownership of C:\Program Files\WindowsApps\ and C:\ProgramData\Microsoft <br>
Then delete the SecHealthUI folder insider WindowsApps and every folder related to Windows Defender inside ProgramData <br>
Now disable Windows Defender through WinAeroTweaker

### 最適化

Now since you have removed all the bloatware let's just finally delete the leftovers from C:\Program Files\WindowsApps <br>
Take the ownership as we did above <br>
Now delete folders according to what apps you removed... <br>

For Ex. I've removed everything and kept Store, Xbox, Notepad (UWP) and Windows Terminal <br>

![Screenshot (12)](https://user-images.githubusercontent.com/85176292/132127306-370369f6-d9f0-4a39-87e4-9b1eaa35eef8.png)

And here I've removed every bloatware <br>

![Screenshot (13)](https://user-images.githubusercontent.com/85176292/132127308-3c44ff88-4dd9-4595-a1c9-f868c77ff33c.png)

Now create a new user account or enable Windows Administrator Account, log into it and voila! <br>
You Have Successfully Debloated Windows 11!

![Screenshot (14)](https://user-images.githubusercontent.com/85176292/132127314-a39be4cc-f084-4190-81e5-c44306db1edf.png)

Unfortunately there is no way to remove "Get Started App" from the start menu without breaking the new startmenu/taskbar (at least for now) so let's just pretend it's not there at all :)

## 基本的な調整

### 設定アプリのオプションを削除
Now since you have removed the bloatware it is recommended to remove the options related to them from the settings apps <br>
Open Regedit and go to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` <br>
Create new string named 'SettingsPageVisibility' <br>
now type 
```
hide:cortana;crossdevice;easeofaccess-speechrecognition;holographic-audio;mobile-devices;privacy-automaticfiledownloads;privacy-feedback;recovery;remotedesktop;speech;sync;sync;easeofaccess-closedcaptioning;easeofaccess-highcontrast;easeofaccess-keyboard;easeofaccess-magnifier;easeofaccess-mouse;easeofaccess-narrator;easeofaccess-otheroptions;privacy-location;backup;findmydevice;quiethours;tabletmode
```

TIP : Add `;windowsdefender` at the end of the string value if you have removed Windows Defender as well (doesn't matter if u kept updates or not)

### Edit with 3D Paint / 3D Print
It is now possible to remove 3D Paint and 3D Print, but they forgot to remove the option in the context menu when you remove them. To remove it, run this in the command prompt:
```
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" ') do (reg delete "%I" /f )
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" ') do (reg delete "%I" /f )
```
### Cortanaの無効化
Open our command prompt again and use this command:
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f
```

### Windowsのエラー報告を無効化
In the command prompt, type:
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
```

### Windows Update (Storeに影響を与えない)
By doing this you will still be able to use Windows Store (Windows Updates service will run in background) without downloading any update <br>
Open Regedit and go to `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer` <br>
Open the string we created earlier and type `;windowsupdate` at the end

### Windows Updateを無効化 (Effects Windows Store)
By doing this you will not be able to use Microsoft Store or any other app which requires Windows Updates to be enabled
Open Command Prompt and type:

```
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
```

### 同期を無効化
It doesn't really affect you if you're not using a Microsoft Account, but it will at least disable the Sync settings from the Settings app.
In the command prompt, type:
```
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
```

### テレメトリなどの不要なサービスの削除
In the command prompt type the following commands:
```
sc delete DiagTrack
sc delete dmwappushservice
sc delete WerSvc
sc delete OneSyncSvc
sc delete MessagingService
sc delete wercplsupport
sc delete PcaSvc
sc config wlidsvc start=demand
sc delete wisvc
sc delete RetailDemo
sc delete diagsvc
sc delete shpamsvc 
sc delete TermService
sc delete UmRdpService
sc delete SessionEnv
sc delete TroubleshootingSvc
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)
sc delete diagnosticshub.standardcollector.service
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
```

### スケジュールされたタスク
In command prompt type:
```
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 
```
## 不要なサービスを無効化とシステムの調整

Use the batch script to disable some useless services and the reg file to import some tweaks <br>

## WinAeroTweakerでのシステムの調整

Simply install WinAeroTweaker and import the preset made by me (.ini file) <br>

![Screenshot (1672)](https://user-images.githubusercontent.com/85176292/147569287-a7223dc9-3081-4289-b18e-8f71507e8d02.png)

## (任意) Windows UpdateとStore関連サービスの無効化

Use the batch script to disable them. <br>

## Stripping Windows 11 to barebone!

**NOTE : The stripping method doesn't work on 22000.184 and above builds, though the registry one does** <br>

## For Build 22000.184/22454.1000 and above

Open WinAeroTweaker and enable the classic windows 10 start menu <br>
sign out and sign in again to let the changes take place, and there you have the old Windows 10 start menu, after 22000.132 it's broken but before this update you can still use it . Now continue from  [Making it usable](https://github.com/TheWorldOfPC/Windows11-Debloat-Privacy-Guide#Making-it-usable) <br>

![Screenshot (1185)](https://user-images.githubusercontent.com/85176292/132989873-06223852-2fd5-41bc-b79d-293338ad7d06.png)

## For Build 22000.176 and older

To remove the new taskbar you need to dualboot to any other OS or use Linux Live (any distro) <br>
Now use NTFS Access and gain ownership of C:\Windows\SystemApps\

![Screenshot (1004)](https://user-images.githubusercontent.com/85176292/132132735-421f9e2f-8aab-4570-9ebc-2670e9c2cbfd.png)

Now delete the folder named "MicrosoftWindows.Client.CBS_cw5n1h2txyewy" <br>

![Screenshot (1005)](https://user-images.githubusercontent.com/85176292/132132744-5e804520-0538-4b23-ae6a-a4686476c013.png)

Now just boot back to Windows 11, you'll notice a broken taskbar <br>
Press Win Key + R and type "netplwiz" and press enter <br>

![Screenshot (3)](https://user-images.githubusercontent.com/85176292/132132748-3ddd7117-f1b7-4359-893a-9fae2cd240d0.png)

Now create a new user account, log out of the current one and log into the new one <br>

![Screenshot (4)](https://user-images.githubusercontent.com/85176292/132132754-c51f2c7d-ca2b-4fad-ba28-24021780570f.png)

and there you have the old Windows 10 start menu, after 22000.132 it's broken but before this update you can still use it <br>

### Making it usable

Well since the Win10 start menu is broken we need an alternative to it like [StartAllBack](https://www.startallback.com/). <br>

![Screenshot (1)](https://user-images.githubusercontent.com/85176292/147569057-49849363-c0c4-49cc-9646-85dc38dc05e2.png)
![Screenshot (2)](https://user-images.githubusercontent.com/85176292/147569068-ad579193-8a28-46f5-a539-4b41caf359a6.png)

## And here you have Windows 11 Barebone!
By removing the new start menu and taskbar files we also remove the new explorer UI and context menu, but as I said if you are not a big fan of the new UI it won't matter.

![Screenshot (3)](https://user-images.githubusercontent.com/85176292/147568962-77363296-6bb6-4a6b-a0d6-87c604cb9178.jpg)


## Congratulations! Your copy of Windows is now Debloated & Optimized!
Things will change in the future, and I'll do what I can to keep this guide updated. As of December 2021, this guide works on Windows 11 22000.376

## クレジット 

• This guide is based on Adolf Intel's [Windows 10 Privacy Guide](https://github.com/adolfintel/Windows10-Privacy) with many modifications to make it usable on Windows 11 <br>
• Thanks to PPGSource#3112 from my discord server for stripping Windows 11 to barebones <br>
• Guide by The World Of PC#8783 <br>
• [Discord Server](https://discord.gg/WtmzZ4EEjt) <br>
• [Youtube Channel](https://www.youtube.com/channel/UCphlFqj7Xa9INM3DIvtXUhA/) <br>
<br>
[!["Buy Me A Coffee"](https://cdn.discordapp.com/attachments/837916532003962910/884133800655851540/78w12.png)](https://www.buymeacoffee.com/TheWorldOfPC)
