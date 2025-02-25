; UnrealIRCd Win32 Installation Script for My Inno Setup Extensions
; Requires Inno Setup 4.1.6 and ISX 3.0.4 to work

 #define USE_SSL
; Uncomment the above line to package an SSL build
 #define USE_ZIP
; Uncomment the above line to package with ZIP support
 #define USE_CURL
; Uncomment the above line to package with libcurl support


[Setup]
AppName=UnrealIRCd
AppVerName=UnrealIRCd3.2.8+UDB 3.6.1
AppPublisher=UnrealIRCd Team
AppPublisherURL=http://www.unrealircd.com
AppSupportURL=http://www.unrealircd.com
AppUpdatesURL=http://www.unrealircd.com
AppMutex=UnrealMutex,Global\UnrealMutex
DefaultDirName={pf}\Unreal3.2
DefaultGroupName=UnrealIRCd
AllowNoIcons=yes
#ifndef USE_SSL
LicenseFile=.\gpl.rtf
#else
LicenseFile=.\gplplusssl.rtf
#endif
Compression=lzma/ultra
SolidCompression=true
InternalCompressLevel=ultra
MinVersion=4.0.1111,4.0.1381
OutputDir=../../

[Tasks]
Name: "desktopicon"; Description: "Crear un icono en el &escritorio"; GroupDescription: "Iconos adicionales:"
Name: "quicklaunchicon"; Description: "Crear un icono en la barra de men� &r�pido"; GroupDescription: "Iconos adicionales:"; Flags: unchecked
Name: "installservice"; Description: "Instalarlo como &servicio (no principiantes)"; GroupDescription: "Soporte servicio:"; Flags: unchecked; MinVersion: 0,4.0
Name: "installservice/startboot"; Description: "&Iniciar UnrealIRCd cuando Windows arranca"; GroupDescription: "Soporte servicio:"; MinVersion: 0,4.0; Flags: exclusive unchecked
Name: "installservice/startdemand"; Description: "Iniciar UnrealIRCd por &petici�n"; GroupDescription: "Soporte servicio:"; MinVersion: 0,4.0; Flags: exclusive unchecked
Name: "installservice/crashrestart"; Description: "Reiniciar UnrealIRCd si se cierra inesperadamente"; GroupDescription: "Soporte servicio:"; Flags: unchecked; MinVersion: 0,5.0;
#ifdef USE_SSL
Name: "makecert"; Description: "&Crear certificado"; GroupDescription: "Opciones SSL:";
Name: "enccert"; Description: "&Encriptar certificado"; GroupDescription: "Opciones SSL:"; Flags: unchecked;
#endif

[Files]
Source: "..\..\wircd.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\WIRCD.pdb"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\.CHANGES.NEW"; DestDir: "{app}"; DestName: "CHANGES.NEW.txt";Flags: ignoreversion
Source: "..\..\.CONFIG.RANT"; DestDir: "{app}"; DestName: "CONFIG.RANT.txt"; Flags: ignoreversion
Source: "..\..\.RELEASE.NOTES"; DestDir: "{app}"; DestName: "RELEASE.NOTES.txt"; Flags: ignoreversion
Source: "..\..\.SICI"; DestDir: "{app}"; DestName: "SICI.txt"; Flags: ignoreversion
Source: "..\..\badwords.channel.conf"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\badwords.message.conf"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\badwords.quit.conf"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\spamfilter.conf"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\dccallow.conf"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\cambios.udb"; DestDir: "{app}"; DestName: "cambios.udb.txt"; Flags: ignoreversion
Source: "..\..\Changes"; DestDir: "{app}"; DestName: "Changes.txt"; Flags: ignoreversion
Source: "..\..\Changes.old"; DestDir: "{app}"; DestName: "Changes.old.txt"; Flags: ignoreversion
Source: "..\..\Donation"; DestDir: "{app}"; DestName: "Donation.txt"; Flags: ignoreversion
Source: "..\..\help.conf"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "..\..\Unreal.nfo"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\doc\*.*"; DestDir: "{app}\doc"; Flags: ignoreversion
Source: "..\..\doc\technical\*.*"; DestDir: "{app}\doc\technical"; Flags: ignoreversion
Source: "..\..\aliases\*"; DestDir: "{app}\aliases"; Flags: ignoreversion
Source: "..\..\networks\*"; DestDir: "{app}\networks"; Flags: ignoreversion
Source: "..\..\unreal.exe"; DestDir: "{app}"; Flags: ignoreversion; MinVersion: 0,4.0
Source: "..\modules\*.dll"; DestDir: "{app}\modules"; Flags: ignoreversion
Source: "tre.dll"; DestDir: "{app}"; Flags: ignoreversion
#ifdef USE_SSL
Source: "C:\dev\openssl\bin\openssl.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\dev\openssl\bin\ssleay32.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\dev\openssl\bin\libeay32.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: ".\makecert.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: ".\encpem.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\ssl.cnf"; DestDir: "{app}"; Flags: ignoreversion
#endif
#ifdef USE_ZIP
Source: "c:\dev\zlib\dll32\zlibwapi.dll"; DestDir: "{app}"; Flags: ignoreversion
#endif
#ifdef USE_SSL
#ifdef USE_CURL
; curl with ssl support
Source: "C:\dev\curl\lib\Release\libcurl.dll"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\..\curl-ca-bundle.crt"; DestDir: "{app}"; Flags: ignoreversion
#endif
#else
#ifdef USE_CURL
; curl without ssl support
Source: "c:\dev\curl\lib\libcurl.dll"; DestDir: "{app}"; Flags: ignoreversion
#endif
#endif
Source: isxdl.dll; DestDir: {tmp}; Flags: dontcopy
Source: "..\..\dbghelp.dll"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\tmp"

[UninstallDelete]
Type: files; Name: "{app}\DbgHelp.Dll"

[Code]
function isxdl_Download(hWnd: Integer; URL, Filename: PChar): Integer;
external 'isxdl_Download@files:isxdl.dll stdcall';
function isxdl_SetOption(Option, Value: PChar): Integer;
external 'isxdl_SetOption@files:isxdl.dll stdcall';
const crturl = 'http://www.unrealircd.com/downloads/msvcr71.dll';
const cpturl = 'http://www.unrealircd.com/downloads/msvcp71.dll';
var didDbgDl,didCrtDl: Boolean;

function NextButtonClick(CurPage: Integer): Boolean;
var
tmp, msvcrt, msvcpt: String;
hWnd,answer: Integer;
begin

    if ((CurPage = wpReady)) then begin
      msvcrt := ExpandConstant('{sys}\msvcr71.Dll');
      msvcpt := ExpandConstant('{sys}\msvcp71.Dll');
    if (NOT FileExists(msvcrt)) then begin
      answer := MsgBox('Unreal necesita MS C Runtime 7.1 para funcionar. �Quiere instalarlo?', mbConfirmation, MB_YESNO);
      if answer = IDYES then begin
        tmp := ExpandConstant('{tmp}\msvcr71.Dll');
        isxdl_SetOption('title', 'Downloading msvcr71.dll');
        hWnd := StrToInt(ExpandConstant('{wizardhwnd}'));
        if isxdl_Download(hWnd, crturl, tmp) = 0 then begin
          MsgBox('La descarga e instalaci�n de msvcr71.dll han fallado. El archivo tiene que instalarse manualmente. Puede descargarlo de http://www.unrealircd.com/downloads/mscvr71.dll', mbInformation, MB_OK);
        end else
          didCrtDl := true;
      end else
        MsgBox('Esta librer�a es necesaria. Puede descargarla de http://www.unrealircd.com/downloads/msvcr71.dll', mbInformation, MB_OK);
    end;
    if (NOT FileExists(msvcpt)) then begin
      answer := MsgBox('Unreal necesita the MS C++ Runtime 7.1 para funcionar. �Quiere instalarlo?', mbConfirmation, MB_YESNO);
      if answer = IDYES then begin
        tmp := ExpandConstant('{tmp}\msvcp71.Dll');
        isxdl_SetOption('title', 'Downloading msvcp71.dll');
        hWnd := StrToInt(ExpandConstant('{wizardhwnd}'));
        if isxdl_Download(hWnd, cpturl, tmp) = 0 then begin
          MsgBox('La descarga e instalaci�n de msvcp71.dll han fallado. El archivo tiene que instalarse manualmente. Puede descargarlo de http://www.unrealircd.com/downloads/mscvp71.dll', mbInformation, MB_OK);
        end else
          didCrtDl := true;
      end else
        MsgBox('Esta librer�a es necesaria. Puede descargarla de http://www.unrealircd.com/downloads/msvcp71.dll', mbInformation, MB_OK);
    end;

  end;
  Result := true;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
input,output: String;
begin
  if (CurStep = ssPostInstall) then begin
    if (didDbgDl) then begin
      input := ExpandConstant('{tmp}\dbghelp.dll');
      output := ExpandConstant('{app}\dbghelp.dll');
      FileCopy(input, output, true);
    end;
    if (didCrtDl) then begin
      input := ExpandConstant('{tmp}\msvcr71.dll');
      output := ExpandConstant('{sys}\msvcr71.dll');
      FileCopy(input, output, true);
      input := ExpandConstant('{tmp}\msvcp71.dll');
      output := ExpandConstant('{sys}\msvcp71.dll');
      FileCopy(input, output, true);
    end;
  end;
end;

[Icons]
Name: "{group}\UnrealIRCd"; Filename: "{app}\wircd.exe"; WorkingDir: "{app}"
Name: "{group}\Uninstall UnrealIRCd"; Filename: "{uninstallexe}"; WorkingDir: "{app}"
#ifdef USE_SSL
Name: "{group}\Make Certificate"; Filename: "{app}\makecert.bat"; WorkingDir: "{app}"
Name: "{group}\Encrypt Certificate"; Filename: "{app}\encpem.bat"; WorkingDir: "{app}"
#endif
Name: "{group}\Documentation"; Filename: "{app}\doc\unreal32docs.html"; WorkingDir: "{app}"
Name: "{userdesktop}\UnrealIRCd"; Filename: "{app}\wircd.exe"; WorkingDir: "{app}"; Tasks: desktopicon
Name: "{userappdata}\Microsoft\Internet Explorer\Quick Launch\UnrealIRCd"; Filename: "{app}\wircd.exe"; WorkingDir: "{app}"; Tasks: quicklaunchicon

[Run]
Filename: "notepad"; Description: "View example.conf"; Parameters: "{app}\doc\example.conf"; Flags: postinstall skipifsilent shellexec runmaximized
Filename: "{app}\doc\unreal32docs.html"; Description: "View UnrealIRCd documentation"; Parameters: ""; Flags: postinstall skipifsilent shellexec runmaximized
Filename: "notepad"; Description: "View Release Notes"; Parameters: "{app}\RELEASE.NOTES.txt"; Flags: postinstall skipifsilent shellexec runmaximized
Filename: "notepad"; Description: "View Changes"; Parameters: "{app}\Changes.txt"; Flags: postinstall skipifsilent shellexec runmaximized
Filename: "{app}\unreal.exe"; Parameters: "install"; Flags: runminimized nowait; Tasks: installservice
Filename: "{app}\unreal.exe"; Parameters: "config startup manual"; Flags: runminimized nowait; Tasks: installservice/startdemand
Filename: "{app}\unreal.exe"; Parameters: "config startup auto"; Flags: runminimized nowait; Tasks: installservice/startboot
Filename: "{app}\unreal.exe"; Parameters: "config crashrestart 2"; Flags: runminimized nowait; Tasks: installservice/crashrestart
#ifdef USE_SSL
Filename: "{app}\makecert.bat"; Tasks: makecert; Flags: postinstall;
Filename: "{app}\encpem.bat"; WorkingDir: "{app}"; Tasks: enccert; Flags: postinstall;
#endif

[UninstallRun]
Filename: "{app}\unreal.exe"; Parameters: "uninstall"; Flags: runminimized; RunOnceID: "DelService"; Tasks: installservice

[Languages]
Name: Castellano; MessagesFile: compiler:Languages\Spanish.isl
