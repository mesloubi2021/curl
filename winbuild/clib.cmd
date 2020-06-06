set "P=..\builds"
set "NAME=libcurl-vc7-x86-release-static-ipv6-sspi-winssl"

set "POBJLIB=%P%\%NAME%-obj-lib"
SET "PLIB=%P%\%NAME%\lib\libcurl_a.lib"

for /f "usebackq delims=\ tokens=1,2" %%a in ('%1') do if not "%%b" == "" (
    for %%v in (%%b) do cl -GS- -Gd -Oi -O1 /DNDEBUG /MD /DCURL_STATICLIB /I. /I../lib /I../include /nologo /W4 /EHsc /DWIN32 /FD /c /DBUILDING_LIBCURL  /DUSE_IPV6  /DUSE_WINDOWS_SSPI /DUSE_SCHANNEL /Fo"%POBJLIB%\%%a\%%~nv.obj"  ..\lib\%%a\%%b
) else (
    for %%v in (%1) do cl -GS- -Gd -Oi -O1 /DNDEBUG /MD /DCURL_STATICLIB /I. /I../lib /I../include /nologo /W4 /EHsc /DWIN32 /FD /c /DBUILDING_LIBCURL  /DUSE_IPV6  /DUSE_WINDOWS_SSPI /DUSE_SCHANNEL /Fo"%POBJLIB%\%%~nv.obj"  ..\lib\%%v
)

del "%PLIB%"