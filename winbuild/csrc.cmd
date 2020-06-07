set "P=..\builds"
set "NAME=libcurl-vc7-x86-release-static-ipv6-sspi-winssl"

set "POBJBIN=%P%\%NAME%-obj-curl"

for %%v in (%1) do cl -GS- -Gd -Oi -O1 /DNDEBUG /MD /DCURL_STATICLIB /I. /I../lib /I../include /nologo /W4 /EHsc /DWIN32 /FD /c /DBUILDING_LIBCURL  /DUSE_IPV6  /DUSE_WINDOWS_SSPI /DUSE_SCHANNEL /Fo"%POBJBIN%\%%~nv.obj"  ..\src\%%v