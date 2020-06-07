set "DDKDIR=C:\WinDDK\7600.16385.1"
set "NAME=libcurl-vc7-x86-release-static-ipv6-sspi-winssl"

set "SDK=%DDKDIR%\lib\win7\i386"
set "CRT=%DDKDIR%\lib\Crt\i386"

set "CURL_LIBDIR=..\builds\%NAME%\lib"
set "CURL_EXE=..\builds\%NAME%\bin\curl.exe"
set "CURL_OBJDIR=..\builds\%NAME%-obj-curl"

set OBJECTS=%CURL_OBJDIR%\tool_hugehelp.obj  %CURL_OBJDIR%\nonblock.obj  %CURL_OBJDIR%\strtoofft.obj  %CURL_OBJDIR%\warnless.obj  %CURL_OBJDIR%\curl_ctype.obj %CURL_OBJDIR%/slist_wc.obj  %CURL_OBJDIR%/tool_binmode.obj  %CURL_OBJDIR%/tool_bname.obj  %CURL_OBJDIR%/tool_cb_dbg.obj  %CURL_OBJDIR%/tool_cb_hdr.obj  %CURL_OBJDIR%/tool_cb_prg.obj  %CURL_OBJDIR%/tool_cb_rea.obj  %CURL_OBJDIR%/tool_cb_see.obj  %CURL_OBJDIR%/tool_cb_wrt.obj  %CURL_OBJDIR%/tool_cfgable.obj  %CURL_OBJDIR%/tool_convert.obj  %CURL_OBJDIR%/tool_dirhie.obj  %CURL_OBJDIR%/tool_doswin.obj  %CURL_OBJDIR%/tool_easysrc.obj  %CURL_OBJDIR%/tool_filetime.obj  %CURL_OBJDIR%/tool_formparse.obj  %CURL_OBJDIR%/tool_getparam.obj  %CURL_OBJDIR%/tool_getpass.obj  %CURL_OBJDIR%/tool_help.obj  %CURL_OBJDIR%/tool_helpers.obj  %CURL_OBJDIR%/tool_homedir.obj  %CURL_OBJDIR%/tool_libinfo.obj  %CURL_OBJDIR%/tool_main.obj  %CURL_OBJDIR%/tool_metalink.obj  %CURL_OBJDIR%/tool_msgs.obj  %CURL_OBJDIR%/tool_operate.obj  %CURL_OBJDIR%/tool_operhlp.obj  %CURL_OBJDIR%/tool_panykey.obj  %CURL_OBJDIR%/tool_paramhlp.obj  %CURL_OBJDIR%/tool_parsecfg.obj  %CURL_OBJDIR%/tool_progress.obj  %CURL_OBJDIR%/tool_strdup.obj  %CURL_OBJDIR%/tool_setopt.obj  %CURL_OBJDIR%/tool_sleep.obj  %CURL_OBJDIR%/tool_urlglob.obj  %CURL_OBJDIR%/tool_util.obj  %CURL_OBJDIR%/tool_vms.obj  %CURL_OBJDIR%/tool_writeout.obj  %CURL_OBJDIR%/tool_writeout_json.obj  %CURL_OBJDIR%/tool_xattr.obj

link.exe -release /incremental:no /libpath:"%SDK%" /libpath:"%CRT%" /libpath:"%CURL_LIBDIR%" /out:"%CURL_EXE%" /subsystem:console /nologo /machine:x86 ws2_32.lib safecrtnt.lib wldap32.lib advapi32.lib crypt32.lib libcurl_a.lib fake-msvcrt.obj %OBJECTS%

