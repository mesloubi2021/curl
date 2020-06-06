You'll need Visual Studio 2015 or something newer in order to get access
to the SChannel header files. To link, you'll need WinDDK 7600.16385.1
from the `GRMWDK_EN_7600_1.ISO` that you can download from Microsoft.

1. First compile with latest version of Visual Studio. Use the `build.cmd`
   script to feed the correct parameters to NMake.

2. If there's any issues with compiling these files, use the `clib.cmd`
   script to compile that particular file if it's a library file, or the
   `csrc.cmd` script if it's part of the binary.

3. Compile the `fake-msvcrt.c` file with `cl /MD /C fake-msvcrt.c` using
   the WinDDK environment. This contains fake implementations of any of
   the missing CRT symbols. It should emit a file named `fake-msvcrt.obj`
   for you to link with.

4. Finally you should have a .lib file for curl. You can link everything
   into an .exe using the `link-curl.cmd` script. This must be done within
   the WinDDK environment.
