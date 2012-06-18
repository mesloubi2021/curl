compatability-policy {
    minimum: "7.21.0.0";
    maximum: "${OneLessThanCurrent}"; // this is the default
}

package {
    version: "${package-version}";
    location: "http://coapp.org/repository/${OutputFilename}";

    feed: "http://coapp.org/repository/packages.atom.xml";
    publisher: "CoApp Project";
}

license[curl] {
    license-url: "http://curl.haxx.se/docs/copyright.html";
    license-type: "MIT/X";
}

metadata {
    description: @"libcurl is a free and easy-to-use client-side URL transfer library, supporting DICT, FILE, FTP, FTPS, Gopher, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S, RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, Telnet and TFTP. libcurl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP form based upload, proxies, cookies, user+password authentication (Basic, Digest, NTLM, Negotiate, Kerberos), file transfer resume, http proxy tunneling and more!
 
libcurl is highly portable, it builds and works identically on numerous platforms, including Solaris, NetBSD, FreeBSD, OpenBSD, Darwin, HPUX, IRIX, AIX, Tru64, Linux, UnixWare, HURD, Windows, Amiga, OS/2, BeOs, Mac OS X, Ultrix, QNX, OpenVMS, RISC OS, Novell NetWare, DOS and more...
 
libcurl is free, thread-safe, IPv6 compatible, feature rich, well supported, fast, thoroughly documented and is already used by many known, big and successful companies and numerous applications.


Web site: http://curl.haxx.se/libcurl/"; // or path to a file...
    
    author-version : "${package-version}";
    bug-tracker: "https://github.com/coapp-packages/curl/issues";
    stability : "0";
    licenses : {
        curl
    };
}
