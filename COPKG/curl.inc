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
    description: @"curl is a command line tool for transferring data with URL syntax, supporting DICT, FILE, FTP, FTPS, Gopher, HTTP, HTTPS, IMAP, IMAPS, LDAP, LDAPS, POP3, POP3S, RTMP, RTSP, SCP, SFTP, SMTP, SMTPS, Telnet and TFTP. curl supports SSL certificates, HTTP POST, HTTP PUT, FTP uploading, HTTP form based upload, proxies, cookies, user+password authentication (Basic, Digest, NTLM, Negotiate, kerberos...), file transfer resume, proxy tunneling and a busload of other useful tricks.

Web site: http://curl.haxx.se/"; // or path to a file...
    
    author-version : "${package-version}";
    bug-tracker: "https://github.com/coapp-packages/curl/issues";
    stability : "0";
    licenses : {
        curl
    };
}
