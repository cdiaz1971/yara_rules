rule network_smtp_dotNet {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:
	$f1 = "System.Net.Mail" nocase
        $p1 = "SmtpClient" nocase
    condition:
        all of them
}

rule network_smtp_raw {
    meta:
        author = "x0r"
        description = "Communications smtp"
	version = "0.1"
    strings:
	$s1 = "MAIL FROM:" nocase
        $s2 = "RCPT TO:" nocase
    condition:
        all of them
}

rule network_p2p_win {
    meta:
        author = "x0r"
        description = "Communications over P2P network"
	version = "0.1"
    strings:
     	$c1 = "PeerCollabExportContact"
     	$c2 = "PeerCollabGetApplicationRegistrationInfo"
     	$c3 = "PeerCollabGetEndpointName"
     	$c4 = "PeerCollabGetEventData"
     	$c5 = "PeerCollabGetInvitationResponse"
     	$c6 = "PeerCollabGetPresenceInfo"
     	$c7 = "PeerCollabGetSigninOptions"
     	$c8 = "PeerCollabInviteContact"
     	$c9 = "PeerCollabInviteEndpoint"
     	$c10 = "PeerCollabParseContact"
     	$c11 = "PeerCollabQueryContactData"
     	$c12 = "PeerCollabRefreshEndpointData"
     	$c13 = "PeerCollabRegisterApplication"
     	$c14 = "PeerCollabRegisterEvent"
     	$c15 = "PeerCollabSetEndpointName"
     	$c16 = "PeerCollabSetObject"
     	$c17 = "PeerCollabSetPresenceInfo"
     	$c18 = "PeerCollabSignout"
     	$c19 = "PeerCollabUnregisterApplication"
     	$c20 = "PeerCollabUpdateContact"
    condition:
        5 of them
}

rule network_tor {
    meta:
        author = "x0r"
        description = "Communications over TOR network"
	version = "0.1"
    strings:
        $p1 = "tor\\hidden_service\\private_key" nocase
        $p2 = "tor\\hidden_service\\hostname" nocase
        $p3 = "tor\\lock" nocase
        $p4 = "tor\\state" nocase
    condition:
        any of them
}
rule network_irc {
    meta:
        author = "x0r"
        description = "Communications over IRC network"
	version = "0.1"
    strings:
        $s1 = "NICK"
        $s2 = "PING"
        $s3 = "JOIN"
        $s4 = "USER"
        $s5 = "PRIVMSG"
    condition:
        all of them
}

rule network_http {
    meta:
        author = "x0r"
        description = "Communications over HTTP"
	version = "0.1"
    strings:
        $f1 = "wininet.dll" nocase
        $c1 = "InternetConnect"
        $c2 = "InternetOpen"
        $c3 = "InternetOpenUrl"
        $c4 = "InternetReadFile"
        $c5 = "InternetWriteFile"
        $c6 = "HttpOpenRequest"
        $c7 = "HttpSendRequest"
        $c8 = "IdHTTPHeaderInfo"
    condition:
        $f1 and $c1 and ($c2 or $c3) and ($c4 or $c5 or $c6 or $c7 or $c8)
}

rule network_ftp {
    meta:
        author = "x0r"
        description = "Communications over FTP"
	version = "0.1"
    strings:
	   $f1 = "Wininet.dll" nocase
        $c1 = "FtpGetCurrentDirectory"
        $c2 = "FtpGetFile"
        $c3 = "FtpPutFile"
        $c4 = "FtpSetCurrentDirectory"
        $c5 = "FtpOpenFile"
        $c6 = "FtpGetFileSize"
        $c7 = "FtpDeleteFile"
        $c8 = "FtpCreateDirectory"
        $c9 = "FtpRemoveDirectory"
        $c10 = "FtpRenameFile"
        $c11 = "FtpDownload"
        $c12 = "FtpUpload"
        $c13 = "FtpGetDirectory"
    condition:
        $f1 and (4 of ($c*))
}

rule network_dns {
    meta:
        author = "x0r"
        description = "Communications use DNS"
	version = "0.1"
    strings:
        $f1 = "System.Net"
        $f2 = "Ws2_32.dll" nocase
        $f3 = "Dnsapi.dll" nocase
        $f4 = "wsock32.dll" nocase
        $c2 = "GetHostEntry"
	    $c3 = "getaddrinfo"
	    $c4 = "gethostbyname"
	    $c5 = "WSAAsyncGetHostByName"
	    $c6 = "DnsQuery"
    condition:
        1 of ($f*) and  1 of ($c*)
}

rule network_ssl {
    meta:
        author = "x0r"
        description = "Communications over SSL"
        version = "0.1"
    strings:
        $f1 = "ssleay32.dll" nocase
        $f2 = "libeay32.dll" nocase
        $f3 = "libssl32.dll" nocase
        $c1 = "IdSSLOpenSSL" nocase
    condition:
        any of them
}

rule bitcoin {
    meta:
        author = "x0r"
        description = "Perform crypto currency mining"
	version = "0.1"
    strings:
        $f1 = "OpenCL.dll" nocase
        $f2 = "nvcuda.dll" nocase
        $f3 = "opengl32.dll" nocase
        $s1 = "cpuminer 2.2.2X-Mining-Extensions"
        $s2 = "cpuminer 2.2.3X-Mining-Extensions"
	    $s3 = "Ufasoft bitcoin-miner/0.20"
	    $s4 = "bitcoin" nocase
	    $s5 = "stratum" nocase
    condition:
        1 of ($f*) and 1 of ($s*)
}

rule lookupip {
    meta:
        author = "x0r"
        description = "Lookup external IP"
	version = "0.1"
    strings:
        $n1 = "checkip.dyndns.org" nocase
        $n2 = "whatismyip.org" nocase
        $n3 = "whatsmyipaddress.com" nocase
        $n4 = "getmyip.org" nocase
        $n5 = "getmyip.co.uk" nocase
    condition:
        any of them
}

rule dyndns {
    meta:
        author = "x0r"
        description = "Dynamic DNS"
	version = "0.1"
    strings:
        $s1 = "SOFTWARE\\Vitalwerks\\DUC" nocase
    condition:
        any of them
}

rule lookupgeo {
    meta:
        author = "x0r"
        description = "Lookup Geolocation"
	version = "0.1"
    strings:
        $n1 = "j.maxmind.com" nocase
    condition:
        any of them
}
