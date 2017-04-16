rule smb_p7 : windows
{
meta:
	author = "Cesar Diaz"
	date = "2017-04-16"
	description = "file dowloaded to honeypot as smb-pm7asmpp.tmp"
	hash0 = "3e4fc616c5efdefddb651b8391ee9646"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "U]@aQ:"
	$string1 = "SVCRT7"
	$string2 = "d%A9}h"
	$string3 = "QToolhelp"
	$string4 = "A0CBAD"
	$string5 = "niRaliz"
	$string6 = "D,Y7\\2"
	$string7 = "pi.dll"
	$string8 = "me error "
	$string9 = "qR\\VAW"
	$string10 = "J]@L ["
	$string11 = "I\\eeRnEf"
	$string12 = "_YS9,q"
	$string13 = "/5ty Auth"
	$string14 = "(cY-Ag"
	$string15 = "p@ssw0rd"
	$string16 = "r6s7tF"
	$string17 = "OFTWAR"
condition:
	17 of them
}
