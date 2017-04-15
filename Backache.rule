rule Backache : windows
{
meta:
	author = "Cesar Diaz"
	date = "2017-04-14"
	description = ""
	hash0 = "4a700ad6166cbabd02dc4a65fcaecd09"
strings:
	$string0 = "Out of memory" wide
	$string1 = "System Error.  Code: %d." wide
	$string2 = "         (((((                  H" wide
	$string3 = "9D$Lu "
	$string4 = "ltiger Variant-Typ" wide
	$string5 = "Division by zero" wide
	$string6 = ";-;;;A;\\;"
	$string7 = "99D$<u$"
	$string8 = "urn:schemas-microsoft-com:asm.v3"
	$string9 = "quz-pe" wide
	$string10 = "Range check error" wide
	$string11 = ":\\;e;m;"
	$string12 = ";-;;;C;i;};"
	$string13 = "api-ms-win-core-file-l2-1-1" wide
	$string14 = "__vectorcall"
	$string15 = " </trustInfo>"
	$string16 = "ltigen Bereichs (%d)" wide
	$string17 = "Invalid numeric input" wide
	$string18 = "Windows Vista"
condition:
	18 of them
}
