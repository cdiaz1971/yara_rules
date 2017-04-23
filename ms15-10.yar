rule ms15-10 : windows
{
meta:
	author = "Cesar Diaz"
	date = "2017-04-23"
	description = "No Description Provided"
	hash0 = "1cc220919b386853ab90fdd8953a1e2d"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = " publicKeyToken"
	$string1 = "    <security>"
	$string2 = "terminate@@YAXXZ"
	$string3 = "3D3Q3V3\\3f3w3"
	$string4 = " encoding"
	$string5 = "21282@2"
	$string6 = "      <requestedPrivileges>"
	$string7 = "CreateProcessW Failed!" wide
	$string8 = "    </security>"
	$string9 = ">4>9>X>"
	$string10 = "urn:schemas-microsoft-com:asm.v3"
	$string11 = "1fc8b3b9a1e18e3b"
	$string12 = "  </trustInfo>"
	$string13 = "  <trustInfo xmlns"
	$string14 = "<%<n<t<"
	$string15 = "      <assemblyIdentity type"
condition:
	15 of them
}
