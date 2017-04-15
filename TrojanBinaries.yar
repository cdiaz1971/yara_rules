rule TrojanBinaries : linux binaries trojan
{
meta:
	author = "Cesar Diaz"
	date = "2017-04-15"
	description = "Trojaned versions of standard linux binaries"
strings:
	$string0 = "Is a named type file"
	$string1 = "__stdout"
	$string2 = "_h_errno"
	$string3 = "__xpg_strerror_r"
	$string4 = "__GI___C_ctype_b_data"
	$string5 = "(null)"
	$string6 = "wildString"
	$string7 = "strtok_r"
	$string8 = "Identifier removed"
	$string9 = "fwrite_unlocked.c"
	$string10 = "environ"
	$string11 = "AVAUATUSH"
	$string12 = "stderr"
	$string13 = "attempting to start scanner"
	$string14 = "_start"
	$string15 = "Protocol family not supported"
	$string16 = "nanosleep.c"
	$string17 = "mempcpy"
	$string18 = "__GI_wcsrtombs"
condition:
	17 of them
}
