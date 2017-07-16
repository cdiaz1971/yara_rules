rule anti_virus
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "detectss possible checks for anti-virus"

    strings:
        $a = "BitDefender"
	$b = "Mcshield.exe"
	$c = "Avast"
        $d = "f-secure.exe"
        $e = "QuickHeal"
        $f = "Avira"
        $g = "avcenter.exe"
        $h = "Ad-watch"
        $i = "UnThreat"
	$j = "K7TSecurity.exe"
	$k = "PSafe"
	$l = "SinaShow"
	$m = "remupd.exe"
	$n = "rtvscan.exe"
	$o = "ashDisp.exe"
	$p = "TMBMSRV.exe"
	$q = "NOD32"
	$r = "egui.exe"
	condition:
	        any of them

}

