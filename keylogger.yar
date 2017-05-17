rule keylogger
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "detects GetKeyState string, possible keylogger"

    strings:
        $a1 = "GetKeyState"
	$a2 = "GetKeyboardType"
	
    
	condition:
	        1 of ($a*)

}

