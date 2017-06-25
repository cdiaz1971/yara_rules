rule wscript
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "Windows Scripting Host Content"

    strings:
        $a = "WScript"
	
    
	condition:
	        all of them

}

