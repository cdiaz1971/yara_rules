rule wannacry_051217
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"

    strings:
	$a = "WNcry@2ol7"	
    
	condition:
	        all of them

}

