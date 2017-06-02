rule varmus
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "contains string VARMUS"

    strings:
        $a = "VARMUS"
	
    
	condition:
	        all of them

}

