rule pdf
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "should detect a standard PDF doc"

    strings:
        $a = "%PDF"
	
    
	condition:
	        all of them

}

