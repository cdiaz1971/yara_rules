rule onion_site
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "detect potential .onion sites"

    strings:
        $a = ".onion"
	
    
	condition:
	        all of them

}

