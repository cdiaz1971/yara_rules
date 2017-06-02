rule parite
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "xxxxxxxxxx"

    strings:
        $a = "qunminghanzi" ascii wide
    
	condition:
	        all of them

}

