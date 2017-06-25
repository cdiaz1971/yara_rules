rule zusy
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "Inital detection of a zusy variant"

    strings:
        $a = "http://103.213.251.219:5173/1.exe"
	$b = "http://103.213.251.219:5173/NBtxz.exe"
	$c = "NBtxz"	
    
	condition:
	       1 of them

}

