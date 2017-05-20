rule BASE64_table
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"

    strings:
        $a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	
    
	condition:
	      $a

}

