rule LinuxDownloader
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "https://www.virustotal.com/en/file/184c76027aabec8407273797a210c8eaa1c318983d35aed52b5e1cff493ed60e/analysis/"

    strings:
        $a = "wget"
	$b = "SEX"
	$c = "#!/bin/bash"
	
    
	condition:
	        all of them

}

