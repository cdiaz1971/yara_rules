rule trojan_downloader2 : linux trojan dowloader
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description = "xxxxxxxxxx"
	hash = "e6b2d0410ffb2368b6412cab4bbdefd0"

    strings:
        $a = "176.223.165.167"
    
	condition:
	        all of them

}

