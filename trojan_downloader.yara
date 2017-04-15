rule trojan_downloader : linux trojan dowloader
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description = "xxxxxxxxxx"
	hash = "e6b2d0410ffb2368b6412cab4bbdefd0"

    strings:
        $a = "cat bash >badbox;chmod +x *;./badbox"
	$b = "cat wget >badbox;chmod +x *;./badbox"
	$c = "cat cron >badbox;chmod +x *;./badbox"	
    
	condition:
	        all of them

}

