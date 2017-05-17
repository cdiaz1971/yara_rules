rule trojan_downloader : linux trojan dowloader
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description = "files downloaded as tfpt1.sh and tftp2.sh Rule matches both"

    strings:
        $a = "cat bash >badbox;chmod +x *;./badbox"
	$b = "cat wget >badbox;chmod +x *;./badbox"
	$c = "cat cron >badbox;chmod +x *;./badbox"	
    
	condition:
	        all of them

}
