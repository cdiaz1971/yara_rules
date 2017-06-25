rule url_download_to_file
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "Shows use of the URLDownloadToFileA function or urlmon.dll"

    strings:
        $a = "URLDownloadToFileA"
	$b = "urlmon.dll"
	
    
	condition:
	        1 of them

}

