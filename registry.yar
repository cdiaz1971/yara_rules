rule registry_add
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "detects an addition to windows registry"

    strings:
        $a = "reg add HKEY"
	
    
	condition:
	        all of them

}
rule registry
{
	meta:
	author ="Cesar Diaz <cesar@cesardiaz.me>"
	description = "detects HKEY activity"

	strings:
		$a = "HKEY"

	condition:
		all of them
}
