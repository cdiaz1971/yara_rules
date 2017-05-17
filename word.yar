rule microsoft_word
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= ""

    strings:
        $a = "Microsoft Office Word"
	
    
	condition:
	        all of them

}
rule VARMUS
{
	meta:
	    author = "Cesar Diaz"

	strings:
	    $a = "VARMUS"

	condition:
		$a and microsoft_word
}
