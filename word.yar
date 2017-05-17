rule microsoft_word
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= ""

    strings:
        $a = "Microsoft Office Word"
        $b = "word/document.xml"	
    
	condition:
	        $a or $b

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
