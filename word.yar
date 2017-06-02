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
