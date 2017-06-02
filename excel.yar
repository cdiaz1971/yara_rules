rule excel
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
	description= "rule to detect any Excel files"

    strings:
        $a = "sheet1" nocase 
	$b = "workbook" nocase
	condition:
	        1 of them

}

