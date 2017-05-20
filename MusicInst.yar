rule MusicInst
{
    meta:
	author = "Cesar Diaz <cesar@cesardiaz.me>"
        sha256 = "94275b86a17e4d96e9ef3d3aa344496ed2f7e3e0436d820cadfc5e00d4fb82ba"

    strings:
        $a = "SB360.exe"
	$b = "MusicInst"
	
    
	condition:
	        all of them

}

