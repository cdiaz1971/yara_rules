rule LinuxDDOS : linux DDOS
{
    strings:
        $a = "sed -i -e '/%s/d' /etc/rc.local"
	$b = "info[DT_PLTREL]->d_un.d_val == DT_REL || info[DT_PLTREL]->d_un.d_val == DT_RELA"
    
	condition:
	        all of them

}

