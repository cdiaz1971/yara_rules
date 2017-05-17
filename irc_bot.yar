rule IRCBot : irc perl
{
    strings:
        $a = "DDoS Perl IrcBot v1.0 / 2013 By vK"
	$b = "Stealth MultiFunctional IrcBot writen in Perl"
	$c = "Teste on every system with PERL instlled"
    
	condition:
	        all of them

}

