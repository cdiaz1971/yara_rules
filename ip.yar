
rule IP {
    meta:
        author = "Antonio S. <asanchez@plutec.net>"
    strings:
        $ip = /([0-9]{1,3}\.){3}[0-9]{1,3}/ wide ascii
    condition:
        $ip
}
