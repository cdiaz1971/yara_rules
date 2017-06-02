rule office_macro
{
    meta:
        description = "M$ Office document containing a macro"
        thread_level = 1
        in_the_wild = true
    strings:
        $a = {d0 cf 11 e0}
        $b = {00 41 74 74 72 69 62 75 74 00}
    condition:
        $a at 0 and $b
}
