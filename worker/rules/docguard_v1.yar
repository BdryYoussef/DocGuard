rule DOCGUARD_EICAR_TEST
{
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}

rule DOCGUARD_POWERSHELL_ENCODED
{
    strings:
        $powershell = /powershell(\.exe)?/ nocase ascii wide
        $encoded_flag = /-(e|en|enc|enco|encod|encode|encodedcommand)[ \t]+[A-Za-z0-9+\/]{16,}={0,2}/ nocase ascii wide
    condition:
        $powershell and $encoded_flag
}

rule DOCGUARD_WSCRIPT_ENGINE_INVOCATION
{
    strings:
        $invocation = /(wscript|cscript)(\.exe)?[ \t]+\/\/e:(vbscript|jscript)[ \t]+[^\r\n]{0,120}\.(vbs|vbe|js|jse|wsf)/ nocase ascii wide
    condition:
        $invocation
}

rule DOCGUARD_CMD_CHAIN_INVOCATION
{
    strings:
        $invocation = /cmd(\.exe)?[ \t]+\/c[ \t]+[^\r\n]{0,120}(&&|\|\|)[ \t]*[A-Za-z0-9_%]/ nocase ascii wide
    condition:
        $invocation
}

rule DOCGUARD_MSHTA_SCRIPT_SCHEME
{
    strings:
        $invocation = /mshta(\.exe)?[ \t]+(javascript|vbscript):[^\r\n]{1,160}/ nocase ascii wide
    condition:
        $invocation
}

rule DOCGUARD_CERTUTIL_URLCACHE
{
    strings:
        $invocation = /certutil(\.exe)?[ \t]+[^\r\n]{0,80}-urlcache[ \t]+[^\r\n]{0,80}-split[ \t]+https?:\/\// nocase ascii wide
    condition:
        $invocation
}
