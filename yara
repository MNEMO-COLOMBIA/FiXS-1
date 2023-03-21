rule fixs_detection
{
    meta:
        author = "Fevar54"
        date = "21-03-2023"
        description = "Detecta la presencia de FiXS en el sistema"
    strings:
        $string1 = "fixs"
        $string2 = "fixsc"
        $string3 = "fixs.exe"
        $string4 = "fixs.dll"
        $string5 = "fixs.sys"
        $string6 = "fixsdrv.sys"
        $string7 = "fixsupdater.exe"
        $hash1 = "5e5c5d71a6c33dd6fddab6f4d6e1663f" //hash de fixs.exe
        $hash2 = "34a7f6bdc1e4de4c48715f3f7dd84f89" //hash de fixs.dll
        $hash3 = "ce283641cf78b2d47e2cbfd7cfa68713" //hash de fixs.sys
        $hash4 = "a1280f2747d6880d1e50c3d844dbb9fb" //hash de fixsdrv.sys
        $hash5 = "a8a874a136b53c24fa1e9e08930428a8" //hash de fixsupdater.exe
    condition:
        any of ($string*) or any of (hash*) or filesize < 200KB
}
