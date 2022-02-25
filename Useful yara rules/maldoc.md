
Description: CFBK / ole doc with vba

Ref: https://isc.sans.edu/diary/rss/28062
```
rule olevba {
    strings:
        $attribut_e = {00 41 74 74 72 69 62 75 74 00 65}
    condition:
        uint32be(0) == 0xD0CF11E0 and $attribut_e
}
```

Description: ooxml doc with vba

Ref: https://isc.sans.edu/diary/rss/28066
```
rule pkvbare {
    strings:
        $vbaprojectbin = /[a-zA-Z\/]*\/?vbaProject\.bin/
    condition:
        uint32be(0) == 0x504B0304 and
        $vbaprojectbin and
        for any i in (1..#vbaprojectbin): ((uint32be(@vbaprojectbin[i] - 30) == 0x504B0304) and
                                           (!vbaprojectbin[i] == uint16(@vbaprojectbin[i] - 4))
                                           )
}
```
