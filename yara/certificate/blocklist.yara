/*

 YARA doesn't perform complete digital certificate chain validation.

 This can cause unwanted matches for:
    a) Files that are signed with non-verified, self-issued, certificates
    b) Files that fail integrity validation due to checksum mismatch
    c) Files that have extra data appended after the certificate

 It's also worth mentioning that the timestamp value in the condition is only
 informative, since YARA doesn't extract timestamping certificate information.
 This information could be used in combination with other tools to reduce
 potential false positives.

 ReversingLabs recommends using Titanium platform for best results with certificate-based classifications.

 References on importance of certificate verification:
    https://blog.reversinglabs.com/blog/tampering-with-signed-objects-without-breaking-the-integrity-seal
    https://blog.reversinglabs.com/blog/breaking-the-windows-authenticode-security-model
    https://blog.reversinglabs.com/blog/breaking-uefi-firmware-authenticode-security-model
    https://blog.reversinglabs.com/blog/breaking-the-linux-authenticode-security-model

*/

import "pe"

rule cert_blocklist_05e2e6a4cd09ea54d665b075fe22A256 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "*.google.com" and
            pe.signatures[i].serial == "05:e2:e6:a4:cd:09:ea:54:d6:65:b0:75:fe:22:a2:56" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_77019a082385e4b73f569569c9f87bb8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AND LLC" and
            pe.signatures[i].serial == "77:01:9a:08:23:85:e4:b7:3f:56:95:69:c9:f8:7b:b8" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4f2ef29ca5f96e5777b82c62f34fd3a6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bit9, Inc" and
            pe.signatures[i].serial == "4f:2e:f2:9c:a5:f9:6e:57:77:b8:2c:62:f3:4f:d3:a6" and
            1342051200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7cc1db2ad0a290a4bfe7a5f336d6800c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bit9, Inc" and
            pe.signatures[i].serial == "7c:c1:db:2a:d0:a2:90:a4:bf:e7:a5:f3:36:d6:80:0c" and
            1342051200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_13c8351aece71c731158980f575f4133 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Opera Software ASA" and
            pe.signatures[i].serial == "13:c8:35:1a:ec:e7:1c:73:11:58:98:0f:57:5f:41:33" and
            1371513600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4531954f6265304055f66ce4f624f95b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IDAutomation.com" and
            pe.signatures[i].serial == "45:31:95:4f:62:65:30:40:55:f6:6c:e4:f6:24:f9:5b" and
            1384819199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0e808f231515bc519eea1a73cdf3266f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Careto malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TecSystem Ltd." and
            pe.signatures[i].serial == "0e:80:8f:23:15:15:bc:51:9e:ea:1a:73:cd:f3:26:6f" and
            1468799999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_36be4ad457f062fa77d87595b8ccc8cf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Careto malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TecSystem Ltd." and
            pe.signatures[i].serial == "36:be:4a:d4:57:f0:62:fa:77:d8:75:95:b8:cc:c8:cf" and
            1372377599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_75a38507bf403b152125b8f5ce1b97ad {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Zeus malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "isonet ag" and
            pe.signatures[i].serial == "75:a3:85:07:bf:40:3b:15:21:25:b8:f5:ce:1b:97:ad" and
            1395359999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4effa8b216e24b16202940c1bc2fa8a5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Henan Maijiamai Technology Co., Ltd." and
            pe.signatures[i].serial == "4e:ff:a8:b2:16:e2:4b:16:20:29:40:c1:bc:2f:a8:a5" and
            1404691199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_57d7153a89bbf4729be87f3c927043aa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, zhenganjun" and
            pe.signatures[i].serial == "57:d7:15:3a:89:bb:f4:72:9b:e8:7f:3c:92:70:43:aa" and
            1469059200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_028e1deccf93d38ecf396118dfe908b4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fortuna Games Co., Ltd." and
            pe.signatures[i].serial == "02:8e:1d:ec:cf:93:d3:8e:cf:39:61:18:df:e9:08:b4" and
            1392163199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_40575df73eaa1b6140c7ef62c08bf216 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dali Feifang Tech Co.,LTD." and
            pe.signatures[i].serial == "40:57:5d:f7:3e:aa:1b:61:40:c7:ef:62:c0:8b:f2:16" and
            1394063999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_049ce8c47f1f0e650cb086f0cfa7ca53 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Select'Assistance Pro" and
            pe.signatures[i].serial == "04:9c:e8:c4:7f:1f:0e:65:0c:b0:86:f0:cf:a7:ca:53" and
            1393804799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_29f42680e653cf8fafd0e935553f7e86 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Wemade Entertainment co.,Ltd" and
            pe.signatures[i].serial == "29:f4:26:80:e6:53:cf:8f:af:d0:e9:35:55:3f:7e:86" and
            1390175999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c15 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "William Richard John" and
            pe.signatures[i].serial == "0c:15" and
            1387324799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c0f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dmitry Vasilev" and
            pe.signatures[i].serial == "0c:0f" and
            1386719999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06a164ec5978497741ee6cec9966871b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JOHN WILLIAM RICHARD" and
            pe.signatures[i].serial == "06:a1:64:ec:59:78:49:77:41:ee:6c:ec:99:66:87:1b" and
            1385596799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1121ed568764e75be35574448feadefcd3bc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FRINORTE COMERCIO DE PECAS E SERVICOS LTDA - ME" and
            pe.signatures[i].serial == "11:21:ed:56:87:64:e7:5b:e3:55:74:44:8f:ea:de:fc:d3:bc" and
            1385337599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6ed2450ceac0f72e73fda1727e66e654 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hohhot Handing Trade and Business Co., Ltd." and
            pe.signatures[i].serial == "6e:d2:45:0c:ea:c0:f7:2e:73:fd:a1:72:7e:66:e6:54" and
            1376092799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_32665079c5a5854a6833623ca77ff5ac {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ohanae" and
            pe.signatures[i].serial == "32:66:50:79:c5:a5:85:4a:68:33:62:3c:a7:7f:f5:ac" and
            1381967999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_01a90094c83412c00cf98dd2eb0d7042 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FreeVox SA" and
            pe.signatures[i].serial == "01:a9:00:94:c8:34:12:c0:0c:f9:8d:d2:eb:0d:70:42" and
            1376956799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_55efe24b9674855baf16e67716479c71 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "S2BVISIO BELGIQUE SA" and
            pe.signatures[i].serial == "55:ef:e2:4b:96:74:85:5b:af:16:e6:77:16:47:9c:71" and
            1374451199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_094bf19d509d3074913995160b195b6c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Porral Twinware S.L.L." and
            pe.signatures[i].serial == "09:4b:f1:9d:50:9d:30:74:91:39:95:16:0b:19:5b:6c" and
            1373241599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a77cf3ba49b64e6cbe5fb4a6a6aacc6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "I.ST.SAN. Srl" and
            pe.signatures[i].serial == "0a:77:cf:3b:a4:9b:64:e6:cb:e5:fb:4a:6a:6a:ac:c6" and
            1371081599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1f4c22da1107d20c1eda04569d58e573 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PlanView, Inc." and
            pe.signatures[i].serial == "1f:4c:22:da:11:07:d2:0c:1e:da:04:56:9d:58:e5:73" and
            1366156799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4fe68d48634893d18de040d8f1c289d2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xinghua Yile Network Tech Co.,Ltd." and
            pe.signatures[i].serial == "4f:e6:8d:48:63:48:93:d1:8d:e0:40:d8:f1:c2:89:d2" and
            1371081600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6767def972d6ea702d8c8a53af1832d3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Guangzhou typical corner Network Technology Co., Ltd." and
            pe.signatures[i].serial == "67:67:de:f9:72:d6:ea:70:2d:8c:8a:53:af:18:32:d3" and
            1361750400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06477e3425f1448995ced539789e6842 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Karim Lammali" and
            pe.signatures[i].serial == "06:47:7e:34:25:f1:44:89:95:ce:d5:39:78:9e:68:42" and
            1334275199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0450a7c1c36951da09c8ad0e7f716ff2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PS Partnership" and
            pe.signatures[i].serial == "04:50:a7:c1:c3:69:51:da:09:c8:ad:0e:7f:71:6f:f2" and
            1362182399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0f9fbdab9b39645cf3211f87abb5ddb7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "The Motivo Group, Inc." and
            pe.signatures[i].serial == "0f:9f:bd:ab:9b:39:64:5c:f3:21:1f:87:ab:b5:dd:b7" and
            1361318399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4211d2e4f0e87127319302c55b85bcf2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "yinsheng xie" and
            pe.signatures[i].serial == "42:11:d2:e4:f0:e8:71:27:31:93:02:c5:5b:85:bc:f2" and
            1360713599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07b44cdbfffb78de05f4261672a67312 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Buster Paper Comercial Ltda" and
            pe.signatures[i].serial == "07:b4:4c:db:ff:fb:78:de:05:f4:26:16:72:a6:73:12" and
            1359503999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4f8b9a1ba5e60c754dbb40ddee7905e2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NOX Entertainment Co., Ltd" and
            pe.signatures[i].serial == "4f:8b:9a:1b:a5:e6:0c:75:4d:bb:40:dd:ee:79:05:e2" and
            1348617599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a389b95ee736dd13bc0ed743fd74d2f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BUSTER ASSISTENCIA TECNICA ELETRONICA LTDA - ME" and
            pe.signatures[i].serial == "0a:38:9b:95:ee:73:6d:d1:3b:c0:ed:74:3f:d7:4d:2f" and
            1351814399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1a3faaeb3a8b93b2394fec36345996e6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "salvatore macchiarella" and
            pe.signatures[i].serial == "1a:3f:aa:eb:3a:8b:93:b2:39:4f:ec:36:34:59:96:e6" and
            1468454400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1a35acce5b0c77206b1c3dc2a6a2417c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "cd ingegneri associati srl" and
            pe.signatures[i].serial == "1a:35:ac:ce:5b:0c:77:20:6b:1c:3d:c2:a6:a2:41:7c" and
            1166054399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6eb40ea11eaac847b050de9b59e25bdc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "My Free Internet Update" and
            pe.signatures[i].serial == "6e:b4:0e:a1:1e:aa:c8:47:b0:50:de:9b:59:e2:5b:dc" and
            1062201599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6724340ddbc7252f7fb714b812a5c04d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "YNK JAPAN Inc" and
            pe.signatures[i].serial == "67:24:34:0d:db:c7:25:2f:7f:b7:14:b8:12:a5:c0:4d" and
            1306195199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0813ee9b7b9d7c46001d6bc8784df1dd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Les Garcons s'habillent" and
            pe.signatures[i].serial == "08:13:ee:9b:7b:9d:7c:46:00:1d:6b:c8:78:4d:f1:dd" and
            1334707199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_530591c61b5e1212f659138b7cea0a97 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\x97\\xA5\\xE7\\x85\\xA7\\xE5\\xB3\\xB0\\xE5\\xB7\\x9D\\xE5\\x9B\\xBD\\xE9\\x99\\x85\\xE7\\x9F\\xBF\\xE4\\xB8\\x9A\\xE8\\xB4\\xB8\\xE6\\x98\\x93\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "53:05:91:c6:1b:5e:12:12:f6:59:13:8b:7c:ea:0a:97" and
            1403654399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07270ff9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Cyber CA" and
            pe.signatures[i].serial == "07:27:0f:f9" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0727100d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Cyber CA" and
            pe.signatures[i].serial == "07:27:10:0d" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07271003 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Cyber CA" and
            pe.signatures[i].serial == "07:27:10:03" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_013134bf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar PKIoverheid CA Organisatie - G2" and
            pe.signatures[i].serial == "01:31:34:bf" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_01314476 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar PKIoverheid CA Overheid" and
            pe.signatures[i].serial == "01:31:44:76" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_013169b0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar PKIoverheid CA Overheid en Bedrijven" and
            pe.signatures[i].serial == "01:31:69:b0" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c76da9c910c4e2c9efe15d058933c4c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Root CA" and
            pe.signatures[i].serial == "0c:76:da:9c:91:0c:4e:2c:9e:fe:15:d0:58:93:3c:4c" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_469c2caf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Root CA" and
            pe.signatures[i].serial == "46:9c:2c:af" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_469c3cc9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Root CA" and
            pe.signatures[i].serial == "46:9c:3c:c9" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a82bd1e144e8814d75b1a5527bebf3e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Root CA G2" and
            pe.signatures[i].serial == "0a:82:bd:1e:14:4e:88:14:d7:5b:1a:55:27:be:bf:3e" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_469c2cb0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DigiNotar Services 1024 CA" and
            pe.signatures[i].serial == "46:9c:2c:b0" and
            1308182400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4c0e636a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digisign Server ID - (Enrich)" and
            pe.signatures[i].serial == "4c:0e:63:6a" and
            1320191999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_072714a9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digisign Server ID (Enrich)" and
            pe.signatures[i].serial == "07:27:14:a9" and
            1320191999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_00d8f35f4eb7872b2dab0692e315382fb0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "global trustee" and (
                pe.signatures[i].serial == "00:d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0" or
                pe.signatures[i].serial == "d8:f3:5f:4e:b7:87:2b:2d:ab:06:92:e3:15:38:2f:b0"
            ) and
            1300060800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_750e40ff97f047edf556c7084eb1abfd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Corporation" and
            pe.signatures[i].serial == "75:0e:40:ff:97:f0:47:ed:f5:56:c7:08:4e:b1:ab:fd" and
            980899199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1b5190f73724399c9254cd424637996a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Corporation" and
            pe.signatures[i].serial == "1b:51:90:f7:37:24:39:9c:92:54:cd:42:46:37:99:6a" and
            980812799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_00ebaa11d62e2481081820 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Enforced Licensing Intermediate PCA" and (
                pe.signatures[i].serial == "00:eb:aa:11:d6:2e:24:81:08:18:20" or
                pe.signatures[i].serial == "eb:aa:11:d6:2e:24:81:08:18:20"
            )
        )
}

rule cert_blocklist_3aab11dee52f1b19d056 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Enforced Licensing Intermediate PCA" and
            pe.signatures[i].serial == "3a:ab:11:de:e5:2f:1b:19:d0:56"
        )
}

rule cert_blocklist_6102b01900000000002f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Microsoft Enforced Licensing Registration Authority CA (SHA1)" and
            pe.signatures[i].serial == "61:02:b0:19:00:00:00:00:00:2f"
        )
}

rule cert_blocklist_01e2b4f759811c64379fca0be76d2dce {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sony Pictures Entertainment Inc." and
            pe.signatures[i].serial == "01:e2:b4:f7:59:81:1c:64:37:9f:ca:0b:e7:6d:2d:ce" and
            1417651200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03e5a010b05c9287f823c2585f547b80 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MOCOMSYS INC" and
            pe.signatures[i].serial == "03:e5:a0:10:b0:5c:92:87:f8:23:c2:58:5f:54:7b:80" and
            1385423999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fe7df6c4b9a33b83d04e23e98a77cce {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PIXELPLUS CO., LTD." and
            pe.signatures[i].serial == "0f:e7:df:6c:4b:9a:33:b8:3d:04:e2:3e:98:a7:7c:ce" and
            1396310399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_065569a3e261409128a40affa90d6d10 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Police Mutual Aid Association" and
            pe.signatures[i].serial == "06:55:69:a3:e2:61:40:91:28:a4:0a:ff:a9:0d:6d:10" and
            1381795199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0979616733e062c544df0abd315e3b92 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jessica Karam" and
            pe.signatures[i].serial == "09:79:61:67:33:e0:62:c5:44:df:0a:bd:31:5e:3b:92" and
            1408319999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7d3250b27e0547c77307030491b42802 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Banco do Brasil S.A." and
            pe.signatures[i].serial == "7d:32:50:b2:7e:05:47:c7:73:07:03:04:91:b4:28:02" and
            1412207999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_00d1836bd37c331a67 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MINDSTORM LLC" and (
                pe.signatures[i].serial == "00:d1:83:6b:d3:7c:33:1a:67" or
                pe.signatures[i].serial == "d1:83:6b:d3:7c:33:1a:67"
            ) and
            1422835199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2ca028d1a4de0eb743135edecf74d7af {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "2c:a0:28:d1:a4:de:0e:b7:43:13:5e:de:cf:74:d7:af" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_dbb14dcf973eada14ece7ea79c895c11 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "db:b1:4d:cf:97:3e:ad:a1:4e:ce:7e:a7:9c:89:5c:11" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f8c2239de3977b8d4a3dcbedc9031a51 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "f8:c2:23:9d:e3:97:7b:8d:4a:3d:cb:ed:c9:03:1a:51" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_caad8222705d3fb3430e114a31c8c6a4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "ca:ad:82:22:70:5d:3f:b3:43:0e:11:4a:31:c8:c6:a4" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b191812516e6618d49e6ccf5e63dc343 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "b1:91:81:25:16:e6:61:8d:49:e6:cc:f5:e6:3d:c3:43" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4ba7fb8ee1deff8f4a1525e1e0580057 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "4b:a7:fb:8e:e1:de:ff:8f:4a:15:25:e1:e0:58:00:57" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2df9f7eb6cdc5ca243b33122e3941e25 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "2d:f9:f7:eb:6c:dc:5c:a2:43:b3:31:22:e3:94:1e:25" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_58a541d50f9e2fab4380c6a2ed433b82 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "58:a5:41:d5:0f:9e:2f:ab:43:80:c6:a2:ed:43:3b:82" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5f273626859ae4bc4becbbeb71e2ab2d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "5f:27:36:26:85:9a:e4:bc:4b:ec:bb:eb:71:e2:ab:2d" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b1ad46ce4db160b348c24f66c9663178 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Adobe Systems" and
            pe.signatures[i].serial == "b1:ad:46:ce:4d:b1:60:b3:48:c2:4f:66:c9:66:31:78" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_256541e204619033f8b09f9eb7c88ef8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HON HAI PRECISION INDUSTRY CO. LTD." and
            pe.signatures[i].serial == "25:65:41:e2:04:61:90:33:f8:b0:9f:9e:b7:c8:8e:f8" and
            1424303999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_00e8cc18cf100b6b27443ef26319398734 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Syngenta" and (
                pe.signatures[i].serial == "00:e8:cc:18:cf:10:0b:6b:27:44:3e:f2:63:19:39:87:34" or
                pe.signatures[i].serial == "e8:cc:18:cf:10:0b:6b:27:44:3e:f2:63:19:39:87:34"
            ) and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_62af28a7657ba8ab10fa8e2d47250c69 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AFINA Fintek" and
            pe.signatures[i].serial == "62:af:28:a7:65:7b:a8:ab:10:fa:8e:2d:47:25:0c:69" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04c8eca7243208a110dea926c7ad89ce {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, SINGH ADITYA" and
            pe.signatures[i].serial == "04:c8:ec:a7:24:32:08:a1:10:de:a9:26:c7:ad:89:ce" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_157c3a4a6bcf35cf8453e6b6c0072e1d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Favorite-III" and
            pe.signatures[i].serial == "15:7c:3a:4a:6b:cf:35:cf:84:53:e6:b6:c0:07:2e:1d" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04422f12037bc2032521dbb6ae02ea0e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, Muhammad Lee" and
            pe.signatures[i].serial == "04:42:2f:12:03:7b:c2:03:25:21:db:b6:ae:02:ea:0e" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_65eae6c98111dc40bf4f962bf27227f2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, BHARATH KUCHANGI" and
            pe.signatures[i].serial == "65:ea:e6:c9:81:11:dc:40:bf:4f:96:2b:f2:72:27:f2" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_12d5a4b29fe6156d4195fba55ae0d9a9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, Marc Chapon" and
            pe.signatures[i].serial == "12:d5:a4:b2:9f:e6:15:6d:41:95:fb:a5:5a:e0:d9:a9" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0087d60d1e2b9374eb7a735dce4bbdae56 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing GovRAT malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMO-K Limited Liability Company" and (
                pe.signatures[i].serial == "00:87:d6:0d:1e:2b:93:74:eb:7a:73:5d:ce:4b:bd:ae:56" or
                pe.signatures[i].serial == "87:d6:0d:1e:2b:93:74:eb:7a:73:5d:ce:4b:bd:ae:56"
            ) and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0860c8a7ed18c3f030a32722fd2b220c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, Tony Yeh" and
            pe.signatures[i].serial == "08:60:c8:a7:ed:18:c3:f0:30:a3:27:22:fd:2b:22:0c" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2fdadd0740572270203f8138692c4a83 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, William Zoltan" and
            pe.signatures[i].serial == "2f:da:dd:07:40:57:22:70:20:3f:81:38:69:2c:4a:83" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4fc13d6220c629043a26f81b1cad72d8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, meicun ge" and
            pe.signatures[i].serial == "4f:c1:3d:62:20:c6:29:04:3a:26:f8:1b:1c:ad:72:d8" and
            1404172799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3457a918c6d3701b2eaca6a92474a7cc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KONSALTING PLUS OOO" and
            pe.signatures[i].serial == "34:57:a9:18:c6:d3:70:1b:2e:ac:a6:a9:24:74:a7:cc" and
            1432252799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_621ed8265b0ad872d9f4b4ed6d560513 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fan Li" and
            pe.signatures[i].serial == "62:1e:d8:26:5b:0a:d8:72:d9:f4:b4:ed:6d:56:05:13" and
            1413183357 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_56e22b992b4c7f1afeac1d63b492bf54 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, Hetem Ramadani" and
            pe.signatures[i].serial == "56:e2:2b:99:2b:4c:7f:1a:fe:ac:1d:63:b4:92:bf:54" and
            1435622399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3bc3bae4118d46f3fdd9beeeab749fee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\x9D\\x8E\\xE9\\x9B\\xAA\\xE6\\xA2\\x85" and
            pe.signatures[i].serial == "3b:c3:ba:e4:11:8d:46:f3:fd:d9:be:ee:ab:74:9f:ee" and
            1442275199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0f0449f7691e5b4c8e74e71cae822179 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SBO INVEST" and
            pe.signatures[i].serial == "0f:04:49:f7:69:1e:5b:4c:8e:74:e7:1c:ae:82:21:79" and
            1432079999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_43db4448d870d7bdc275f36a01fba36f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3-T TOV" and
            pe.signatures[i].serial == "43:db:44:48:d8:70:d7:bd:c2:75:f3:6a:01:fb:a3:6f" and
            1436227199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2880a7f7ff2d334aa08744a8754fab2c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Garena Online Pte Ltd" and
            pe.signatures[i].serial == "28:80:a7:f7:ff:2d:33:4a:a0:87:44:a8:75:4f:ab:2c" and
            1393891199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0492f5c18e26fa0cd7e15067674aff1c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ghada Saffarini" and
            pe.signatures[i].serial == "04:92:f5:c1:8e:26:fa:0c:d7:e1:50:67:67:4a:ff:1c" and
            1445990399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6aa668cd6a9de1fdd476ea8225326937 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BSCP LIMITED" and
            pe.signatures[i].serial == "6a:a6:68:cd:6a:9d:e1:fd:d4:76:ea:82:25:32:69:37" and
            1441583999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1cb06dccb482255728671ea12ac41620 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fangzhen Li" and
            pe.signatures[i].serial == "1c:b0:6d:cc:b4:82:25:57:28:67:1e:a1:2a:c4:16:20" and
            1445126399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_370c2467c41d6019bbecd72e00c5d73d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UNINFO SISTEMAS LTDA ME" and
            pe.signatures[i].serial == "37:0c:24:67:c4:1d:60:19:bb:ec:d7:2e:00:c5:d7:3d" and
            1445299199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5067339614c5cc219c489d40420f3bf9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "D-LINK CORPORATION" and
            pe.signatures[i].serial == "50:67:33:96:14:c5:cc:21:9c:48:9d:40:42:0f:3b:f9" and
            1441238400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6e32531ae83992f0573120a5e78de271 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3 AM CHP" and
            pe.signatures[i].serial == "6e:32:53:1a:e8:39:92:f0:57:31:20:a5:e7:8d:e2:71" and
            1451606399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6967a89bcf6efef160aaeebbff376c0a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Chang Yucheng" and
            pe.signatures[i].serial == "69:67:a8:9b:cf:6e:fe:f1:60:aa:ee:bb:ff:37:6c:0a" and
            1451174399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7473d95405d2b0b3a8f28785ce6e74ca {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dmitrij Emelyanov" and
            pe.signatures[i].serial == "74:73:d9:54:05:d2:b0:b3:a8:f2:87:85:ce:6e:74:ca" and
            1453939199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04f380f97579f1702a85e0169bbdfd78 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GRANIFLOR" and
            pe.signatures[i].serial == "04:f3:80:f9:75:79:f1:70:2a:85:e0:16:9b:bd:fd:78" and
            1454889599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04d6b8cc6dce353fcf3ae8a532be7255 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MADERA" and
            pe.signatures[i].serial == "04:d6:b8:cc:6d:ce:35:3f:cf:3a:e8:a5:32:be:72:55" and
            1451692799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_191322a00200f793 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PRABHAKAR NARAYAN" and
            pe.signatures[i].serial == "19:13:22:a0:02:00:f7:93" and
            1442966399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_451c9d0b413e6e8df175 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PRASAD UPENDRA" and
            pe.signatures[i].serial == "45:1c:9d:0b:41:3e:6e:8d:f1:75" and
            1442275199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03943858218f35adb7073a6027555621 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RuN APps FOrEver lld" and
            pe.signatures[i].serial == "03:94:38:58:21:8f:35:ad:b7:07:3a:60:27:55:56:21" and
            1480550399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_09813ee7318452c28a1f6426d1cee12d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Saly Younes" and
            pe.signatures[i].serial == "09:81:3e:e7:31:84:52:c2:8a:1f:64:26:d1:ce:e1:2d" and
            1455667199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_476bf24a4b1e9f4bc2a61b152115e1fe {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Wemade Entertainment co.,Ltd" and
            pe.signatures[i].serial == "47:6b:f2:4a:4b:1e:9f:4b:c2:a6:1b:15:21:15:e1:fe" and
            1414454399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7bd55818c5971b63dc45cf57cbeb950b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "XL Games Co.,Ltd." and
            pe.signatures[i].serial == "7b:d5:58:18:c5:97:1b:63:dc:45:cf:57:cb:eb:95:0b" and
            1371513599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4c0b2e9d2ef909d15270d4dd7fa5a4a5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fuqing Dawu Technology Co.,Ltd." and
            pe.signatures[i].serial == "4c:0b:2e:9d:2e:f9:09:d1:52:70:d4:dd:7f:a5:a4:a5" and
            1372118399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5e3d76dc7e273e2f313fc0775847a2a2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula and Derusbi malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NexG" and
            pe.signatures[i].serial == "5e:3d:76:dc:7e:27:3e:2f:31:3f:c0:77:58:47:a2:a2" and
            1372723199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_47d5d5372bcb1562b4c9f4c2bdf13587 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DTOPTOOLZ Co.,Ltd." and
            pe.signatures[i].serial == "47:d5:d5:37:2b:cb:15:62:b4:c9:f4:c2:bd:f1:35:87" and
            1400803199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3ac10e68f1ce519e84ddcd28b11fa542 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "U-Tech IT service" and
            pe.signatures[i].serial == "3a:c1:0e:68:f1:ce:51:9e:84:dd:cd:28:b1:1f:a5:42" and
            1420156799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_31062e483e0106b18c982f0053185c36 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MICRO DIGITAL INC." and
            pe.signatures[i].serial == "31:06:2e:48:3e:01:06:b1:8c:98:2f:00:53:18:5c:36" and
            1332287999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_20d0ee42fc901e6b3a8fefe8c1e6087a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing Sakula malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SJ SYSTEM" and
            pe.signatures[i].serial == "20:d0:ee:42:fc:90:1e:6b:3a:8f:ef:e8:c1:e6:08:7a" and
            1391299199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_127251b32b9a50bd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing OSX DokSpy backdoor."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Developer ID Application: Edouard Roulet (W7J9LRHXTG)" and
            pe.signatures[i].serial == "12:72:51:b3:2b:9a:50:bd" and
            1493769599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_48cad4e6966e22d6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing OSX DokSpy backdoor."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Developer ID Application: Seven Muller (FUP9692NN6)" and
            pe.signatures[i].serial == "48:ca:d4:e6:96:6e:22:d6" and
            1492732799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5e15205f180442cc6c3c0f03e1a33d9f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ziber Ltd" and
            pe.signatures[i].serial == "5e:15:20:5f:18:04:42:cc:6c:3c:0f:03:e1:a3:3d:9f" and
            1498607999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4c8e3b1613f73542f7106f272094eb23 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ADD Audit" and
            pe.signatures[i].serial == "4c:8e:3b:16:13:f7:35:42:f7:10:6f:27:20:94:eb:23" and
            1472687999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2ce2bd0ad3cfde9ea73eec7ca30400da {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Media Lid" and
            pe.signatures[i].serial == "2c:e2:bd:0a:d3:cf:de:9e:a7:3e:ec:7c:a3:04:00:da" and
            1493337599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fbc30db127a536c34d7a0fa81b48193 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Megabit, OOO" and
            pe.signatures[i].serial == "0f:bc:30:db:12:7a:53:6c:34:d7:a0:fa:81:b4:81:93" and
            1466121599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08448bd6ee9105ae31228ea5fe496f63 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Raffaele Carnacina" and
            pe.signatures[i].serial == "08:44:8b:d6:ee:91:05:ae:31:22:8e:a5:fe:49:6f:63" and
            1445212799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_02f17566ef568dc06c9a379ea2f4faea {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "The digital certificate has leaked."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VALERIANO BEDESCHI" and
            pe.signatures[i].serial == "02:f1:75:66:ef:56:8d:c0:6c:9a:37:9e:a2:f4:fa:ea" and
            1441324799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7d824ba1f7f730319c50d64c9a7ed507 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "joaweb" and
            pe.signatures[i].serial == "7d:82:4b:a1:f7:f7:30:31:9c:50:d6:4c:9a:7e:d5:07" and
            1238025599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_77a64759f12766e363d779998c71bdc9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Gigabit Times Technology Co., Ltd" and
            pe.signatures[i].serial == "77:a6:47:59:f1:27:66:e3:63:d7:79:99:8c:71:bd:c9" and
            1301011199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0b0d17ec1449b4b2d38fcb0f20fbcd3a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WEBPIC DESENVOLVIMENTO DE SOFTWARE LTDA" and
            pe.signatures[i].serial == "0b:0d:17:ec:14:49:b4:b2:d3:8f:cb:0f:20:fb:cd:3a" and
            1394150399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fe9404dc73cf1c2ba1450b8398305557 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x8E\\xA6\\xE9\\x97\\xA8\\xE7\\xBF\\x94\\xE9\\x80\\x9A\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE5\\x88\\x86\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:fe:94:04:dc:73:cf:1c:2b:a1:45:0b:83:98:30:55:57" or
                pe.signatures[i].serial == "fe:94:04:dc:73:cf:1c:2b:a1:45:0b:83:98:30:55:57"
            ) and
            1287360000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1cb2d523a6bf7a066642c578de1c9be4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shenzhen Hua\\xE2\\x80\\x99nan Xingfa Electronic Equipment Firm" and
            pe.signatures[i].serial == "1c:b2:d5:23:a6:bf:7a:06:66:42:c5:78:de:1c:9b:e4" and
            1400889599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3a6ccabb1c62f3be3eb03869fa43dc4a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\xB8\\xB8\\xE5\\xB7\\x9E\\xE9\\xAA\\x8F\\xE6\\x99\\xAF\\xE9\\x80\\x9A\\xE8\\x81\\x94\\xE6\\x95\\xB0\\xE5\\xAD\\x97\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "3a:6c:ca:bb:1c:62:f3:be:3e:b0:38:69:fa:43:dc:4a" and
            1259798399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_864196f01971dbec7002b48642a7013a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WLE DESENVOLVIMENTO DE SOFTWARE E ASSESSORIA LTDA EPP" and (
                pe.signatures[i].serial == "00:86:41:96:f0:19:71:db:ec:70:02:b4:86:42:a7:01:3a" or
                pe.signatures[i].serial == "86:41:96:f0:19:71:db:ec:70:02:b4:86:42:a7:01:3a"
            ) and
            1384300799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4fda1e121b61adeca936a6aebe079303 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Laizhou wanlei stone Co., LTD" and
            pe.signatures[i].serial == "4f:da:1e:12:1b:61:ad:ec:a9:36:a6:ae:be:07:93:03" and
            1310687999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03866deb183abfbf4ff458d4de7bd73a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE9\\x87\\x8D\\xE5\\xBA\\x86\\xE8\\xAF\\x9D\\xE8\\xAF\\xAD\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "03:86:6d:eb:18:3a:bf:bf:4f:f4:58:d4:de:7b:d7:3a" and
            1371772799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1be41b34127ca9e6270830d2070db426 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE8\\x80\\x98\\xE5\\x8D\\x87\\xE5\\xA4\\xA9\\xE4\\xB8\\x8B\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "1b:e4:1b:34:12:7c:a9:e6:27:08:30:d2:07:0d:b4:26" and
            1352764799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9b108b8a1daa0d5581f59fcee0447901 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CharacTell Ltd" and (
                pe.signatures[i].serial == "00:9b:10:8b:8a:1d:aa:0d:55:81:f5:9f:ce:e0:44:79:01" or
                pe.signatures[i].serial == "9b:10:8b:8a:1d:aa:0d:55:81:f5:9f:ce:e0:44:79:01"
            ) and
            1380671999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5f8203c430fc7db4e61f6684f6829ffc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Haivision Network Video" and
            pe.signatures[i].serial == "5f:82:03:c4:30:fc:7d:b4:e6:1f:66:84:f6:82:9f:fc" and
            1382572799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6b6daef5be29f20ddce4b0f5e9fa6ea5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Calibration Consultants" and
            pe.signatures[i].serial == "6b:6d:ae:f5:be:29:f2:0d:dc:e4:b0:f5:e9:fa:6e:a5" and
            1280447999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_57d6dff1ef96f01b9430666b2733cc87 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Smart Plugin Ltda" and
            pe.signatures[i].serial == "57:d6:df:f1:ef:96:f0:1b:94:30:66:6b:27:33:cc:87" and
            1314575999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0166b65038d61e5435b48204cae4795a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TOLGA KAPLAN" and
            pe.signatures[i].serial == "01:66:b6:50:38:d6:1e:54:35:b4:82:04:ca:e4:79:5a" and
            1403999999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_784f226b45c3bd8e4089243d747d1f59 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FSPro Labs" and
            pe.signatures[i].serial == "78:4f:22:6b:45:c3:bd:8e:40:89:24:3d:74:7d:1f:59" and
            1242777599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_11690f05604445fae0de539eeeeec584 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tera information Technology co.Ltd" and
            pe.signatures[i].serial == "11:69:0f:05:60:44:45:fa:e0:de:53:9e:ee:ee:c5:84" and
            1294703999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aa146bff4b832bdbfe30b84580356763 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yancheng Peoples Information Technology Service Co., Ltd" and (
                pe.signatures[i].serial == "00:aa:14:6b:ff:4b:83:2b:db:fe:30:b8:45:80:35:67:63" or
                pe.signatures[i].serial == "aa:14:6b:ff:4b:83:2b:db:fe:30:b8:45:80:35:67:63"
            ) and
            1295481599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e86f46b60142092aae81b8f6fa3d9c7c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Syncode Sistemas e Tecnologia Ltda" and (
                pe.signatures[i].serial == "00:e8:6f:46:b6:01:42:09:2a:ae:81:b8:f6:fa:3d:9c:7c" or
                pe.signatures[i].serial == "e8:6f:46:b6:01:42:09:2a:ae:81:b8:f6:fa:3d:9c:7c"
            ) and
            1373932799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1a0fd2a4ef4c2a36ab9c5e8f792a35e2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x8C\\x97\\xE4\\xBA\\xAC\\xE9\\x87\\x91\\xE5\\x88\\xA9\\xE5\\xAE\\x8F\\xE6\\x98\\x8C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "1a:0f:d2:a4:ef:4c:2a:36:ab:9c:5e:8f:79:2a:35:e2" and
            1389311999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_53bb753b79a99e61a6e822ac52460c70 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xEB\\x8D\\xB0\\xEC\\x8A\\xA4\\xED\\x81\\xAC\\xED\\x83\\x91\\xEC\\x95\\x84\\xEC\\x9D\\xB4\\xEC\\xBD\\x98" and
            pe.signatures[i].serial == "53:bb:75:3b:79:a9:9e:61:a6:e8:22:ac:52:46:0c:70" and
            1400543999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_83f68fc6834bf8bd2c801a2d1f1acc76 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Helpful Technologies, Inc" and (
                pe.signatures[i].serial == "00:83:f6:8f:c6:83:4b:f8:bd:2c:80:1a:2d:1f:1a:cc:76" or
                pe.signatures[i].serial == "83:f6:8f:c6:83:4b:f8:bd:2c:80:1a:2d:1f:1a:cc:76"
            ) and
            1407715199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f385e765acfb95605c9b35ca4c32f80e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CWI SOFTWARE LTDA" and (
                pe.signatures[i].serial == "00:f3:85:e7:65:ac:fb:95:60:5c:9b:35:ca:4c:32:f8:0e" or
                pe.signatures[i].serial == "f3:85:e7:65:ac:fb:95:60:5c:9b:35:ca:4c:32:f8:0e"
            ) and
            1382313599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f62c9c4efc81caf0d5a2608009d48018 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x94\\x90\\xE5\\xB1\\xB1\\xE4\\xB8\\x87\\xE4\\xB8\\x9C\\xE6\\xB6\\xA6\\xE6\\x92\\xAD\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:f6:2c:9c:4e:fc:81:ca:f0:d5:a2:60:80:09:d4:80:18" or
                pe.signatures[i].serial == "f6:2c:9c:4e:fc:81:ca:f0:d5:a2:60:80:09:d4:80:18"
            ) and
            1292889599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cc8d902da36587c9b2113cd76c3c3f8d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE9\\x87\\x91\\xE4\\xBF\\x8A\\xE5\\x9D\\xA4\\xE8\\xAE\\xA1\\xE7\\xAE\\x97\\xE6\\x9C\\xBA\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x8D\\xE5\\x8A\\xA1\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:cc:8d:90:2d:a3:65:87:c9:b2:11:3c:d7:6c:3c:3f:8d" or
                pe.signatures[i].serial == "cc:8d:90:2d:a3:65:87:c9:b2:11:3c:d7:6c:3c:3f:8d"
            ) and
            1292544000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_328bdcc0f679c4649147fbb3eb0e9bc6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nooly Systems LTD" and
            pe.signatures[i].serial == "32:8b:dc:c0:f6:79:c4:64:91:47:fb:b3:eb:0e:9b:c6" and
            1204847999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5f78149eb4f75eb17404a8143aaeaed7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE5\\x9F\\x9F\\xE8\\x81\\x94\\xE8\\xBD\\xAF\\xE4\\xBB\\xB6\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "5f:78:14:9e:b4:f7:5e:b1:74:04:a8:14:3a:ae:ae:d7" and
            1303116124 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_629d120dd84f9c1688d4da40366fab7a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Delta Controls" and
            pe.signatures[i].serial == "62:9d:12:0d:d8:4f:9c:16:88:d4:da:40:36:6f:ab:7a" and
            1306799999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_039e5d0e3297f574db99e1d9503853d9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cigam Software Corporativo LTDA" and
            pe.signatures[i].serial == "03:9e:5d:0e:32:97:f5:74:db:99:e1:d9:50:38:53:d9" and
            1378079999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bc32bbe5bbb4f06f490c50651cd5da50 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Remedica Medical Education and Publishing Ltd" and (
                pe.signatures[i].serial == "00:bc:32:bb:e5:bb:b4:f0:6f:49:0c:50:65:1c:d5:da:50" or
                pe.signatures[i].serial == "bc:32:bb:e5:bb:b4:f0:6f:49:0c:50:65:1c:d5:da:50"
            ) and
            1387151999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3e1656dfcaacfed7c2d2564355698aa3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "John W.Richard" and
            pe.signatures[i].serial == "3e:16:56:df:ca:ac:fe:d7:c2:d2:56:43:55:69:8a:a3" and
            1385251199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4bf1d68e926e2dd8966008c44f95ea1c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Technical and Commercial Consulting Pvt. Ltd." and
            pe.signatures[i].serial == "4b:f1:d6:8e:92:6e:2d:d8:96:60:08:c4:4f:95:ea:1c" and
            1322092799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_149c12083c145e28155510cfc19db0fe {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3rd Eye Solutions Ltd" and
            pe.signatures[i].serial == "14:9c:12:08:3c:14:5e:28:15:55:10:cf:c1:9d:b0:fe" and
            1209340799 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_77e0117e8b2b8faa84bed961019d5ef8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Reiner Wodey Informationssysteme" and
            pe.signatures[i].serial == "77:e0:11:7e:8b:2b:8f:aa:84:be:d9:61:01:9d:5e:f8" and
            1383695999 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4f3feb4baf377aea90a463c5dee63884 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "F3D LIMITED" and
            pe.signatures[i].serial == "4f:3f:eb:4b:af:37:7a:ea:90:a4:63:c5:de:e6:38:84" and
            1526601599 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3d2580e89526f7852b570654efd9a8bf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing LockerGoga ransomware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MIKL LIMITED" and
            pe.signatures[i].serial == "3d:25:80:e8:95:26:f7:85:2b:57:06:54:ef:d9:a8:bf" and
            1529888400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fffe432a53ff03b9223f88be1b83d9d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing BabyShark malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EGIS Co., Ltd." and
            pe.signatures[i].serial == "0f:ff:e4:32:a5:3f:f0:3b:92:23:f8:8b:e1:b8:3d:9d" and
            1498524050 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_832e161aea5206d815f973e5a1feb3e7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing SeedLocker ransomware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Project NSRM Ltd" and (
                pe.signatures[i].serial == "00:83:2e:16:1a:ea:52:06:d8:15:f9:73:e5:a1:fe:b3:e7" or
                pe.signatures[i].serial == "83:2e:16:1a:ea:52:06:d8:15:f9:73:e5:a1:fe:b3:e7"
            ) and
            1549830060 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_09aecea45bfd40ce7d62d7d711916d7d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALINA LTD" and
            pe.signatures[i].serial == "09:ae:ce:a4:5b:fd:40:ce:7d:62:d7:d7:11:91:6d:7d" and
            1551052800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4ff4eda5fa641e70162713426401f438 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DUHANEY LIMITED" and
            pe.signatures[i].serial == "4f:f4:ed:a5:fa:64:1e:70:16:27:13:42:64:01:f4:38" and
            1555349604 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_067dffc5e3026eb4c62971c98ac8a900 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DVERI FADO, TOV" and
            pe.signatures[i].serial == "06:7d:ff:c5:e3:02:6e:b4:c6:29:71:c9:8a:c8:a9:00" and
            1552176000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b1da219688e51fd0bfac2c891d56cbb8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FIRNEEZ EUROPE LIMITED" and (
                pe.signatures[i].serial == "00:b1:da:21:96:88:e5:1f:d0:bf:ac:2c:89:1d:56:cb:b8" or
                pe.signatures[i].serial == "b1:da:21:96:88:e5:1f:d0:bf:ac:2c:89:1d:56:cb:b8"
            ) and
            1542931200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7289b0f9bd641e3e352dc3183f8de6be {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ICE ACTIVATION LIMITED" and
            pe.signatures[i].serial == "72:89:b0:f9:bd:64:1e:3e:35:2d:c3:18:3f:8d:e6:be" and
            1557933274 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fd7b7a8678a67181a54bc7499eba44da {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IMRAN IT SERVICES LTD" and (
                pe.signatures[i].serial == "00:fd:7b:7a:86:78:a6:71:81:a5:4b:c7:49:9e:ba:44:da" or
                pe.signatures[i].serial == "fd:7b:7a:86:78:a6:71:81:a5:4b:c7:49:9e:ba:44:da"
            ) and
            1548028800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ebbdd6cdeda40ca64513280ecd625c54 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IT PUT LIMITED" and (
                pe.signatures[i].serial == "00:eb:bd:d6:cd:ed:a4:0c:a6:45:13:28:0e:cd:62:5c:54" or
                pe.signatures[i].serial == "eb:bd:d6:cd:ed:a4:0c:a6:45:13:28:0e:cd:62:5c:54"
            ) and
            1549238400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_61da676c1dcfcf188276e2c70d68082e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "P2N ONLINE LTD" and
            pe.signatures[i].serial == "61:da:67:6c:1d:cf:cf:18:82:76:e2:c7:0d:68:08:2e" and
            1552723954 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_767436921b2698bd18400a24b01341b6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REBROSE LEISURE LIMITED" and
            pe.signatures[i].serial == "76:74:36:92:1b:26:98:bd:18:40:0a:24:b0:13:41:b6" and
            1556284480 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3e795531b3265510f935187eca59920a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "sasha catering ltd" and
            pe.signatures[i].serial == "3e:79:55:31:b3:26:55:10:f9:35:18:7e:ca:59:92:0a" and
            1557243644 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8f40b1485309a064a28b96bfa3f55f36 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Singh Agile Content Design Limited" and (
                pe.signatures[i].serial == "00:8f:40:b1:48:53:09:a0:64:a2:8b:96:bf:a3:f5:5f:36" or
                pe.signatures[i].serial == "8f:40:b1:48:53:09:a0:64:a2:8b:96:bf:a3:f5:5f:36"
            ) and
            1542585600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b2120facadbb92cc0a176759604c6a0f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLON LTD" and (
                pe.signatures[i].serial == "00:b2:12:0f:ac:ad:bb:92:cc:0a:17:67:59:60:4c:6a:0f" or
                pe.signatures[i].serial == "b2:12:0f:ac:ad:bb:92:cc:0a:17:67:59:60:4c:6a:0f"
            ) and
            1554249600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4f407eb50803845cc43937823e1344c0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLOW COOKED VENTURES LTD" and
            pe.signatures[i].serial == "4f:40:7e:b5:08:03:84:5c:c4:39:37:82:3e:13:44:c0" and
            1556555362 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6922bb5de88e4127e1ac6969e6a199f5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SMACHNA PLITKA, TOV" and
            pe.signatures[i].serial == "69:22:bb:5d:e8:8e:41:27:e1:ac:69:69:e6:a1:99:f5" and
            1552692162 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_73065efa163b7901fa1ccb0a54e80540 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SOVA CONSULTANCY LTD" and
            pe.signatures[i].serial == "73:06:5e:fa:16:3b:79:01:fa:1c:cb:0a:54:e8:05:40" and
            1548115200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4842afad00904ed8c98811e652ccb3b7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\"VERY EXCLUSIVE LTD\"" and
            pe.signatures[i].serial == "48:42:af:ad:00:90:4e:d8:c9:88:11:e6:52:cc:b3:b7" and
            1545177600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5a59a686b4a904d0fca07153ea6db6cc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABADAN PIZZA LTD" and
            pe.signatures[i].serial == "5a:59:a6:86:b4:a9:04:d0:fc:a0:71:53:ea:6d:b6:cc" and
            1563403380 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0b6d8152f4a06ba781c6677eea5ab74b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GLARYSOFT LTD" and
            pe.signatures[i].serial == "0b:6d:81:52:f4:a0:6b:a7:81:c6:67:7e:ea:5a:b7:4b" and
            1568246400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3ad60cea73e1dd1a3e6c02d9b339c380 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CUS Software GmbH" and
            pe.signatures[i].serial == "3a:d6:0c:ea:73:e1:dd:1a:3e:6c:02:d9:b3:39:c3:80" and
            1567036800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7df2dfed47c6fd6542131847cffbc102 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AFVIMPEX SRL" and
            pe.signatures[i].serial == "7d:f2:df:ed:47:c6:fd:65:42:13:18:47:cf:fb:c1:02" and
            1567036800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_74fedf0f8398060fa8378c6d174465c8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DOCS PTY LTD" and
            pe.signatures[i].serial == "74:fe:df:0f:83:98:06:0f:a8:37:8c:6d:17:44:65:c8" and
            1566172800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3bd6a5bba28e7c1ca44880159dace237 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TECHNO BEAVERS LIMITED" and
            pe.signatures[i].serial == "3b:d6:a5:bb:a2:8e:7c:1c:a4:48:80:15:9d:ac:e2:37" and
            1563408000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c04f8f1e00c69e96a51bf14aab1c6ae0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CHAIKA, TOV" and (
                pe.signatures[i].serial == "00:c0:4f:8f:1e:00:c6:9e:96:a5:1b:f1:4a:ab:1c:6a:e0" or
                pe.signatures[i].serial == "c0:4f:8f:1e:00:c6:9e:96:a5:1b:f1:4a:ab:1c:6a:e0"
            ) and
            1551398400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_23f537ce13c6cccdfd3f8ce81fb981cb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ISECURE GROUP PTY LTD" and
            pe.signatures[i].serial == "23:f5:37:ce:13:c6:cc:cd:fd:3f:8c:e8:1f:b9:81:cb" and
            1566086400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_73ecfdbb99aec176ddfcf7958d120e1a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MHOW PTY LTD" and
            pe.signatures[i].serial == "73:ec:fd:bb:99:ae:c1:76:dd:fc:f7:95:8d:12:0e:1a" and
            1566864000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_675129bb174a5b05e330cc09f8bbd70a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALEX & CO PTY LIMITED" and
            pe.signatures[i].serial == "67:51:29:bb:17:4a:5b:05:e3:30:cc:09:f8:bb:d7:0a" and
            1565568000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_de13fe2dbb8f890287e1780aff6ffd22 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LAST TIME PTY LTD" and
            pe.signatures[i].serial == "de:13:fe:2d:bb:8f:89:02:87:e1:78:0a:ff:6f:fd:22" and
            1566259200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_da000d18949c247d4ddfc2585cc8bd0f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PORT-SERVIS LTD" and (
                pe.signatures[i].serial == "00:da:00:0d:18:94:9c:24:7d:4d:df:c2:58:5c:c8:bd:0f" or
                pe.signatures[i].serial == "da:00:0d:18:94:9c:24:7d:4d:df:c2:58:5c:c8:bd:0f"
            ) and
            1564444800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06e842d3ea6249d783d6b55e29c060c7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PORT-SERVIS LTD, TOV" and
            pe.signatures[i].serial == "06:e8:42:d3:ea:62:49:d7:83:d6:b5:5e:29:c0:60:c7" and
            1565568000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06473c3c19d9e1a9429b58b6faec2967 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digital Leadership Solutions Limited" and
            pe.signatures[i].serial == "06:47:3c:3c:19:d9:e1:a9:42:9b:58:b6:fa:ec:29:67" and
            1581984001 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_39f56251df2088223cc03494084e6081 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Inter Med Pty. Ltd." and
            pe.signatures[i].serial == "39:f5:62:51:df:20:88:22:3c:c0:34:94:08:4e:60:81" and
            1583539200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1362e56d34dc7b501e17fa1ac3c3e3d9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO  \"Amaranth\"" and
            pe.signatures[i].serial == "13:62:e5:6d:34:dc:7b:50:1e:17:fa:1a:c3:c3:e3:d9" and
            1575936000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4b83593fc78d92cfaa9bdf3f97383964 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Kometa" and
            pe.signatures[i].serial == "4b:83:59:3f:c7:8d:92:cf:aa:9b:df:3f:97:38:39:64" and
            1579996800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c7505e7464e00ec1dccd8d1b466d15ff {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ltd. \"Eve Beauty\"" and (
                pe.signatures[i].serial == "00:c7:50:5e:74:64:e0:0e:c1:dc:cd:8d:1b:46:6d:15:ff" or
                pe.signatures[i].serial == "c7:50:5e:74:64:e0:0e:c1:dc:cd:8d:1b:46:6d:15:ff"
            ) and
            1583824676 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cbf91988fb83511de1b3a7a520712e9c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ltd. \"Eve Beauty\"" and (
                pe.signatures[i].serial == "00:cb:f9:19:88:fb:83:51:1d:e1:b3:a7:a5:20:71:2e:9c" or
                pe.signatures[i].serial == "cb:f9:19:88:fb:83:51:1d:e1:b3:a7:a5:20:71:2e:9c"
            ) and
            1578786662 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ce3675ae4abfe688870bcacb63060f4f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO \"MPS\"" and (
                pe.signatures[i].serial == "00:ce:36:75:ae:4a:bf:e6:88:87:0b:ca:cb:63:06:0f:4f" or
                pe.signatures[i].serial == "ce:36:75:ae:4a:bf:e6:88:87:0b:ca:cb:63:06:0f:4f"
            ) and
            1582675200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9813229efe0046d23542cc7569d5a403 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO \"MPS\"" and (
                pe.signatures[i].serial == "00:98:13:22:9e:fe:00:46:d2:35:42:cc:75:69:d5:a4:03" or
                pe.signatures[i].serial == "98:13:22:9e:fe:00:46:d2:35:42:cc:75:69:d5:a4:03"
            ) and
            1575849600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_86e5a9b9e89e5075c475006d0ca03832 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BlueMarble GmbH" and (
                pe.signatures[i].serial == "00:86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32" or
                pe.signatures[i].serial == "86:e5:a9:b9:e8:9e:50:75:c4:75:00:6d:0c:a0:38:32"
            ) and
            1574791194 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_075dca9ca84b93e8a89b775128f90302 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UAB GT-servis" and
            pe.signatures[i].serial == "07:5d:ca:9c:a8:4b:93:e8:a8:9b:77:51:28:f9:03:02" and
            1579305601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0ddce8cdc91b5b649bb4b45ffbba6c6c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLIM DOG GROUP SP Z O O" and
            pe.signatures[i].serial == "0d:dc:e8:cd:c9:1b:5b:64:9b:b4:b4:5f:fb:ba:6c:6c" and
            1580722435 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9bd614d5869bb66c96b67e154d517384 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\"CENTR MBP\"" and (
                pe.signatures[i].serial == "00:9b:d6:14:d5:86:9b:b6:6c:96:b6:7e:15:4d:51:73:84" or
                pe.signatures[i].serial == "9b:d6:14:d5:86:9b:b6:6c:96:b6:7e:15:4d:51:73:84"
            ) and
            1581618180 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_540cea639d5d48669b7f2f64 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CENTR MBP LLC" and
            pe.signatures[i].serial == "54:0c:ea:63:9d:5d:48:66:9b:7f:2f:64" and
            1570871755 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03a7748a4355020a652466b5e02e07de {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Teleneras MB" and
            pe.signatures[i].serial == "03:a7:74:8a:43:55:02:0a:65:24:66:b5:e0:2e:07:de" and
            1575244801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b881a72d4117bbc38b81d3c65c792c1a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Red GmbH" and (
                pe.signatures[i].serial == "00:b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a" or
                pe.signatures[i].serial == "b8:81:a7:2d:41:17:bb:c3:8b:81:d3:c6:5c:79:2c:1a"
            ) and
            1581936420 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08653ef2ed9e6ebb56ffa7e93f963235 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Haw Farm LIMITED" and
            pe.signatures[i].serial == "08:65:3e:f2:ed:9e:6e:bb:56:ff:a7:e9:3f:96:32:35" and
            1581465601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9c4816d900a6ecdbe54adf72b19ebcf5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Datamingo Limited" and (
                pe.signatures[i].serial == "00:9c:48:16:d9:00:a6:ec:db:e5:4a:df:72:b1:9e:bc:f5" or
                pe.signatures[i].serial == "9c:48:16:d9:00:a6:ec:db:e5:4a:df:72:b1:9e:bc:f5"
            ) and
            1557187200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_269174f9fe7c6ed4e1d19b26c3f5b35f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GO ONLINE d.o.o." and
            pe.signatures[i].serial == "26:91:74:f9:fe:7c:6e:d4:e1:d1:9b:26:c3:f5:b3:5f" and
            1586386919 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_523fb4036368dc26192d68827f2d889b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO MEDUZA SERVICE GROUP" and
            pe.signatures[i].serial == "52:3f:b4:03:63:68:dc:26:19:2d:68:82:7f:2d:88:9b" and
            1586847880 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_84f842f6d33cd2f25b88dd1710e21137 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DataNext s.r.o." and (
                pe.signatures[i].serial == "00:84:f8:42:f6:d3:3c:d2:f2:5b:88:dd:17:10:e2:11:37" or
                pe.signatures[i].serial == "84:f8:42:f6:d3:3c:d2:f2:5b:88:dd:17:10:e2:11:37"
            ) and
            1586775720 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4fbcaa289ba925b4e247809b6b028202 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kimjac ApS" and
            pe.signatures[i].serial == "4f:bc:aa:28:9b:a9:25:b4:e2:47:80:9b:6b:02:82:02" and
            1588227220 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1f2e8effbb08c7dbcc7a7f2d835457b5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RTI, OOO" and
            pe.signatures[i].serial == "1f:2e:8e:ff:bb:08:c7:db:cc:7a:7f:2d:83:54:57:b5" and
            1581382360 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aeba4c39306fdd022849867801645814 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SK AI MAS GmbH" and (
                pe.signatures[i].serial == "00:ae:ba:4c:39:30:6f:dd:02:28:49:86:78:01:64:58:14" or
                pe.signatures[i].serial == "ae:ba:4c:39:30:6f:dd:02:28:49:86:78:01:64:58:14"
            ) and
            1579478400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_028d50ae0c554b49148e82db5b1c2699 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VAS CO PTY LTD" and
            pe.signatures[i].serial == "02:8d:50:ae:0c:55:4b:49:14:8e:82:db:5b:1c:26:99" and
            1579478400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_684f478c7259dde0cfe2260112ca9846 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC \"IP EM\"" and
            pe.signatures[i].serial == "68:4f:47:8c:72:59:dd:e0:cf:e2:26:01:12:ca:98:46" and
            1584981648 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0b7c32208a954a483dd102e1be094867 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Win Sp Z O O" and
            pe.signatures[i].serial == "0b:7c:32:20:8a:95:4a:48:3d:d1:02:e1:be:09:48:67" and
            1583884800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3e72daf2b9a4449e946009e5084a8e76 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Infoteh63" and
            pe.signatures[i].serial == "3e:72:da:f2:b9:a4:44:9e:94:60:09:e5:08:4a:8e:76" and
            1591787570 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_11edd343e21c36ac985555d85c16135f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pribyl Handels GmbH" and
            pe.signatures[i].serial == "11:ed:d3:43:e2:1c:36:ac:98:55:55:d8:5c:16:13:5f" and
            1589925600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_093fe63d1a5f68f14ecaac871a03f7a3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SPECTACLE IMAGE LTD" and
            pe.signatures[i].serial == "09:3f:e6:3d:1a:5f:68:f1:4e:ca:ac:87:1a:03:f7:a3" and
            1562716800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bb26b7b6634d5db548c437b5085b01c1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO \"IT Mott\"" and (
                pe.signatures[i].serial == "00:bb:26:b7:b6:63:4d:5d:b5:48:c4:37:b5:08:5b:01:c1" or
                pe.signatures[i].serial == "bb:26:b7:b6:63:4d:5d:b5:48:c4:37:b5:08:5b:01:c1"
            ) and
            1591919307 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_29128a56e7b3bfb230742591ac8b4718 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Programavimo paslaugos, MB" and
            pe.signatures[i].serial == "29:12:8a:56:e7:b3:bf:b2:30:74:25:91:ac:8b:47:18" and
            1590900909 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7bfbfdfef43608730ee14779ee3ee2cb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CSTech Software Inc." and
            pe.signatures[i].serial == "7b:fb:fd:fe:f4:36:08:73:0e:e1:47:79:ee:3e:e2:cb" and
            1590537600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_62205361a758b00572d417cba014f007 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UNITEKH-S, OOO" and
            pe.signatures[i].serial == "62:20:53:61:a7:58:b0:05:72:d4:17:cb:a0:14:f0:07" and
            1590470683 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4b47d18dbea57abd1563ddf89f87a6c2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KBK, OOO" and
            pe.signatures[i].serial == "4b:47:d1:8d:be:a5:7a:bd:15:63:dd:f8:9f:87:a6:c2" and
            1590485607 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_be41e2c7bb2493044b9241abb732599d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Company Babylon" and (
                pe.signatures[i].serial == "00:be:41:e2:c7:bb:24:93:04:4b:92:41:ab:b7:32:59:9d" or
                pe.signatures[i].serial == "be:41:e2:c7:bb:24:93:04:4b:92:41:ab:b7:32:59:9d"
            ) and
            1589146251 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_15c5af15afecf1c900cbab0ca9165629 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kompaniya Auttek" and
            pe.signatures[i].serial == "15:c5:af:15:af:ec:f1:c9:00:cb:ab:0c:a9:16:56:29" and
            1586091840 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_476de2f108d20b43ba3bae6f331af8f1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digiwill Limited" and
            pe.signatures[i].serial == "47:6d:e2:f1:08:d2:0b:43:ba:3b:ae:6f:33:1a:f8:f1" and
            1588135722 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08ddcc67f8cad6929607e4cda29b3503 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FAN-CHAI, TOV" and
            pe.signatures[i].serial == "08:dd:cc:67:f8:ca:d6:92:96:07:e4:cd:a2:9b:35:03" and
            1564310268 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_052242ace583adf2a3b96adcb04d0812 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FAN-CHAI, TOV" and
            pe.signatures[i].serial == "05:22:42:ac:e5:83:ad:f2:a3:b9:6a:dc:b0:4d:08:12" and
            1573603200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bebef5c533ce92efc402fab8605c43ec {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO VEKTOR" and (
                pe.signatures[i].serial == "00:be:be:f5:c5:33:ce:92:ef:c4:02:fa:b8:60:5c:43:ec" or
                pe.signatures[i].serial == "be:be:f5:c5:33:ce:92:ef:c4:02:fa:b8:60:5c:43:ec"
            ) and
            1587513600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1d3f39f481fe067f8a9289bb49e05a04 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LOGIKA, OOO" and
            pe.signatures[i].serial == "1d:3f:39:f4:81:fe:06:7f:8a:92:89:bb:49:e0:5a:04" and
            1592553220 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7be35d025e65cc7a4ee01f72 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Logika OOO" and
            pe.signatures[i].serial == "7b:e3:5d:02:5e:65:cc:7a:4e:e0:1f:72" and
            1594976445 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_351fe2efdc0ac56a0c822cf8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Logika OOO" and
            pe.signatures[i].serial == "35:1f:e2:ef:dc:0a:c5:6a:0c:82:2c:f8" and
            1594976475 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9cfbb4c69008821aaacecde97ee149ab {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kivaliz Prest s.r.l." and (
                pe.signatures[i].serial == "00:9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab" or
                pe.signatures[i].serial == "9c:fb:b4:c6:90:08:82:1a:aa:ce:cd:e9:7e:e1:49:ab"
            ) and
            1592363914 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c04f5d17af872cb2c37e3367fe761d0d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DES SP Z O O" and (
                pe.signatures[i].serial == "00:c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d" or
                pe.signatures[i].serial == "c0:4f:5d:17:af:87:2c:b2:c3:7e:33:67:fe:76:1d:0d"
            ) and
            1594590024 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_02c5351936abe405ac760228a40387e8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RESURS-RM OOO" and
            pe.signatures[i].serial == "02:c5:35:19:36:ab:e4:05:ac:76:02:28:a4:03:87:e8" and
            1589932801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1ecd829adcc55d9d6afe30dc371ebda6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Komp.IT" and (
                pe.signatures[i].serial == "00:1e:cd:82:9a:dc:c5:5d:9d:6a:fe:30:dc:37:1e:bd:a6" or
                pe.signatures[i].serial == "1e:cd:82:9a:dc:c5:5d:9d:6a:fe:30:dc:37:1e:bd:a6"
            ) and
            1588723200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b0167124ca59149e64d292eb4b142014 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Euro May SP Z O O" and (
                pe.signatures[i].serial == "00:b0:16:71:24:ca:59:14:9e:64:d2:92:eb:4b:14:20:14" or
                pe.signatures[i].serial == "b0:16:71:24:ca:59:14:9e:64:d2:92:eb:4b:14:20:14"
            ) and
            1585267200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_112613b7b5f696cf377680f6463fcc8c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Infoware Cloud Limited" and
            pe.signatures[i].serial == "11:26:13:b7:b5:f6:96:cf:37:76:80:f6:46:3f:cc:8c" and
            1566518400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b3f906e5e6b2cf61c5e51be79b4e8777 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Accelerate Technologies Ltd" and (
                pe.signatures[i].serial == "00:b3:f9:06:e5:e6:b2:cf:61:c5:e5:1b:e7:9b:4e:87:77" or
                pe.signatures[i].serial == "b3:f9:06:e5:e6:b2:cf:61:c5:e5:1b:e7:9b:4e:87:77"
            ) and
            1594900020 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_566ac16a57b132d3f64dced14de790ee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unirad LLC" and
            pe.signatures[i].serial == "56:6a:c1:6a:57:b1:32:d3:f6:4d:ce:d1:4d:e7:90:ee" and
            1562889600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d2caf7908aaebfa1a8f3e2136fece024 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FANATOR, OOO" and (
                pe.signatures[i].serial == "00:d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24" or
                pe.signatures[i].serial == "d2:ca:f7:90:8a:ae:bf:a1:a8:f3:e2:13:6f:ec:e0:24"
            ) and
            1599041760 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e04a344b397f752a45b128a594a3d6b5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Highweb Ireland Operations Limited" and (
                pe.signatures[i].serial == "00:e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5" or
                pe.signatures[i].serial == "e0:4a:34:4b:39:7f:75:2a:45:b1:28:a5:94:a3:d6:b5"
            ) and
            1597708800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3bcaed3ef678f2f9bf38d09e149b8d70 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "StarY Media Inc." and
            pe.signatures[i].serial == "3b:ca:ed:3e:f6:78:f2:f9:bf:38:d0:9e:14:9b:8d:70" and
            1599091200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_56d576a062491ea0a5877ced418203a1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Silvo LLC" and
            pe.signatures[i].serial == "56:d5:76:a0:62:49:1e:a0:a5:87:7c:ed:41:82:03:a1" and
            1596249885 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fcba260df7da602ecf4d4d6fc89d5dd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Gold Stroy SP Z O O" and
            pe.signatures[i].serial == "0f:cb:a2:60:df:7d:a6:02:ec:f4:d4:d6:fc:89:d5:dd" and
            1593388801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4152169f22454ed604d03555b7afb175 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SMACKTECH SOFTWARE LIMITED" and
            pe.signatures[i].serial == "41:52:16:9f:22:45:4e:d6:04:d0:35:55:b7:af:b1:75" and
            1595808000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_01c88ccbd219500139d1af138a9e898e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Raymond Yanagita" and
            pe.signatures[i].serial == "01:c8:8c:cb:d2:19:50:01:39:d1:af:13:8a:9e:89:8e" and
            1593041280 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_41d05676e0d31908be4dead3486aeae3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rov SP Z O O" and
            pe.signatures[i].serial == "41:d0:56:76:e0:d3:19:08:be:4d:ea:d3:48:6a:ea:e3" and
            1594857600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8cff807edaf368a60e4106906d8df319 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KRAFT BOKS OOO" and (
                pe.signatures[i].serial == "00:8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19" or
                pe.signatures[i].serial == "8c:ff:80:7e:da:f3:68:a6:0e:41:06:90:6d:8d:f3:19"
            ) and
            1598334455 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a3e62be1572293ad618f58a8aa32857f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ISIDA, TOV" and (
                pe.signatures[i].serial == "00:a3:e6:2b:e1:57:22:93:ad:61:8f:58:a8:aa:32:85:7f" or
                pe.signatures[i].serial == "a3:e6:2b:e1:57:22:93:ad:61:8f:58:a8:aa:32:85:7f"
            ) and
            1596585600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_672d4428450afcc24fc60969a5063a3e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MEP, OOO" and
            pe.signatures[i].serial == "67:2d:44:28:45:0a:fc:c2:4f:c6:09:69:a5:06:3a:3e" and
            1597381260 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_df479e14a70c7970a4de3dd3e4bb0318 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SOFTWARE HUB IT LTD" and (
                pe.signatures[i].serial == "00:df:47:9e:14:a7:0c:79:70:a4:de:3d:d3:e4:bb:03:18" or
                pe.signatures[i].serial == "df:47:9e:14:a7:0c:79:70:a4:de:3d:d3:e4:bb:03:18"
            ) and
            1591660800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2924785fd7990b2d510675176dae2bed {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Neoopt LLC" and
            pe.signatures[i].serial == "29:24:78:5f:d7:99:0b:2d:51:06:75:17:6d:ae:2b:ed" and
            1595000258 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f4d2def53bccb0dd2b7d54e4853a2fc5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PETROYL GROUP, TOV" and (
                pe.signatures[i].serial == "00:f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5" or
                pe.signatures[i].serial == "f4:d2:de:f5:3b:cc:b0:dd:2b:7d:54:e4:85:3a:2f:c5"
            ) and
            1598347687 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03bf9ef4cf037a2385649026c3da9d3e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "COLLECTIVE SOFTWARE INC." and
            pe.signatures[i].serial == "03:bf:9e:f4:cf:03:7a:23:85:64:90:26:c3:da:9d:3e" and
            1595371955 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_790177a54209d55560a55db97c5900d6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MAK GmbH" and
            pe.signatures[i].serial == "79:01:77:a5:42:09:d5:55:60:a5:5d:b9:7c:59:00:d6" and
            1594080000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_048f7b5f67d8e2b3030f75eb7be2713d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RITEIL SERVIS, OOO" and
            pe.signatures[i].serial == "04:8f:7b:5f:67:d8:e2:b3:03:0f:75:eb:7b:e2:71:3d" and
            1591142400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_082023879112289bf351d297cc8efcfc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STA-R TOV" and
            pe.signatures[i].serial == "08:20:23:87:91:12:28:9b:f3:51:d2:97:cc:8e:fc:fc" and
            1573430400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0d53690631dd186c56be9026eb931ae2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STA-R TOV" and
            pe.signatures[i].serial == "0d:53:69:06:31:dd:18:6c:56:be:90:26:eb:93:1a:e2" and
            1592190240 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_32119925a6ce4710aecc4006c28e749f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Maxiol" and
            pe.signatures[i].serial == "32:11:99:25:a6:ce:47:10:ae:cc:40:06:c2:8e:74:9f" and
            1592438400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2c90eaf4de3afc03ba924c719435c2a3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AntiFIX s.r.o." and (
                pe.signatures[i].serial == "00:2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3" or
                pe.signatures[i].serial == "2c:90:ea:f4:de:3a:fc:03:ba:92:4c:71:94:35:c2:a3"
            ) and
            1586293430 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aff762e907f0644e76ed8a7485fb12a1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lets Start SP Z O O" and (
                pe.signatures[i].serial == "00:af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1" or
                pe.signatures[i].serial == "af:f7:62:e9:07:f0:64:4e:76:ed:8a:74:85:fb:12:a1"
            ) and
            1594882330 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d8530214ca0f512946496b5164c61201 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DJ ONLINE MARKETING LIMITED" and (
                pe.signatures[i].serial == "00:d8:53:02:14:ca:0f:51:29:46:49:6b:51:64:c6:12:01" or
                pe.signatures[i].serial == "d8:53:02:14:ca:0f:51:29:46:49:6b:51:64:c6:12:01"
            ) and
            1595485920 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_661ba8f3c9d1b348413484e9a49502f7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unique Digital Services Ltd." and (
                pe.signatures[i].serial == "00:66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7" or
                pe.signatures[i].serial == "66:1b:a8:f3:c9:d1:b3:48:41:34:84:e9:a4:95:02:f7"
            ) and
            1594942800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_51aead5a9ab2d841b449fa82de3a8a00 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Corsair Software Solution Inc." and
            pe.signatures[i].serial == "51:ae:ad:5a:9a:b2:d8:41:b4:49:fa:82:de:3a:8a:00" and
            1501577475 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03b630f9645531f8868dae8ac0f8cfe6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Geksan LLC" and
            pe.signatures[i].serial == "03:b6:30:f9:64:55:31:f8:86:8d:ae:8a:c0:f8:cf:e6" and
            1594252801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6f8373cf89f1b49138f4328118487f9e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "30 PTY LTD" and
            pe.signatures[i].serial == "6f:83:73:cf:89:f1:b4:91:38:f4:32:81:18:48:7f:9e" and
            1572566400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e38259cf24cc702ce441b683ad578911 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Akhirah Technologies Inc." and (
                pe.signatures[i].serial == "00:e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11" or
                pe.signatures[i].serial == "e3:82:59:cf:24:cc:70:2c:e4:41:b6:83:ad:57:89:11"
            ) and
            1597276800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bdc81bc76090dae0eee2e1eb744a4f9a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALM4U GmbH" and (
                pe.signatures[i].serial == "00:bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a" or
                pe.signatures[i].serial == "bd:c8:1b:c7:60:90:da:e0:ee:e2:e1:eb:74:4a:4f:9a"
            ) and
            1579824000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b2e730b0526f36faf7d093d48d6d9997 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bamboo Connect s.r.o." and (
                pe.signatures[i].serial == "00:b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97" or
                pe.signatures[i].serial == "b2:e7:30:b0:52:6f:36:fa:f7:d0:93:d4:8d:6d:99:97"
            ) and
            1597276800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7156ec47ef01ab8359ef4304e5af1a05 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BOREC, OOO" and
            pe.signatures[i].serial == "71:56:ec:47:ef:01:ab:83:59:ef:43:04:e5:af:1a:05" and
            1597363200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_13794371c052ec0559e9b492abb25c26 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Carmel group LLC" and
            pe.signatures[i].serial == "13:79:43:71:c0:52:ec:05:59:e9:b4:92:ab:b2:5c:26" and
            1599177600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5c7e78f53c31d6aa5b45de14b47eb5c4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cubic Information Systems, UAB" and
            pe.signatures[i].serial == "5c:7e:78:f5:3c:31:d6:aa:5b:45:de:14:b4:7e:b5:c4" and
            1579824000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_dadf44e4046372313ee97b8e394c4079 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digital Capital Management Ireland Limited" and (
                pe.signatures[i].serial == "00:da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79" or
                pe.signatures[i].serial == "da:df:44:e4:04:63:72:31:3e:e9:7b:8e:39:4c:40:79"
            ) and
            1600244736 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f8c2e08438bb0e9adc955e4b493e5821 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DocsGen Software Solutions Inc." and (
                pe.signatures[i].serial == "00:f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21" or
                pe.signatures[i].serial == "f8:c2:e0:84:38:bb:0e:9a:dc:95:5e:4b:49:3e:58:21"
            ) and
            1599523200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_70e1ebd170db8102d8c28e58392e5632 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Equal Cash Technologies Limited" and
            pe.signatures[i].serial == "70:e1:eb:d1:70:db:81:02:d8:c2:8e:58:39:2e:56:32" and
            1599264000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_09c89de6f64a7fdf657e69353c5fdd44 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EXON RENTAL SP Z O O" and
            pe.signatures[i].serial == "09:c8:9d:e6:f6:4a:7f:df:65:7e:69:35:3c:5f:dd:44" and
            1601337601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ffff2ce862378b26440df49ca9175b70 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "F & A.TIM d.o.o." and (
                pe.signatures[i].serial == "00:ff:ff:2c:e8:62:37:8b:26:44:0d:f4:9c:a9:17:5b:70" or
                pe.signatures[i].serial == "ff:ff:2c:e8:62:37:8b:26:44:0d:f4:9c:a9:17:5b:70"
            ) and
            1576195200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3223b4616c2687c04865bee8321726a8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and
            pe.signatures[i].serial == "32:23:b4:61:6c:26:87:c0:48:65:be:e8:32:17:26:a8" and
            1601337600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7709d2df39e9a4f7db2f3cbc29b49743 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Grina LLC" and
            pe.signatures[i].serial == "77:09:d2:df:39:e9:a4:f7:db:2f:3c:bc:29:b4:97:43" and
            1556353331 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e29690e14518874d2dcf00234ae94f1f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GRIND & TAMP ENTERPRISES PTY LTD" and (
                pe.signatures[i].serial == "00:e2:96:90:e1:45:18:87:4d:2d:cf:00:23:4a:e9:4f:1f" or
                pe.signatures[i].serial == "e2:96:90:e1:45:18:87:4d:2d:cf:00:23:4a:e9:4f:1f"
            ) and
            1570838400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cfac705c7e6845904f99995324f7562c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HMWOCFPSDLAFMFZIVD" and (
                pe.signatures[i].serial == "cf:ac:70:5c:7e:68:45:90:4f:99:99:53:24:f7:56:2c" or
                pe.signatures[i].serial == "30:53:8f:a3:81:97:ba:6f:b0:66:66:ac:db:08:a9:d4"
            ) and
            1601918720 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a7989f8be0c82d35a19e7b3dd4be30e5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Instamix Limited" and (
                pe.signatures[i].serial == "00:a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5" or
                pe.signatures[i].serial == "a7:98:9f:8b:e0:c8:2d:35:a1:9e:7b:3d:d4:be:30:e5"
            ) and
            1598054400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fa13ae98e17ae23fcfe7ae873d0c120 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KLAKSON, LLC" and
            pe.signatures[i].serial == "0f:a1:3a:e9:8e:17:ae:23:fc:fe:7a:e8:73:d0:c1:20" and
            1597276801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3696883055975d571199c6b5d48f3cd5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Korist Networks Incorporated" and
            pe.signatures[i].serial == "36:96:88:30:55:97:5d:57:11:99:c6:b5:d4:8f:3c:d5" and
            1600069289 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ee678930d5bdfaa2ab0172fa4c10ae07 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LEX CORPORATION PTY LTD" and (
                pe.signatures[i].serial == "00:ee:67:89:30:d5:bd:fa:a2:ab:01:72:fa:4c:10:ae:07" or
                pe.signatures[i].serial == "ee:67:89:30:d5:bd:fa:a2:ab:01:72:fa:4c:10:ae:07"
            ) and
            1571011200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d7c432e8d4edef515bfb9d1c214ff0f5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC \"MILKY PUT\"" and (
                pe.signatures[i].serial == "00:d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5" or
                pe.signatures[i].serial == "d7:c4:32:e8:d4:ed:ef:51:5b:fb:9d:1c:21:4f:f0:f5"
            ) and
            1601596800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5b440a47e8ce3dd202271e5c7a666c78 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Master Networking s.r.o." and
            pe.signatures[i].serial == "5b:44:0a:47:e8:ce:3d:d2:02:27:1e:5c:7a:66:6c:78" and
            1601895571 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b82c6553b2186c219797621aaa233edb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MC Commerce SP Z o o" and (
                pe.signatures[i].serial == "00:b8:2c:65:53:b2:18:6c:21:97:97:62:1a:aa:23:3e:db" or
                pe.signatures[i].serial == "b8:2c:65:53:b2:18:6c:21:97:97:62:1a:aa:23:3e:db"
            ) and
            1585785600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f360f7ad0ed065fec0b44f98e04481a0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MEHANIKUM OOO" and (
                pe.signatures[i].serial == "00:f3:60:f7:ad:0e:d0:65:fe:c0:b4:4f:98:e0:44:81:a0" or
                pe.signatures[i].serial == "f3:60:f7:ad:0e:d0:65:fe:c0:b4:4f:98:e0:44:81:a0"
            ) and
            1599031121 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fe41941464b9992a69b7317418ae8eb7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Milsean Software Limited" and (
                pe.signatures[i].serial == "00:fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7" or
                pe.signatures[i].serial == "fe:41:94:14:64:b9:99:2a:69:b7:31:74:18:ae:8e:b7"
            ) and
            1599523200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c14b611a44a1bae0e8c7581651845b6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NEEDCODE SP Z O O" and
            pe.signatures[i].serial == "0c:14:b6:11:a4:4a:1b:ae:0e:8c:75:81:65:18:45:b6" and
            1600300801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_690910dc89d7857c3500fb74bed2b08d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OLIMP STROI, OOO" and
            pe.signatures[i].serial == "69:09:10:dc:89:d7:85:7c:35:00:fb:74:be:d2:b0:8d" and
            1597276800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fd41e6bd7428d3008c8a05f68c9ac6f2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OM-FAS d.o.o." and (
                pe.signatures[i].serial == "00:fd:41:e6:bd:74:28:d3:00:8c:8a:05:f6:8c:9a:c6:f2" or
                pe.signatures[i].serial == "fd:41:e6:bd:74:28:d3:00:8c:8a:05:f6:8c:9a:c6:f2"
            ) and
            1575590400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c7079866c0e48b01246ba0c148e70d4d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO GARANT" and (
                pe.signatures[i].serial == "00:c7:07:98:66:c0:e4:8b:01:24:6b:a0:c1:48:e7:0d:4d" or
                pe.signatures[i].serial == "c7:07:98:66:c0:e4:8b:01:24:6b:a0:c1:48:e7:0d:4d"
            ) and
            1588679105 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d591da22f33c800a7024aecff2cd6c6d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO T2 Soft" and (
                pe.signatures[i].serial == "00:d5:91:da:22:f3:3c:80:0a:70:24:ae:cf:f2:cd:6c:6d" or
                pe.signatures[i].serial == "d5:91:da:22:f3:3c:80:0a:70:24:ae:cf:f2:cd:6c:6d"
            ) and
            1588679107 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b36e0f2053caee9c3b966f7be0b40fc3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PARTS-JEST d.o.o." and (
                pe.signatures[i].serial == "00:b3:6e:0f:20:53:ca:ee:9c:3b:96:6f:7b:e0:b4:0f:c3" or
                pe.signatures[i].serial == "b3:6e:0f:20:53:ca:ee:9c:3b:96:6f:7b:e0:b4:0f:c3"
            ) and
            1600172855 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5b320a2f46c99c1ba1357bee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REGION TOURISM LLC" and
            pe.signatures[i].serial == "5b:32:0a:2f:46:c9:9c:1b:a1:35:7b:ee" and
            1602513116 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08d4352185317271c1cec9d05c279af7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Retalit LLC" and
            pe.signatures[i].serial == "08:d4:35:21:85:31:72:71:c1:ce:c9:d0:5c:27:9a:f7" and
            1596585601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b514e4c5309ef9f27add05bedd4339a0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SCABONE PTY LTD" and (
                pe.signatures[i].serial == "00:b5:14:e4:c5:30:9e:f9:f2:7a:dd:05:be:dd:43:39:a0" or
                pe.signatures[i].serial == "b5:14:e4:c5:30:9e:f9:f2:7a:dd:05:be:dd:43:39:a0"
            ) and
            1572566400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_13c7b92282aae782bfb00baf879935f4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and
            pe.signatures[i].serial == "13:c7:b9:22:82:aa:e7:82:bf:b0:0b:af:87:99:35:f4" and
            1603130510 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d627f1000d12485995514bfbdefc55d9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THREE D CORPORATION PTY LTD" and (
                pe.signatures[i].serial == "00:d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9" or
                pe.signatures[i].serial == "d6:27:f1:00:0d:12:48:59:95:51:4b:fb:de:fc:55:d9"
            ) and
            1597622400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5fb6bae8834edd8d3d58818edc86d7d7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tramplink LLC" and
            pe.signatures[i].serial == "5f:b6:ba:e8:83:4e:dd:8d:3d:58:81:8e:dc:86:d7:d7" and
            1600781989 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e5ad42c509a7c24605530d35832c091e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VESNA, OOO" and (
                pe.signatures[i].serial == "00:e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e" or
                pe.signatures[i].serial == "e5:ad:42:c5:09:a7:c2:46:05:53:0d:35:83:2c:09:1e"
            ) and
            1600786458 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8e3d89c682f7c0dad70110cb7b7c8263 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WORK PLACEMENTS INTERNATIONAL LIMITED" and (
                pe.signatures[i].serial == "00:8e:3d:89:c6:82:f7:c0:da:d7:01:10:cb:7b:7c:82:63" or
                pe.signatures[i].serial == "8e:3d:89:c6:82:f7:c0:da:d7:01:10:cb:7b:7c:82:63"
            ) and
            1570626662 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ef2d35f2ae82a767a16be582ab0d1ba0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Workstage Limited" and (
                pe.signatures[i].serial == "00:ef:2d:35:f2:ae:82:a7:67:a1:6b:e5:82:ab:0d:1b:a0" or
                pe.signatures[i].serial == "ef:2d:35:f2:ae:82:a7:67:a1:6b:e5:82:ab:0d:1b:a0"
            ) and
            1567123200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_039668034826df47e6207ec9daed57c3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CHOO FSP, LLC" and
            pe.signatures[i].serial == "03:96:68:03:48:26:df:47:e6:20:7e:c9:da:ed:57:c3" and
            1601424001 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07bb6a9d1c642c5973c16d5353b17ca4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MADAS d.o.o." and
            pe.signatures[i].serial == "07:bb:6a:9d:1c:64:2c:59:73:c1:6d:53:53:b1:7c:a4" and
            1601856001 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a1dc99e4d5264c45a5090f93242a30a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "K & D KOMPANI d.o.o." and
            pe.signatures[i].serial == "0a:1d:c9:9e:4d:52:64:c4:5a:50:90:f9:32:42:a3:0a" and
            1600905601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_018093cfad72cdf402eecbe18b33ec71 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FAT11 d.o.o." and 
            pe.signatures[i].serial == "01:80:93:cf:ad:72:cd:f4:02:ee:cb:e1:8b:33:ec:71" and
            1602000390 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_569e03988af60d80ce60728940850d9b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OORT inc." and (
                pe.signatures[i].serial == "00:56:9e:03:98:8a:f6:0d:80:ce:60:72:89:40:85:0d:9b" or
                pe.signatures[i].serial == "56:9e:03:98:8a:f6:0d:80:ce:60:72:89:40:85:0d:9b"
            ) and
            1601006510 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_418f6d959a8a0f82bef07ceba3603e52 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OORT inc." and (
                pe.signatures[i].serial == "00:41:8f:6d:95:9a:8a:0f:82:be:f0:7c:eb:a3:60:3e:52" or
                pe.signatures[i].serial == "41:8f:6d:95:9a:8a:0f:82:be:f0:7c:eb:a3:60:3e:52"
            ) and
            1601928240 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5378c5bbeba0d3309a35bb47f63037f7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OORT inc." and (
                pe.signatures[i].serial == "00:53:78:c5:bb:eb:a0:d3:30:9a:35:bb:47:f6:30:37:f7" or
                pe.signatures[i].serial == "53:78:c5:bb:eb:a0:d3:30:9a:35:bb:47:f6:30:37:f7"
            ) and
            1601427420 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0bab6a2aa84b495d9e554a4c42c0126d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NOSOV SP Z O O" and
            pe.signatures[i].serial == "0b:ab:6a:2a:a8:4b:49:5d:9e:55:4a:4c:42:c0:12:6d" and
            1597971600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6314001c3235cd59bcc3f5278c518804 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GIE-MUTUALISTE" and
            pe.signatures[i].serial == "63:14:00:1c:32:35:cd:59:bc:c3:f5:27:8c:51:88:04" and
            1600304400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0ed8ade5d73b73dade6943d557ff87e5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rumikon LLC" and
            pe.signatures[i].serial == "0e:d8:ad:e5:d7:3b:73:da:de:69:43:d5:57:ff:87:e5" and
            1597885200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0292c7d574132ba5c0441d1c7ffcb805 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TES LOGISTIKA d.o.o." and
            pe.signatures[i].serial == "02:92:c7:d5:74:13:2b:a5:c0:44:1d:1c:7f:fc:b8:05" and
            1602183720 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1f23f001458716d435cca1a55d660ec5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Ringen" and
            pe.signatures[i].serial == "1f:23:f0:01:45:87:16:d4:35:cc:a1:a5:5d:66:0e:c5" and
            1603176940 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6e0ccbdfb4777e10ea6221b90dc350c2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TRAUMALAB INTERNATIONAL APS" and
            pe.signatures[i].serial == "6e:0c:cb:df:b4:77:7e:10:ea:62:21:b9:0d:c3:50:c2" and
            1603046620 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0ed1847a2ae5d71def1e833fddd33d38 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SNAB-RESURS, OOO" and
            pe.signatures[i].serial == "0e:d1:84:7a:2a:e5:d7:1d:ef:1e:83:3f:dd:d3:3d:38" and
            1598662800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_97df46acb26b7c81a13cc467b47688c8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Information Civilized System Oy" and (
                pe.signatures[i].serial == "00:97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8" or
                pe.signatures[i].serial == "97:df:46:ac:b2:6b:7c:81:a1:3c:c4:67:b4:76:88:c8"
            ) and
            1602636910 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_186d49fac34ce99775b8e7ffbf50679d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hairis LLC" and
            pe.signatures[i].serial == "18:6d:49:fa:c3:4c:e9:97:75:b8:e7:ff:bf:50:67:9d" and
            1602234590 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b1aea98bf0ce789b6c952310f14edde0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Absolut LLC" and (
                pe.signatures[i].serial == "00:b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0" or
                pe.signatures[i].serial == "b1:ae:a9:8b:f0:ce:78:9b:6c:95:23:10:f1:4e:dd:e0"
            ) and
            1602612570 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2dcd0699da08915dde6d044cb474157c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VENTE DE TOUT" and
            pe.signatures[i].serial == "2d:cd:06:99:da:08:91:5d:de:6d:04:4c:b4:74:15:7c" and
            1601830010 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4b03cabe6a0481f17a2dbeb9aefad425 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RASSVET, OOO" and
            pe.signatures[i].serial == "4b:03:ca:be:6a:04:81:f1:7a:2d:be:b9:ae:fa:d4:25" and
            1603230930 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_64cd303fa289790afa03c403e9240002 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MAITLAND TRIFECTA, INC." and 
            pe.signatures[i].serial == "64:cd:30:3f:a2:89:79:0a:fa:03:c4:03:e9:24:00:02" and
            1602723600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07cef66a71c35bc3aed6d100c6493863 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fubon Technologies Ltd" and
            pe.signatures[i].serial == "07:ce:f6:6a:71:c3:5b:c3:ae:d6:d1:00:c6:49:38:63" and
            1602740890 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_be77fe5c58b7a360add6a3fced4e8334 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Incar LLC" and (
                pe.signatures[i].serial == "00:be:77:fe:5c:58:b7:a3:60:ad:d6:a3:fc:ed:4e:83:34" or
                pe.signatures[i].serial == "be:77:fe:5c:58:b7:a3:60:ad:d6:a3:fc:ed:4e:83:34"
            ) and
            1602530730 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f097e59809ae2e771b7b9ae5fc3408d7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABEL RENOVATIONS, INC." and (
                pe.signatures[i].serial == "00:f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7" or
                pe.signatures[i].serial == "f0:97:e5:98:09:ae:2e:77:1b:7b:9a:e5:fc:34:08:d7"
            ) and
            1602542033 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0cf1ed2a6ff4bee621efdf725ea174b7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LEVEL LIST SP Z O O" and
            pe.signatures[i].serial == "0c:f1:ed:2a:6f:f4:be:e6:21:ef:df:72:5e:a1:74:b7" and
            1603036100 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1249aa2ada4967969b71ce63bf187c38 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Umbrella LLC" and
            pe.signatures[i].serial == "12:49:aa:2a:da:49:67:96:9b:71:ce:63:bf:18:7c:38" and
            1599181200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d59a05955a4a421500f9561ce983aac4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Olymp LLC" and (
                pe.signatures[i].serial == "00:d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4" or
                pe.signatures[i].serial == "d5:9a:05:95:5a:4a:42:15:00:f9:56:1c:e9:83:aa:c4"
            ) and
            1601895290 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_539015999e304a5952985a994f9c3a53 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Service lab LLC" and
            pe.signatures[i].serial == "53:90:15:99:9e:30:4a:59:52:98:5a:99:4f:9c:3a:53" and
            1599181200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0b1926a5e8ae50a0efa504f005f93869 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nordkod LLC" and
            pe.signatures[i].serial == "0b:19:26:a5:e8:ae:50:a0:ef:a5:04:f0:05:f9:38:69" and
            1600650000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a23b660e7322e54d7bd0e5acc890966 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ARTBUD RADOM SP Z O O" and
            pe.signatures[i].serial == "0a:23:b6:60:e7:32:2e:54:d7:bd:0e:5a:cc:89:09:66" and
            1601254800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6cfa5050c819c4acbb8fa75979688dff {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Elite Web Development Ltd." and (
                pe.signatures[i].serial == "00:6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff" or
                pe.signatures[i].serial == "6c:fa:50:50:c8:19:c4:ac:bb:8f:a7:59:79:68:8d:ff"
            ) and
            1600176940 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_044e05bb1a01a1cbb50cfb6cd24e5d6b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MUSTER PLUS SP Z O O" and
            pe.signatures[i].serial == "04:4e:05:bb:1a:01:a1:cb:b5:0c:fb:6c:d2:4e:5d:6b" and
            1601427600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b7f19b13de9bee8a52ff365ced6f67fa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALEXIS SECURITY GROUP, LLC" and (
                pe.signatures[i].serial == "00:b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa" or
                pe.signatures[i].serial == "b7:f1:9b:13:de:9b:ee:8a:52:ff:36:5c:ed:6f:67:fa"
            ) and
            1574914319 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b61b8e71514059adc604da05c283e514 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APP DIVISION ApS" and (
                pe.signatures[i].serial == "00:b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14" or
                pe.signatures[i].serial == "b6:1b:8e:71:51:40:59:ad:c6:04:da:05:c2:83:e5:14"
            ) and
            1603328400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ece6cbf67dc41635a5e5d075f286af23 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THRANE AGENTUR ApS" and (
                pe.signatures[i].serial == "00:ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23" or
                pe.signatures[i].serial == "ec:e6:cb:f6:7d:c4:16:35:a5:e5:d0:75:f2:86:af:23"
            ) and
            1603369254 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_014a98d697b44f43ded21f18eb6ad0ba {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hillcoe Software Inc." and
            pe.signatures[i].serial == "01:4a:98:d6:97:b4:4f:43:de:d2:1f:18:eb:6a:d0:ba" and
            1605364760 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_063a7d09107eddd8aa1f733634c6591b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Smart Line Logistics" and
            pe.signatures[i].serial == "06:3a:7d:09:10:7e:dd:d8:aa:1f:73:36:34:c6:59:1b" and
            1605712706 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1e74cfe7de8c5f57840a61034414ca9f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Insta Software Solution Inc." and (
                pe.signatures[i].serial == "00:1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f" or
                pe.signatures[i].serial == "1e:74:cf:e7:de:8c:5f:57:84:0a:61:03:44:14:ca:9f"
            ) and
            1601733106 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_75cf729f8a740bbdef183a1c4d86a02f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Umbor LLC" and
            pe.signatures[i].serial == "75:cf:72:9f:8a:74:0b:bd:ef:18:3a:1c:4d:86:a0:2f" and
            1604223894 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2f64677254d3844efdac2922123d05d1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ORGANICUP ApS" and
            pe.signatures[i].serial == "2f:64:67:72:54:d3:84:4e:fd:ac:29:22:12:3d:05:d1" and
            1605640092 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_32fbf8cfa43dca3f85efabe96dfefa49 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Foxstyle LLC" and
            pe.signatures[i].serial == "32:fb:f8:cf:a4:3d:ca:3f:85:ef:ab:e9:6d:fe:fa:49" and
            1598255906 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ef9d0cf071d463cd63d13083046a7b8d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rubin LLC" and (
                pe.signatures[i].serial == "00:ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d" or
                pe.signatures[i].serial == "ef:9d:0c:f0:71:d4:63:cd:63:d1:30:83:04:6a:7b:8d"
            ) and
            1605358307 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_115cf1353a0e33e19099a4867a4c750a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "212 NY Gifts, Inc." and (
                pe.signatures[i].serial == "00:11:5c:f1:35:3a:0e:33:e1:90:99:a4:86:7a:4c:75:0a" or
                pe.signatures[i].serial == "11:5c:f1:35:3a:0e:33:e1:90:99:a4:86:7a:4c:75:0a"
            ) and
            1605515909 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5cf3778bb11115a884e192a7cb807599 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SLOMATIC d.o.o." and (
                pe.signatures[i].serial == "00:5c:f3:77:8b:b1:11:15:a8:84:e1:92:a7:cb:80:75:99" or
                pe.signatures[i].serial == "5c:f3:77:8b:b1:11:15:a8:84:e1:92:a7:cb:80:75:99"
            ) and
            1605006199 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_82cb93593b658100cdd7a00c874287f2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sportsonline24 B.V." and (
                pe.signatures[i].serial == "00:82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2" or
                pe.signatures[i].serial == "82:cb:93:59:3b:65:81:00:cd:d7:a0:0c:87:42:87:f2"
            ) and
            1605117874 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9a8bcfd05f86b15d0c99f50cf414bd00 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AI Software a.s." and (
                pe.signatures[i].serial == "00:9a:8b:cf:d0:5f:86:b1:5d:0c:99:f5:0c:f4:14:bd:00" or
                pe.signatures[i].serial == "9a:8b:cf:d0:5f:86:b1:5d:0c:99:f5:0c:f4:14:bd:00"
            ) and
            1592442000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_95e5793f2abe0b4ec9be54fd24f76ae5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kommservice LLC" and (
                pe.signatures[i].serial == "00:95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5" or
                pe.signatures[i].serial == "95:e5:79:3f:2a:be:0b:4e:c9:be:54:fd:24:f7:6a:e5"
            ) and
            1604933746 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_133565779808c3b79d8e3f70a9c3ffac {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Istok" and
            pe.signatures[i].serial == "13:35:65:77:98:08:c3:b7:9d:8e:3f:70:a9:c3:ff:ac" and
            1605019819 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7e0ccda0ef37acef6c2ebe4538627e5c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Orangetree B.V." and (
                pe.signatures[i].serial == "00:7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c" or
                pe.signatures[i].serial == "7e:0c:cd:a0:ef:37:ac:ef:6c:2e:be:45:38:62:7e:5c"
            ) and
            1606159604 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bad35fd70025d46c56b89e32b1a3954c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fort LLC" and (
                pe.signatures[i].serial == "00:ba:d3:5f:d7:00:25:d4:6c:56:b8:9e:32:b1:a3:95:4c" or
                pe.signatures[i].serial == "ba:d3:5f:d7:00:25:d4:6c:56:b8:9e:32:b1:a3:95:4c"
            ) and
            1604937337 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7b91468122273aa32b7cfc80c331ea13 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO KBI" and
            pe.signatures[i].serial == "7b:91:46:81:22:27:3a:a3:2b:7c:fc:80:c3:31:ea:13" and
            1586942863 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3e267b5d14cdf1f645c1ec545cec3aee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO KBI" and
            pe.signatures[i].serial == "3e:26:7b:5d:14:cd:f1:f6:45:c1:ec:54:5c:ec:3a:ee" and
            1579825892 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ae6d3c0269ef6497e14379c51a8507ba {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VELES PROPERTIES LIMITED" and (
                pe.signatures[i].serial == "00:ae:6d:3c:02:69:ef:64:97:e1:43:79:c5:1a:85:07:ba" or
                pe.signatures[i].serial == "ae:6d:3c:02:69:ef:64:97:e1:43:79:c5:1a:85:07:ba"
            ) and
            1578566034 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fd8c468cc1b45c9cfb41cbd8c835cc9e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pivo ZLoun s.r.o." and (
                pe.signatures[i].serial == "00:fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e" or
                pe.signatures[i].serial == "fd:8c:46:8c:c1:b4:5c:9c:fb:41:cb:d8:c8:35:cc:9e"
            ) and
            1604019600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7c061baa3118327255161f6a7fa4e21d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "YUTAKS, OOO" and (
                pe.signatures[i].serial == "00:7c:06:1b:aa:31:18:32:72:55:16:1f:6a:7f:a4:e2:1d" or
                pe.signatures[i].serial == "7c:06:1b:aa:31:18:32:72:55:16:1f:6a:7f:a4:e2:1d"
            ) and
            1599611338 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04332c16724ffeda5868d22af56aea43 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bespoke Software Solutions Limited" and
            pe.signatures[i].serial == "04:33:2c:16:72:4f:fe:da:58:68:d2:2a:f5:6a:ea:43" and
            1597971601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_030012f134e64347669f3256c7d050c5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Futumarket LLC" and
            pe.signatures[i].serial == "03:00:12:f1:34:e6:43:47:66:9f:32:56:c7:d0:50:c5" and
            1604036657 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fa3dcac19b884b44ef4f81541184d6b0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Unicom Ltd" and (
                pe.signatures[i].serial == "00:fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0" or
                pe.signatures[i].serial == "fa:3d:ca:c1:9b:88:4b:44:ef:4f:81:54:11:84:d6:b0"
            ) and
            1603958571 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0e6f4cb8b06e01c3bd296ace3a95f814 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EVATON, s.r.o." and
            pe.signatures[i].serial == "0e:6f:4c:b8:b0:6e:01:c3:bd:29:6a:ce:3a:95:f8:14" and
            1603957781 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_085b70224253486624fc36fa658a1e32 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Best Fud, OOO" and
            pe.signatures[i].serial == "08:5b:70:22:42:53:48:66:24:fc:36:fa:65:8a:1e:32" and
            1597971601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_51cd5393514f7ace2b407c3dbfb09d8d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APPI CZ a.s" and
            pe.signatures[i].serial == "51:cd:53:93:51:4f:7a:ce:2b:40:7c:3d:bf:b0:9d:8d" and
            1605299467 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b72179c027b9037ee220e81ab18fe56d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Planeta, TOV" and (
                pe.signatures[i].serial == "00:b7:21:79:c0:27:b9:03:7e:e2:20:e8:1a:b1:8f:e5:6d" or
                pe.signatures[i].serial == "b7:21:79:c0:27:b9:03:7e:e2:20:e8:1a:b1:8f:e5:6d"
            ) and
            1603381300 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_07b74c70c4aa092648b7f0d1a8a3a28f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rad-Grad D.O.O." and
            pe.signatures[i].serial == "07:b7:4c:70:c4:aa:09:26:48:b7:f0:d1:a8:a3:a2:8f" and
            1603240965 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4c8def294478b7d59ee95c61fae3d965 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DREAM SECURITY USA INC" and
            pe.signatures[i].serial == "4c:8d:ef:29:44:78:b7:d5:9e:e9:5c:61:fa:e3:d9:65" and
            1592961292 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7d36cbb64bc9add17ba71737d3ecceca {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LTD SERVICES LIMITED" and
            pe.signatures[i].serial == "7d:36:cb:b6:4b:c9:ad:d1:7b:a7:17:37:d3:ec:ce:ca" and
            1616025600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ad255d4ebefa751f3782587396c08629 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Ornitek" and (
                pe.signatures[i].serial == "00:ad:25:5d:4e:be:fa:75:1f:37:82:58:73:96:c0:86:29" or
                pe.signatures[i].serial == "ad:25:5d:4e:be:fa:75:1f:37:82:58:73:96:c0:86:29"
            ) and
            1614643200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_262ca7ae19d688138e75932832b18f9d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bisoyetutu Ltd Ltd" and
            pe.signatures[i].serial == "26:2c:a7:ae:19:d6:88:13:8e:75:93:28:32:b1:8f:9d" and
            1616025600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_59a57e8ba3dcf2b6f59981fda14b03 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Medium LLC" and
            pe.signatures[i].serial == "59:a5:7e:8b:a3:dc:f2:b6:f5:99:81:fd:a1:4b:03" and
            1609113600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aebe117a13b8bca21685df48c74f584d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NANAX d.o.o." and (
                pe.signatures[i].serial == "00:ae:be:11:7a:13:b8:bc:a2:16:85:df:48:c7:4f:58:4d" or
                pe.signatures[i].serial == "ae:be:11:7a:13:b8:bc:a2:16:85:df:48:c7:4f:58:4d"
            ) and
            1613520000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7dcd19a94535f034ee36af4676740633 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Toko Saya ApS" and
            pe.signatures[i].serial == "7d:cd:19:a9:45:35:f0:34:ee:36:af:46:76:74:06:33" and
            1609200000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ca4822e6905aa4fca9e28523f04f14a3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ELISTREID, OOO" and (
                pe.signatures[i].serial == "00:ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3" or
                pe.signatures[i].serial == "ca:48:22:e6:90:5a:a4:fc:a9:e2:85:23:f0:4f:14:a3"
            ) and
            1614643200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_24c1ef800f275ab2780280c595de3464 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HOLGAN LIMITED" and
            pe.signatures[i].serial == "24:c1:ef:80:0f:27:5a:b2:78:02:80:c5:95:de:34:64" and
            1614729600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6401831b46588b9d872b02076c3a7b00 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ACTIV GROUP ApS" and
            pe.signatures[i].serial == "64:01:83:1b:46:58:8b:9d:87:2b:02:07:6c:3a:7b:00" and
            1615507200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a01a91cce63ede5eaa3dac4883aea05 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Seacloud Technologies Pte. Ltd." and
            pe.signatures[i].serial == "0a:01:a9:1c:ce:63:ed:e5:ea:a3:da:c4:88:3a:ea:05" and
            1618876800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_54cd7ae1c27f1421136ed25088f4979a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABBYMAJUTA LTD LIMITED" and
            pe.signatures[i].serial == "54:cd:7a:e1:c2:7f:14:21:13:6e:d2:50:88:f4:97:9a" and
            1616371200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f2d693aad63e6920782a0027dfc97d91 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EKO-KHIM TOV" and (
                pe.signatures[i].serial == "00:f2:d6:93:aa:d6:3e:69:20:78:2a:00:27:df:c9:7d:91" or
                pe.signatures[i].serial == "f2:d6:93:aa:d6:3e:69:20:78:2a:00:27:df:c9:7d:91"
            ) and
            1598989763 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f8e8f6c92ba666b0688a8cacce9acccf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "5 th Dimension LTD Oy" and (
                pe.signatures[i].serial == "00:f8:e8:f6:c9:2b:a6:66:b0:68:8a:8c:ac:ce:9a:cc:cf" or
                pe.signatures[i].serial == "f8:e8:f6:c9:2b:a6:66:b0:68:8a:8c:ac:ce:9a:cc:cf"
            ) and
            1618531200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e3d5089d4b8f01aadce2731062fb0cce {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DEVELOP - Residence s. r. o." and (
                pe.signatures[i].serial == "00:e3:d5:08:9d:4b:8f:01:aa:dc:e2:73:10:62:fb:0c:ce" or
                pe.signatures[i].serial == "e3:d5:08:9d:4b:8f:01:aa:dc:e2:73:10:62:fb:0c:ce"
            ) and
            1618358400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7ed801843fa001b8add52d3a97b25931 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AM El-Teknik ApS" and
            pe.signatures[i].serial == "7e:d8:01:84:3f:a0:01:b8:ad:d5:2d:3a:97:b2:59:31" and
            1614297600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d9e834182dec62c654e775e809ac1d1b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FoodLehto Oy" and (
                pe.signatures[i].serial == "00:d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b" or
                pe.signatures[i].serial == "d9:e8:34:18:2d:ec:62:c6:54:e7:75:e8:09:ac:1d:1b"
            ) and
            1614297600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_801689896ed339237464a41a2900a969 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GLG Rental ApS" and (
                pe.signatures[i].serial == "00:80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69" or
                pe.signatures[i].serial == "80:16:89:89:6e:d3:39:23:74:64:a4:1a:29:00:a9:69"
            ) and
            1615507200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3fd3661533eef209153c9afec3ba4d8a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SFB Regnskabsservice ApS" and
            pe.signatures[i].serial == "3f:d3:66:15:33:ee:f2:09:15:3c:9a:fe:c3:ba:4d:8a" and
            1614816000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0ced87bd70b092cb93b182fac32655f6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Creator Soft Limited" and
            pe.signatures[i].serial == "0c:ed:87:bd:70:b0:92:cb:93:b1:82:fa:c3:26:55:f6" and
            1614816000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_047801d5b55c800b48411fd8c320ca5b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LICHFIELD STUDIO GLASS LIMITED" and
            pe.signatures[i].serial == "04:78:01:d5:b5:5c:80:0b:48:41:1f:d8:c3:20:ca:5b" and
            1614297600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0f0ed5318848703405d40f7c62d0f39a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SIES UPRAVLENIE PROTSESSAMI, OOO" and
            pe.signatures[i].serial == "0f:0e:d5:31:88:48:70:34:05:d4:0f:7c:62:d0:f3:9a" and
            1614729600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4e7545c9fc5938f5198ab9f1749ca31c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "For M d.o.o." and
            pe.signatures[i].serial == "4e:75:45:c9:fc:59:38:f5:19:8a:b9:f1:74:9c:a3:1c" and
            1614297600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7ddd3796a427b42f2e52d7c7af0ca54f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Fobos" and
            pe.signatures[i].serial == "7d:dd:37:96:a4:27:b4:2f:2e:52:d7:c7:af:0c:a5:4f" and
            1612915200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_03b27d7f4ee21a462a064a17eef70d6c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CCL TRADING LIMITED" and
            pe.signatures[i].serial == "03:b2:7d:7f:4e:e2:1a:46:2a:06:4a:17:ee:f7:0d:6c" and
            1613952000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b0a308fc2e71ac4ac40677b9c27ccbad {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Volpayk LLC" and (
                pe.signatures[i].serial == "00:b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad" or
                pe.signatures[i].serial == "b0:a3:08:fc:2e:71:ac:4a:c4:06:77:b9:c2:7c:cb:ad"
            ) and
            1611705600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_61b11ef9726ab2e78132e01bd791b336 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Skalari" and
            pe.signatures[i].serial == "61:b1:1e:f9:72:6a:b2:e7:81:32:e0:1b:d7:91:b3:36" and
            1609372800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8fe807310d98357a59382090634b93f0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MAVE MEDIA" and (
                pe.signatures[i].serial == "00:8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0" or
                pe.signatures[i].serial == "8f:e8:07:31:0d:98:35:7a:59:38:20:90:63:4b:93:f0"
            ) and
            1613433600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b97f66bb221772dc07ef1d4bed8f6085 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "S-PRO d.o.o." and (
                pe.signatures[i].serial == "00:b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85" or
                pe.signatures[i].serial == "b9:7f:66:bb:22:17:72:dc:07:ef:1d:4b:ed:8f:60:85"
            ) and
            1614556800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fed006fbf85cd1c6ba6b4345b198e1e6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LoL d.o.o." and (
                pe.signatures[i].serial == "00:fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6" or
                pe.signatures[i].serial == "fe:d0:06:fb:f8:5c:d1:c6:ba:6b:43:45:b1:98:e1:e6"
            ) and
            1614297600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aa28c9bd16d9d304f18af223b27bfa1e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tecno trade d.o.o." and (
                pe.signatures[i].serial == "00:aa:28:c9:bd:16:d9:d3:04:f1:8a:f2:23:b2:7b:fa:1e" or
                pe.signatures[i].serial == "aa:28:c9:bd:16:d9:d3:04:f1:8a:f2:23:b2:7b:fa:1e"
            ) and
            1611705600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_19beff8a6c129663e5e8c18953dc1f67 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CULNADY LTD LTD" and
            pe.signatures[i].serial == "19:be:ff:8a:6c:12:96:63:e5:e8:c1:89:53:dc:1f:67" and
            1608163200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_029685cda1c8233d2409a31206f78f9f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KOTO TRADE, dru\\xC5\\xBEba za posredovanje, d.o.o." and
            pe.signatures[i].serial == "02:96:85:cd:a1:c8:23:3d:24:09:a3:12:06:f7:8f:9f" and
            1612396800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d609b6c95428954a999a8a99d4f198af {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Fudl" and (
                pe.signatures[i].serial == "00:d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af" or
                pe.signatures[i].serial == "d6:09:b6:c9:54:28:95:4a:99:9a:8a:99:d4:f1:98:af"
            ) and
            1612828800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d3356318924c8c42959bf1d1574e6482 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ADV TOURS d.o.o." and (
                pe.signatures[i].serial == "00:d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82" or
                pe.signatures[i].serial == "d3:35:63:18:92:4c:8c:42:95:9b:f1:d1:57:4e:64:82"
            ) and
            1613001600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_31d852f5fca1a5966b5ed08a14825c54 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BBT KLA d.o.o." and
            pe.signatures[i].serial == "31:d8:52:f5:fc:a1:a5:96:6b:5e:d0:8a:14:82:5c:54" and
            1612396800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_17d99cc2f5b29522d422332e681f3e18 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PKV Trading ApS" and
            pe.signatures[i].serial == "17:d9:9c:c2:f5:b2:95:22:d4:22:33:2e:68:1f:3e:18" and
            1613088000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6a568f85de2061f67ded98707d4988df {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Apladis" and
            pe.signatures[i].serial == "6a:56:8f:85:de:20:61:f6:7d:ed:98:70:7d:49:88:df" and
            1613001600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_038fc745523b41b40d653b83aa381b80 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Optima" and
            pe.signatures[i].serial == "03:8f:c7:45:52:3b:41:b4:0d:65:3b:83:aa:38:1b:80" and
            1606143708 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_30af0d0e6d8201a5369664c5ebbb010f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3N-\\xC5\\xA0PORT podjetje za in\\xC5\\xBEeniring, storitve in trgovino d.o.o." and
            pe.signatures[i].serial == "30:af:0d:0e:6d:82:01:a5:36:96:64:c5:eb:bb:01:0f" and
            1613433600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ac0a7b9420b369af3ddb748385b981 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Tochka" and (
                pe.signatures[i].serial == "00:ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81" or
                pe.signatures[i].serial == "ac:0a:7b:94:20:b3:69:af:3d:db:74:83:85:b9:81"
            ) and
            1604620800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c167f04b338b1e8747b92c2197403c43 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORTUNE STAR TRADING, INC." and (
                pe.signatures[i].serial == "00:c1:67:f0:4b:33:8b:1e:87:47:b9:2c:21:97:40:3c:43" or
                pe.signatures[i].serial == "c1:67:f0:4b:33:8b:1e:87:47:b9:2c:21:97:40:3c:43"
            ) and
            1604361600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9272607cfc982b782a5d36c4b78f5e7b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rada SP Z o o" and (
                pe.signatures[i].serial == "00:92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b" or
                pe.signatures[i].serial == "92:72:60:7c:fc:98:2b:78:2a:5d:36:c4:b7:8f:5e:7b"
            ) and
            1605139200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_45eb9187a2505d8e6c842e6d366ad0c8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BAKERA s.r.o." and
            pe.signatures[i].serial == "45:eb:91:87:a2:50:5d:8e:6c:84:2e:6d:36:6a:d0:c8" and
            1607040000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_56fff139df5ae7e788e5d72196dd563a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Cifromatika LLC" and
            pe.signatures[i].serial == "56:ff:f1:39:df:5a:e7:e7:88:e5:d7:21:96:dd:56:3a" and
            1606435200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e161f76da3b5e4623892c8e6fda1ea3d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TGN Nedelica d.o.o." and (
                pe.signatures[i].serial == "00:e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d" or
                pe.signatures[i].serial == "e1:61:f7:6d:a3:b5:e4:62:38:92:c8:e6:fd:a1:ea:3d"
            ) and
            1604966400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9ae5b177ac3a7ce2aadf1c891b574924 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Kolorit" and (
                pe.signatures[i].serial == "00:9a:e5:b1:77:ac:3a:7c:e2:aa:df:1c:89:1b:57:49:24" or
                pe.signatures[i].serial == "9a:e5:b1:77:ac:3a:7c:e2:aa:df:1c:89:1b:57:49:24"
            ) and
            1608076800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a03ea3a4fa772b17037a0b80f1f968aa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DREVOKAPITAL, s.r.o." and (
                pe.signatures[i].serial == "00:a0:3e:a3:a4:fa:77:2b:17:03:7a:0b:80:f1:f9:68:aa" or
                pe.signatures[i].serial == "a0:3e:a3:a4:fa:77:2b:17:03:7a:0b:80:f1:f9:68:aa"
            ) and
            1608076800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_333ca7d100b139b0d9c1a97cb458e226 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FSE, d.o.o." and
            pe.signatures[i].serial == "33:3c:a7:d1:00:b1:39:b0:d9:c1:a9:7c:b4:58:e2:26" and
            1608076800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9245d1511923f541844faa3c6bfebcbe {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LEHTEH d.o.o., Ljubljana" and (
                pe.signatures[i].serial == "00:92:45:d1:51:19:23:f5:41:84:4f:aa:3c:6b:fe:bc:be" or
                pe.signatures[i].serial == "92:45:d1:51:19:23:f5:41:84:4f:aa:3c:6b:fe:bc:be"
            ) and
            1607040000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2888cf0f953a4a3640ee4cfc6304d9d4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lotte Schmidt" and
            pe.signatures[i].serial == "28:88:cf:0f:95:3a:4a:36:40:ee:4c:fc:63:04:d9:d4" and
            1608024974 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c8edcfe8be174c2f204d858c5b91dea5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Paarcopy Oy" and (
                pe.signatures[i].serial == "00:c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5" or
                pe.signatures[i].serial == "c8:ed:cf:e8:be:17:4c:2f:20:4d:85:8c:5b:91:de:a5"
            ) and
            1608076800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9faf8705a3eaef9340800cc4fd38597c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tekhnokod LLC" and (
                pe.signatures[i].serial == "00:9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c" or
                pe.signatures[i].serial == "9f:af:87:05:a3:ea:ef:93:40:80:0c:c4:fd:38:59:7c"
            ) and
            1605744000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0940fa9a4080f35052b2077333769c2f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PROFF LAIN, OOO" and
            pe.signatures[i].serial == "09:40:fa:9a:40:80:f3:50:52:b2:07:73:33:76:9c:2f" and
            1603497600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ea720222d92dc8d48e3b3c3b0fc360a6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CAVANAGH NETS LIMITED" and (
                pe.signatures[i].serial == "00:ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6" or
                pe.signatures[i].serial == "ea:72:02:22:d9:2d:c8:d4:8e:3b:3c:3b:0f:c3:60:a6"
            ) and
            1608640280 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4743e140c05b33f0449023946bd05acb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STROI RENOV SARL" and
            pe.signatures[i].serial == "47:43:e1:40:c0:5b:33:f0:44:90:23:94:6b:d0:5a:cb" and
            1607644800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a496bc774575c31abec861b68c36dcb6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ORGLE DVORSAK, d.o.o" and (
                pe.signatures[i].serial == "00:a4:96:bc:77:45:75:c3:1a:be:c8:61:b6:8c:36:dc:b6" or
                pe.signatures[i].serial == "a4:96:bc:77:45:75:c3:1a:be:c8:61:b6:8c:36:dc:b6"
            ) and
            1606867200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a55c15f733bf1633e9ffae8a6e3b37d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Osnova OOO" and
            pe.signatures[i].serial == "0a:55:c1:5f:73:3b:f1:63:3e:9f:fa:e8:a6:e3:b3:7d" and
            1604016000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c650ae531100a91389a7f030228b3095 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "POKEROWA STRUNA SP Z O O" and (
                pe.signatures[i].serial == "00:c6:50:ae:53:11:00:a9:13:89:a7:f0:30:22:8b:30:95" or
                pe.signatures[i].serial == "c6:50:ae:53:11:00:a9:13:89:a7:f0:30:22:8b:30:95"
            ) and
            1606089600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3990362c34015ce4c23ecc3377fd3c06 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RZOH ApS" and
            pe.signatures[i].serial == "39:90:36:2c:34:01:5c:e4:c2:3e:cc:33:77:fd:3c:06" and
            1606780800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_121fca3cfa4bd011669f5cc4e053aa3f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kymijoen Projektipalvelut Oy" and
            pe.signatures[i].serial == "12:1f:ca:3c:fa:4b:d0:11:66:9f:5c:c4:e0:53:aa:3f" and
            1606953600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d338f8a490e37e6c2be80a0e349929fa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SAGUARO ApS" and (
                pe.signatures[i].serial == "00:d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa" or
                pe.signatures[i].serial == "d3:38:f8:a4:90:e3:7e:6c:2b:e8:0a:0e:34:99:29:fa"
            ) and
            1607558400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2c1ee9b583310b5e34a1ee6945a34b26 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Artmarket" and
            pe.signatures[i].serial == "2c:1e:e9:b5:83:31:0b:5e:34:a1:ee:69:45:a3:4b:26" and
            1607558400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d875b3e3f2db6c3eb426e24946066111 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kubit LLC" and (
                pe.signatures[i].serial == "00:d8:75:b3:e3:f2:db:6c:3e:b4:26:e2:49:46:06:61:11" or
                pe.signatures[i].serial == "d8:75:b3:e3:f2:db:6c:3e:b4:26:e2:49:46:06:61:11"
            ) and
            1606953600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ad0a958cdf188bed43154a54bf23afba {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RHM Ltd" and (
                pe.signatures[i].serial == "00:ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba" or
                pe.signatures[i].serial == "ad:0a:95:8c:df:18:8b:ed:43:15:4a:54:bf:23:af:ba"
            ) and
            1612915200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3cee26c125b8c188f316c3fa78d9c2f1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Bitubit LLC" and
            pe.signatures[i].serial == "3c:ee:26:c1:25:b8:c1:88:f3:16:c3:fa:78:d9:c2:f1" and
            1606435200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4c687a0022c36f89e253f91d1f6954e2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HETCO ApS" and
            pe.signatures[i].serial == "4c:68:7a:00:22:c3:6f:89:e2:53:f9:1d:1f:69:54:e2" and
            1606780800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ca646b4275406df639cf603756f63d77 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SHOECORP LIMITED" and (
                pe.signatures[i].serial == "00:ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77" or
                pe.signatures[i].serial == "ca:64:6b:42:75:40:6d:f6:39:cf:60:37:56:f6:3d:77"
            ) and
            1605830400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_addbec454b5479cabd940a72df4500af {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SHAT LIMITED" and (
                pe.signatures[i].serial == "00:ad:db:ec:45:4b:54:79:ca:bd:94:0a:72:df:45:00:af" or
                pe.signatures[i].serial == "ad:db:ec:45:4b:54:79:ca:bd:94:0a:72:df:45:00:af"
            ) and
            1612828800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ac307e5257bb814b818d3633b630326f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aqua Direct s.r.o." and (
                pe.signatures[i].serial == "00:ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f" or
                pe.signatures[i].serial == "ac:30:7e:52:57:bb:81:4b:81:8d:36:33:b6:30:32:6f"
            ) and
            1606089600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0d83e7f47189cdbfc7fa3e5f58882329 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE WIZARD GIFT CORPORATION" and
            pe.signatures[i].serial == "0d:83:e7:f4:71:89:cd:bf:c7:fa:3e:5f:58:88:23:29" and
            1605830400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_58aa64564a50e8b2d6e31d5cd6250fde {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Foreground" and
            pe.signatures[i].serial == "58:aa:64:56:4a:50:e8:b2:d6:e3:1d:5c:d6:25:0f:de" and
            1609002028 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2aa0ae245b487c8926c88ee6d736d1ca {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PILOTE SPRL" and
            pe.signatures[i].serial == "2a:a0:ae:24:5b:48:7c:89:26:c8:8e:e6:d7:36:d1:ca" and
            1612262280 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1aec3d3f752a38617c1d7a677d0b5591 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SILVER d.o.o." and
            pe.signatures[i].serial == "1a:ec:3d:3f:75:2a:38:61:7c:1d:7a:67:7d:0b:55:91" and
            1611705600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a7e1dc5352c3852c5523030f57f2425c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pushka LLC" and (
                pe.signatures[i].serial == "00:a7:e1:dc:53:52:c3:85:2c:55:23:03:0f:57:f2:42:5c" or
                pe.signatures[i].serial == "a7:e1:dc:53:52:c3:85:2c:55:23:03:0f:57:f2:42:5c"
            ) and
            1611792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bbd4dc3768a51aa2b3059c1bad569276 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JJ ELECTRICAL SERVICES LIMITED" and (
                pe.signatures[i].serial == "00:bb:d4:dc:37:68:a5:1a:a2:b3:05:9c:1b:ad:56:92:76" or
                pe.signatures[i].serial == "bb:d4:dc:37:68:a5:1a:a2:b3:05:9c:1b:ad:56:92:76"
            ) and
            1607472000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08622b9dd9d78e67678ecc21e026522e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kayak Republic af 2015 APS" and
            pe.signatures[i].serial == "08:62:2b:9d:d9:d7:8e:67:67:8e:cc:21:e0:26:52:2e" and
            1611619200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e69a6de0074ece38c2f30f0d4a808456 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Semantic" and (
                pe.signatures[i].serial == "00:e6:9a:6d:e0:07:4e:ce:38:c2:f3:0f:0d:4a:80:84:56" or
                pe.signatures[i].serial == "e6:9a:6d:e0:07:4e:ce:38:c2:f3:0f:0d:4a:80:84:56"
            ) and
            1611532800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8385684419ab26a3f2640b1496e1fe94 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CAUSE FOR CHANGE LTD" and (
                pe.signatures[i].serial == "00:83:85:68:44:19:ab:26:a3:f2:64:0b:14:96:e1:fe:94" or
                pe.signatures[i].serial == "83:85:68:44:19:ab:26:a3:f2:64:0b:14:96:e1:fe:94"
            ) and
            1612137600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_21e3cae5b77c41528658ada08509c392 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Network Design International Holdings Limited" and
            pe.signatures[i].serial == "21:e3:ca:e5:b7:7c:41:52:86:58:ad:a0:85:09:c3:92" and
            1609233559 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2abd2eef14d480dfea9ca9fdd823cf03 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BE SOL d.o.o." and
            pe.signatures[i].serial == "2a:bd:2e:ef:14:d4:80:df:ea:9c:a9:fd:d8:23:cf:03" and
            1611100800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_86909b91f07f9316984d888d1e28ab76 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dantherm Intelligent Monitoring A/S" and (
                pe.signatures[i].serial == "00:86:90:9b:91:f0:7f:93:16:98:4d:88:8d:1e:28:ab:76" or
                pe.signatures[i].serial == "86:90:9b:91:f0:7f:93:16:98:4d:88:8d:1e:28:ab:76"
            ) and
            1611273600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d1b8f1fe56381befdb2e73ffef2a4b28 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sein\\xC3\\xA4joen Squash ja Bowling Oy" and (
                pe.signatures[i].serial == "00:d1:b8:f1:fe:56:38:1b:ef:db:2e:73:ff:ef:2a:4b:28" or
                pe.signatures[i].serial == "d1:b8:f1:fe:56:38:1b:ef:db:2e:73:ff:ef:2a:4b:28"
            ) and
            1617667200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d4ef1ab6ab5d3cb35e4efb7984def7a2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REIGN BROS ApS" and (
                pe.signatures[i].serial == "00:d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2" or
                pe.signatures[i].serial == "d4:ef:1a:b6:ab:5d:3c:b3:5e:4e:fb:79:84:de:f7:a2"
            ) and
            1611187200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_066276af2f2c7e246d3b1cab1b4aa42e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IQ Trade ApS" and
            pe.signatures[i].serial == "06:62:76:af:2f:2c:7e:24:6d:3b:1c:ab:1b:4a:a4:2e" and
            1616630400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_65cd323c2483668b90a44a711d2a6b98 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Giperion" and
            pe.signatures[i].serial == "65:cd:32:3c:24:83:66:8b:90:a4:4a:71:1d:2a:6b:98" and
            1602547200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5a17d5de74fd8f09df596df3123139bb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ACTA FIS d.o.o." and
            pe.signatures[i].serial == "5a:17:d5:de:74:fd:8f:09:df:59:6d:f3:12:31:39:bb" and
            1611273600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_15da61d7e1a631803431561674fb9b90 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JAY DANCE STUDIO d.o.o." and
            pe.signatures[i].serial == "15:da:61:d7:e1:a6:31:80:34:31:56:16:74:fb:9b:90" and
            1610668800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7ab21306b11ff280a93fc445876988ab {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABC BIOS d.o.o." and
            pe.signatures[i].serial == "7a:b2:13:06:b1:1f:f2:80:a9:3f:c4:45:87:69:88:ab" and
            1611014400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_634e16e38f12e9a71aca08e4c6b2dbb9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AUTO RESPONSE LTD CYF" and
            pe.signatures[i].serial == "63:4e:16:e3:8f:12:e9:a7:1a:ca:08:e4:c6:b2:db:b9" and
            1616112000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_289051a83f350a2c600187c99b6c0a73 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HALL HAULAGE LTD LTD" and
            pe.signatures[i].serial == "28:90:51:a8:3f:35:0a:2c:60:01:87:c9:9b:6c:0a:73" and
            1616716800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_818631110b5d14331dac7e6ad998b902 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "2 TOY GUYS LLC" and (
                pe.signatures[i].serial == "00:81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02" or
                pe.signatures[i].serial == "81:86:31:11:0b:5d:14:33:1d:ac:7e:6a:d9:98:b9:02"
            ) and
            1571616000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_277cd16de5d61b9398b645afe41c09c7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE SIGN COMPANY LIMITED" and
            pe.signatures[i].serial == "27:7c:d1:6d:e5:d6:1b:93:98:b6:45:af:e4:1c:09:c7" and
            1619049600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d0eda76c13d30c97015708790bb94214 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LAEN ApS" and (
                pe.signatures[i].serial == "00:d0:ed:a7:6c:13:d3:0c:97:01:57:08:79:0b:b9:42:14" or
                pe.signatures[i].serial == "d0:ed:a7:6c:13:d3:0c:97:01:57:08:79:0b:b9:42:14"
            ) and
            1619136000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6333ed618f88a05b4d82ad7bf66cb0fa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RHM LIMITED" and
            pe.signatures[i].serial == "63:33:ed:61:8f:88:a0:5b:4d:82:ad:7b:f6:6c:b0:fa" and
            1616457600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3b777165b125bccc181d0bac3f5b55b3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STAND ALONE MUSIC LTD" and
            pe.signatures[i].serial == "3b:77:71:65:b1:25:bc:cc:18:1d:0b:ac:3f:5b:55:b3" and
            1607299200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5b37ac3479283b6f9d75ddf0f8742d06 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ART BOOK PHOTO s.r.o." and
            pe.signatures[i].serial == "5b:37:ac:34:79:28:3b:6f:9d:75:dd:f0:f8:74:2d:06" and
            1619740800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3112c69d460c781fd649c71e61bfec82 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KREATURHANDLER BJARNE ANDERSEN ApS" and
            pe.signatures[i].serial == "31:12:c6:9d:46:0c:78:1f:d6:49:c7:1e:61:bf:ec:82" and
            1614902400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a5b4f67ad8b22afc2debe6ce5f8f679 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Farad LLC" and
            pe.signatures[i].serial == "0a:5b:4f:67:ad:8b:22:af:c2:de:be:6c:e5:f8:f6:79" and
            1607472000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_df45b36c9d0bd248c3f9494e7ca822 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MPO STORITVE d.o.o." and (
                pe.signatures[i].serial == "00:df:45:b3:6c:9d:0b:d2:48:c3:f9:49:4e:7c:a8:22" or
                pe.signatures[i].serial == "df:45:b3:6c:9d:0b:d2:48:c3:f9:49:4e:7c:a8:22"
            ) and
            1619740800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1ae3c4eccecda2127d43be390a850dda {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PARTYNET LIMITED" and
            pe.signatures[i].serial == "1a:e3:c4:ec:ce:cd:a2:12:7d:43:be:39:0a:85:0d:da" and
            1614902400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2e36360538624c9b1afd78a2fb756028 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ts Trade ApS" and
            pe.signatures[i].serial == "2e:36:36:05:38:62:4c:9b:1a:fd:78:a2:fb:75:60:28" and
            1615766400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_addb899f8229fd53e6435e08bbd3a733 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "U.K. STEEL EXPORTS LIMITED" and (
                pe.signatures[i].serial == "00:ad:db:89:9f:82:29:fd:53:e6:43:5e:08:bb:d3:a7:33" or
                pe.signatures[i].serial == "ad:db:89:9f:82:29:fd:53:e6:43:5e:08:bb:d3:a7:33"
            ) and
            1616630400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c1a1db95d7bf80290aa6e82d8f8f996a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Software Two Pty Ltd" and (
                pe.signatures[i].serial == "00:c1:a1:db:95:d7:bf:80:29:0a:a6:e8:2d:8f:8f:99:6a" or
                pe.signatures[i].serial == "c1:a1:db:95:d7:bf:80:29:0a:a6:e8:2d:8f:8f:99:6a"
            ) and
            1615334400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c667ffe3a5b0a5ae7cf3a9e41682e91b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and (
                pe.signatures[i].serial == "00:c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b" or
                pe.signatures[i].serial == "c6:67:ff:e3:a5:b0:a5:ae:7c:f3:a9:e4:16:82:e9:1b"
            ) and
            1616976000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e0a83917660d05cf476374659d3c7b85 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PIK MOTEL S.R.L." and (
                pe.signatures[i].serial == "00:e0:a8:39:17:66:0d:05:cf:47:63:74:65:9d:3c:7b:85" or
                pe.signatures[i].serial == "e0:a8:39:17:66:0d:05:cf:47:63:74:65:9d:3c:7b:85"
            ) and
            1621468800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_afc5522898143aafaab7fd52304cf00c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "YAN CHING LIMITED" and (
                pe.signatures[i].serial == "00:af:c5:52:28:98:14:3a:af:aa:b7:fd:52:30:4c:f0:0c" or
                pe.signatures[i].serial == "af:c5:52:28:98:14:3a:af:aa:b7:fd:52:30:4c:f0:0c"
            ) and
            1622419200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8b3333d32b2c2a1d33b41ba5db9d4d2d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BOOK CAF\\xC3\\x89, s.r.o." and (
                pe.signatures[i].serial == "00:8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d" or
                pe.signatures[i].serial == "8b:33:33:d3:2b:2c:2a:1d:33:b4:1b:a5:db:9d:4d:2d"
            ) and
            1620000000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fbb1198bd8bddb0d693eb72a8613fe3f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Trade Hunters, s. r. o." and (
                pe.signatures[i].serial == "00:fb:b1:19:8b:d8:bd:db:0d:69:3e:b7:2a:86:13:fe:3f" or
                pe.signatures[i].serial == "fb:b1:19:8b:d8:bd:db:0d:69:3e:b7:2a:86:13:fe:3f"
            ) and
            1620000000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_846f77d9919fc4405aefe1701309bd67 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IPM Skupina d.o.o." and (
                pe.signatures[i].serial == "00:84:6f:77:d9:91:9f:c4:40:5a:ef:e1:70:13:09:bd:67" or
                pe.signatures[i].serial == "84:6f:77:d9:91:9f:c4:40:5a:ef:e1:70:13:09:bd:67"
            ) and
            1621382400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0939c2bad859c0432e8e98a6c0162c02 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Activ Expeditions ApS" and
            pe.signatures[i].serial == "09:39:c2:ba:d8:59:c0:43:2e:8e:98:a6:c0:16:2c:02" and
            1615939200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7fba0e19919ac50d700ba60250d02c8b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Diamartis" and
            pe.signatures[i].serial == "7f:ba:0e:19:91:9a:c5:0d:70:0b:a6:02:50:d0:2c:8b" and
            1623196800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a758504e7971869d0aec2775fffa03d5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Amcert LLC" and (
                pe.signatures[i].serial == "00:a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5" or
                pe.signatures[i].serial == "a7:58:50:4e:79:71:86:9d:0a:ec:27:75:ff:fa:03:d5"
            ) and
            1623628800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_37a67cf754ee5ae284b4cf8b9d651604 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORTH PROPERTY LTD" and
            pe.signatures[i].serial == "37:a6:7c:f7:54:ee:5a:e2:84:b4:cf:8b:9d:65:16:04" and
            1617321600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_119acead668bad57a48b4f42f294f8f0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PB03 TRANSPORT LTD." and
            pe.signatures[i].serial == "11:9a:ce:ad:66:8b:ad:57:a4:8b:4f:42:f2:94:f8:f0" and
            1619654400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7a6d30a6eb2fa0c3369283725704ac4c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Trade By International ApS" and
            pe.signatures[i].serial == "7a:6d:30:a6:eb:2f:a0:c3:36:92:83:72:57:04:ac:4c" and
            1619568000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_670c3494206b9f0c18714fdcffaaa42f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ADRIATIK PORT SERVIS, d.o.o." and
            pe.signatures[i].serial == "67:0c:34:94:20:6b:9f:0c:18:71:4f:dc:ff:aa:a4:2f" and
            1622160000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0e8aa328af207ce8bcae1dc15c626188 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PRO SAT SRL" and
            pe.signatures[i].serial == "0e:8a:a3:28:af:20:7c:e8:bc:ae:1d:c1:5c:62:61:88" and
            1627344000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cfad6be1d823b4eacb803b720f525a7d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sistema LLC" and (
                pe.signatures[i].serial == "00:cf:ad:6b:e1:d8:23:b4:ea:cb:80:3b:72:0f:52:5a:7d" or
                pe.signatures[i].serial == "cf:ad:6b:e1:d8:23:b4:ea:cb:80:3b:72:0f:52:5a:7d"
            ) and
            1627430400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7ebcb54b7e0e6410b28610de0743d4dd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SIA \"MWorx\"" and
            pe.signatures[i].serial == "7e:bc:b5:4b:7e:0e:64:10:b2:86:10:de:07:43:d4:dd" and
            1625616000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_01106cc293772ca905a2b6eff02bf0f5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DMR Consulting Ltd." and
            pe.signatures[i].serial == "01:10:6c:c2:93:77:2c:a9:05:a2:b6:ef:f0:2b:f0:f5" and
            1627084800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_05bb162f6efe852b7bd4712fd737a61e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Wellpro Impact Solutions Oy" and
            pe.signatures[i].serial == "05:bb:16:2f:6e:fe:85:2b:7b:d4:71:2f:d7:37:a6:1e" and
            1628726400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6171990ba1c8e71049ebb296a35bd160 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OWLNET LIMITED" and
            pe.signatures[i].serial == "61:71:99:0b:a1:c8:e7:10:49:eb:b2:96:a3:5b:d1:60" and
            1620000000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2114ca3bd2afd63d7fa29d744992b043 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MATCH CONSULTANTS LTD" and
            pe.signatures[i].serial == "21:14:ca:3b:d2:af:d6:3d:7f:a2:9d:74:49:92:b0:43" and
            1625097600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6aaa62208a3a78bfac1443007d031e61 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Solar LLC" and
            pe.signatures[i].serial == "6a:aa:62:20:8a:3a:78:bf:ac:14:43:00:7d:03:1e:61" and
            1608163200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_09450b8f73ea43e39d2cdd56049dbe40 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE4\\xB9\\x9D\\xE6\\xB1\\x9F\\xE5\\xAE\\x8F\\xE5\\x9B\\xBE\\xE6\\x97\\xA0\\xE5\\xBF\\xA7\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "09:45:0b:8f:73:ea:43:e3:9d:2c:dd:56:04:9d:be:40" and
            1561602110 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0efd9bd4b4281c6522d96011df46c9c4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE9\\x9B\\xB7\\xE7\\xA5\\x9E\\xEF\\xBC\\x88\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xEF\\xBC\\x89\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "0e:fd:9b:d4:b4:28:1c:65:22:d9:60:11:df:46:c9:c4" and
            1586249095 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0dd7d4a785990584d8c0837659173272 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE9\\x9B\\xB7\\xE7\\xA5\\x9E\\xEF\\xBC\\x88\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xEF\\xBC\\x89\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "0d:d7:d4:a7:85:99:05:84:d8:c0:83:76:59:17:32:72" and
            1586249095 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c59d46580f039af2c4ab6ba0ffed197 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\xA4\\xA7\\xE8\\xBF\\x9E\\xE7\\xBA\\xB5\\xE6\\xA2\\xA6\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "0c:59:d4:65:80:f0:39:af:2c:4a:b6:ba:0f:fe:d1:97" and
            1585108595 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0448ec8d26597f99912138500cc41c1b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\xA4\\xA7\\xE8\\xBF\\x9E\\xE7\\xBA\\xB5\\xE6\\xA2\\xA6\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "04:48:ec:8d:26:59:7f:99:91:21:38:50:0c:c4:1c:1b" and
            1585108595 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0108cbaee60728f5bf06e45a56d6f170 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xE4\\xB8\\x9C\\xE6\\xB9\\x96\\xE6\\x96\\xB0\\xE6\\x8A\\x80\\xE6\\x9C\\xAF\\xE5\\xBC\\x80\\xE5\\x8F\\x91\\xE5\\x8C\\xBA" and
            pe.signatures[i].serial == "01:08:cb:ae:e6:07:28:f5:bf:06:e4:5a:56:d6:f1:70" and
            1605680260 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_038d56a12153e8b5c74c69bff65cbe3f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\xAD\\xA6\\xE6\\xB1\\x89\\xE5\\x86\\x85\\xE7\\x91\\x9F\\xE6\\x96\\xAF\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "03:8d:56:a1:21:53:e8:b5:c7:4c:69:bf:f6:5c:be:3f" and
            1605680260 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_060d94e2ccae84536654d9daf39fef1e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HasCred ApS" and
            pe.signatures[i].serial == "06:0d:94:e2:cc:ae:84:53:66:54:d9:da:f3:9f:ef:1e" and
            1627948800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0bc9b800f480691bd6b60963466b0c75 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HasCred ApS" and
            pe.signatures[i].serial == "0b:c9:b8:00:f4:80:69:1b:d6:b6:09:63:46:6b:0c:75" and
            1629158400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c4324ff41f0a7b16ffcc93dffa8fa99 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE7\\xA6\\x8F\\xE5\\xBB\\xBA\\xE7\\x9C\\x81\\xE4\\xBA\\x94\\xE6\\x98\\x9F\\xE4\\xBF\\xA1\\xE6\\x81\\xAF\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "0c:43:24:ff:41:f0:a7:b1:6f:fc:c9:3d:ff:a8:fa:99" and
            1600300800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0b980fc8783e4f158e41829ab21bab81 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Idris Kanchwala Holding Corp." and
            pe.signatures[i].serial == "0b:98:0f:c8:78:3e:4f:15:8e:41:82:9a:b2:1b:ab:81" and
            1631750400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d8f515715aeffef0a0e4e37f16c254fa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HOLDING LA LTD" and (
                pe.signatures[i].serial == "00:d8:f5:15:71:5a:ef:fe:f0:a0:e4:e3:7f:16:c2:54:fa" or
                pe.signatures[i].serial == "d8:f5:15:71:5a:ef:fe:f0:a0:e4:e3:7f:16:c2:54:fa"
            ) and
            1619136000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d79739187c585e453c00afc11d77b523 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SAN MARINO INVESTMENTS PTY LTD" and (
                pe.signatures[i].serial == "00:d7:97:39:18:7c:58:5e:45:3c:00:af:c1:1d:77:b5:23" or
                pe.signatures[i].serial == "d7:97:39:18:7c:58:5e:45:3c:00:af:c1:1d:77:b5:23"
            ) and
            1631059200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_961cecb0227845317549e9343a980e91 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AmiraCo Oy" and (
                pe.signatures[i].serial == "00:96:1c:ec:b0:22:78:45:31:75:49:e9:34:3a:98:0e:91" or
                pe.signatures[i].serial == "96:1c:ec:b0:22:78:45:31:75:49:e9:34:3a:98:0e:91"
            ) and
            1615248000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1ef6392b2993a6f67578299659467ea8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALUSEN d. o. o." and
            pe.signatures[i].serial == "1e:f6:39:2b:29:93:a6:f6:75:78:29:96:59:46:7e:a8" and
            1618531200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a918455c0d4da7ca474f41f11a7cf38c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MIDDRA INTERNATIONAL CORP." and (
                pe.signatures[i].serial == "00:a9:18:45:5c:0d:4d:a7:ca:47:4f:41:f1:1a:7c:f3:8c" or
                pe.signatures[i].serial == "a9:18:45:5c:0d:4d:a7:ca:47:4f:41:f1:1a:7c:f3:8c"
            ) and
            1618963200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_936bc256d2057ca9b9ec3034c3ed0ee6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SALES & MAINTENANCE LIMITED" and (
                pe.signatures[i].serial == "00:93:6b:c2:56:d2:05:7c:a9:b9:ec:30:34:c3:ed:0e:e6" or
                pe.signatures[i].serial == "93:6b:c2:56:d2:05:7c:a9:b9:ec:30:34:c3:ed:0e:e6"
            ) and
            1616889600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_afe8fee94b41422e01e4897bcd52d0a4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TLGM ApS" and (
                pe.signatures[i].serial == "00:af:e8:fe:e9:4b:41:42:2e:01:e4:89:7b:cd:52:d0:a4" or
                pe.signatures[i].serial == "af:e8:fe:e9:4b:41:42:2e:01:e4:89:7b:cd:52:d0:a4"
            ) and
            1617062400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_718e89ddb33257ea77ba74be7f2baf1d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Trap Capital ApS" and
            pe.signatures[i].serial == "71:8e:89:dd:b3:32:57:ea:77:ba:74:be:7f:2b:af:1d" and
            1635462927 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4d3e38f4aebbc32257450726b29be117 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "POLE & AERIAL FITNESS LIMITED" and
            pe.signatures[i].serial == "4d:3e:38:f4:ae:bb:c3:22:57:45:07:26:b2:9b:e1:17" and
            1636123882 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8f4c49dae1f1ff0ebe9104c6f73242bd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Contact Merger Holding ApS" and (
                pe.signatures[i].serial == "00:8f:4c:49:da:e1:f1:ff:0e:be:91:04:c6:f7:32:42:bd" or
                pe.signatures[i].serial == "8f:4c:49:da:e1:f1:ff:0e:be:91:04:c6:f7:32:42:bd"
            ) and
            1636039748 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ac3c05f1cb9453de8e7110f589fb32c0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TRAIN BUILDING TEAM s.r.o." and (
                pe.signatures[i].serial == "00:ac:3c:05:f1:cb:94:53:de:8e:71:10:f5:89:fb:32:c0" or
                pe.signatures[i].serial == "ac:3c:05:f1:cb:94:53:de:8e:71:10:f5:89:fb:32:c0"
            ) and
            1635854205 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fbb96a90b6718810311767ca25ab1e48 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rakurs LLC" and (
                pe.signatures[i].serial == "00:fb:b9:6a:90:b6:71:88:10:31:17:67:ca:25:ab:1e:48" or
                pe.signatures[i].serial == "fb:b9:6a:90:b6:71:88:10:31:17:67:ca:25:ab:1e:48"
            ) and
            1636046757 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cfd38423aef875a10b16644d058297e2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TRUST DANMARK ApS" and (
                pe.signatures[i].serial == "00:cf:d3:84:23:ae:f8:75:a1:0b:16:64:4d:05:82:97:e2" or
                pe.signatures[i].serial == "cf:d3:84:23:ae:f8:75:a1:0b:16:64:4d:05:82:97:e2"
            ) and
            1632884040 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e6c05c5a2222bf92818324a3a7374ad3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ANAQA EVENTS LTD" and (
                pe.signatures[i].serial == "00:e6:c0:5c:5a:22:22:bf:92:81:83:24:a3:a7:37:4a:d3" or
                pe.signatures[i].serial == "e6:c0:5c:5a:22:22:bf:92:81:83:24:a3:a7:37:4a:d3"
            ) and
            1634720407 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_75ce08bdbad44123299dbe9d7c1d20de {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rose Holm International ApS" and
            pe.signatures[i].serial == "75:ce:08:bd:ba:d4:41:23:29:9d:be:9d:7c:1d:20:de" and
            1631007095 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_333705c20b56e57f60b5eb191eef0d90 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TASK Holding ApS" and
            pe.signatures[i].serial == "33:37:05:c2:0b:56:e5:7f:60:b5:eb:19:1e:ef:0d:90" and
            1634233052 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a2a0ba281262acce7a00119e25564386 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sopiteks LLC" and (
                pe.signatures[i].serial == "00:a2:a0:ba:28:12:62:ac:ce:7a:00:11:9e:25:56:43:86" or
                pe.signatures[i].serial == "a2:a0:ba:28:12:62:ac:ce:7a:00:11:9e:25:56:43:86"
            ) and
            1631908320 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_338483cc174c16ebc454a3803ffd4217 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lpr:n Laatu-Ravintolat Oy" and
            pe.signatures[i].serial == "33:84:83:cc:17:4c:16:eb:c4:54:a3:80:3f:fd:42:17" and
            1635208206 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_be89936c26cd0d845074f6b7b47f480c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Argus Security Maintenance Systems Inc." and (
                pe.signatures[i].serial == "00:be:89:93:6c:26:cd:0d:84:50:74:f6:b7:b4:7f:48:0c" or
                pe.signatures[i].serial == "be:89:93:6c:26:cd:0d:84:50:74:f6:b7:b4:7f:48:0c"
            ) and
            1634235015 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0f20a5155e53ce20bb644f646ed6a2fd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CB CAM SP Z O O" and
            pe.signatures[i].serial == "0f:20:a5:15:5e:53:ce:20:bb:64:4f:64:6e:d6:a2:fd" and
            1635196200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ea734e1dfb6e69ed2bc55e513bf95b5e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Postmarket LLC" and (
                pe.signatures[i].serial == "00:ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e" or
                pe.signatures[i].serial == "ea:73:4e:1d:fb:6e:69:ed:2b:c5:5e:51:3b:f9:5b:5e"
            ) and
            1635153791 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ba67b0de51ebb9b1179804e75357ab26 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Fjordland Bike Wear ApS" and (
                pe.signatures[i].serial == "00:ba:67:b0:de:51:eb:b9:b1:17:98:04:e7:53:57:ab:26" or
                pe.signatures[i].serial == "ba:67:b0:de:51:eb:b9:b1:17:98:04:e7:53:57:ab:26"
            ) and
            1636145940 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cff2b275ba8a1dde83ac7ff858399a62 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "XL-FORCE ApS" and (
                pe.signatures[i].serial == "00:cf:f2:b2:75:ba:8a:1d:de:83:ac:7f:f8:58:39:9a:62" or
                pe.signatures[i].serial == "cf:f2:b2:75:ba:8a:1d:de:83:ac:7f:f8:58:39:9a:62"
            ) and
            1636111842 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d22e026c5b5966f1cf6ef00a7c06682e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMCERT, LLC" and (
                pe.signatures[i].serial == "00:d2:2e:02:6c:5b:59:66:f1:cf:6e:f0:0a:7c:06:68:2e" or
                pe.signatures[i].serial == "d2:2e:02:6c:5b:59:66:f1:cf:6e:f0:0a:7c:06:68:2e"
            ) and
            1636456620 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3054f940c931bad7b238a24376c6a5cc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "POLE CLEAN LTD" and
            pe.signatures[i].serial == "30:54:f9:40:c9:31:ba:d7:b2:38:a2:43:76:c6:a5:cc" and
            1637030220 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a617e23d6ca8f34e2f7413cd299fc72b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EXPRESS BOOKS LTD" and (
                pe.signatures[i].serial == "00:a6:17:e2:3d:6c:a8:f3:4e:2f:74:13:cd:29:9f:c7:2b" or
                pe.signatures[i].serial == "a6:17:e2:3d:6c:a8:f3:4e:2f:74:13:cd:29:9f:c7:2b"
            ) and
            1636971821 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_387eeb89b8bf626bbf4c7c9f5b998b40 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ULTRA ACADEMY LTD" and
            pe.signatures[i].serial == "38:7e:eb:89:b8:bf:62:6b:bf:4c:7c:9f:5b:99:8b:40" and
            1637141034 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_292eb1133507f42e6f36c5549c189d5e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Affairs-case s.r.o." and
            pe.signatures[i].serial == "29:2e:b1:13:35:07:f4:2e:6f:36:c5:54:9c:18:9d:5e" and
            1638832273 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5fbf16a33d26390a15f046c310030cf0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MACHINES SATU MARE SRL" and
            pe.signatures[i].serial == "5f:bf:16:a3:3d:26:39:0a:15:f0:46:c3:10:03:0c:f0" and
            1638390070 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0f007898afcba5f8af8ae65d01803617 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TechnoElek s.r.o." and
            pe.signatures[i].serial == "0f:00:78:98:af:cb:a5:f8:af:8a:e6:5d:01:80:36:17" and
            1638372946 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e55be88ddbd93c423220468d430905dd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VALVE ACTUATION LTD" and (
                pe.signatures[i].serial == "00:e5:5b:e8:8d:db:d9:3c:42:32:20:46:8d:43:09:05:dd" or
                pe.signatures[i].serial == "e5:5b:e8:8d:db:d9:3c:42:32:20:46:8d:43:09:05:dd"
            ) and
            1637712000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06bcb74291d96096577bdb1e165dce85 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Revo Security SRL" and
            pe.signatures[i].serial == "06:bc:b7:42:91:d9:60:96:57:7b:db:1e:16:5d:ce:85" and
            1637971201 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c8442a8185082ef1ed7dc3fff2176aa7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ambidekstr LLC" and (
                pe.signatures[i].serial == "00:c8:44:2a:81:85:08:2e:f1:ed:7d:c3:ff:f2:17:6a:a7" or
                pe.signatures[i].serial == "c8:44:2a:81:85:08:2e:f1:ed:7d:c3:ff:f2:17:6a:a7"
            ) and
            1616976000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0406c4a1521a38c8d0c4aa214388e4dc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Venezia Design SRL" and
            pe.signatures[i].serial == "04:06:c4:a1:52:1a:38:c8:d0:c4:aa:21:43:88:e4:dc" and
            1641859201 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_12705fb66bc22c68372a1c4e5fa662e2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "APRIL BROTHERS LTD" and
            pe.signatures[i].serial == "12:70:5f:b6:6b:c2:2c:68:37:2a:1c:4e:5f:a6:62:e2" and
            1642464000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3b0914e2982be8980aa23f49848555e5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Office Rat s.r.o." and
            pe.signatures[i].serial == "3b:09:14:e2:98:2b:e8:98:0a:a2:3f:49:84:85:55:e5" and
            1643155200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_029bf7e1cb09fe277564bd27c267de5a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SAMOYAJ LIMITED" and
            pe.signatures[i].serial == "02:9b:f7:e1:cb:09:fe:27:75:64:bd:27:c2:67:de:5a" and
            1637712001 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d3aee8abb9948844a3ac1c04cc7e6bdf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HOUSE 9A s.r.o" and (
                pe.signatures[i].serial == "00:d3:ae:e8:ab:b9:94:88:44:a3:ac:1c:04:cc:7e:6b:df" or
                pe.signatures[i].serial == "d3:ae:e8:ab:b9:94:88:44:a3:ac:1c:04:cc:7e:6b:df"
            ) and
            1640822400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_734819463c1195bd6e135ce4d5bf49bc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "videoalarm s. r. o." and
            pe.signatures[i].serial == "73:48:19:46:3c:11:95:bd:6e:13:5c:e4:d5:bf:49:bc" and
            1637884800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_db95b22362d46a73c39e0ac924883c5b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SPSLTD PLYMOUTH LTD" and (
                pe.signatures[i].serial == "00:db:95:b2:23:62:d4:6a:73:c3:9e:0a:c9:24:88:3c:5b" or
                pe.signatures[i].serial == "db:95:b2:23:62:d4:6a:73:c3:9e:0a:c9:24:88:3c:5b"
            ) and
            1621296000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c48732873ac8ccebaf8f0e1e8329cec {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hermetica Digital Ltd" and
            pe.signatures[i].serial == "0c:48:73:28:73:ac:8c:ce:ba:f8:f0:e1:e8:32:9c:ec" and
            1618272000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c51f4cf4d82bc920421e1ad93e39d490 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CUT AHEAD LTD" and (
                pe.signatures[i].serial == "00:c5:1f:4c:f4:d8:2b:c9:20:42:1e:1a:d9:3e:39:d4:90" or
                pe.signatures[i].serial == "c5:1f:4c:f4:d8:2b:c9:20:42:1e:1a:d9:3e:39:d4:90"
            ) and
            1644624000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c96086f1894e6420d2b4bdeea834c4d7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE FAITH SP Z O O" and (
                pe.signatures[i].serial == "00:c9:60:86:f1:89:4e:64:20:d2:b4:bd:ee:a8:34:c4:d7" or
                pe.signatures[i].serial == "c9:60:86:f1:89:4e:64:20:d2:b4:bd:ee:a8:34:c4:d7"
            ) and
            1644969600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06fa27a121cc82230c3013ee634b6c62 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Zimmi Consulting Inc" and
            pe.signatures[i].serial == "06:fa:27:a1:21:cc:82:23:0c:30:13:ee:63:4b:6c:62" and
            1645142401 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9dd3b2f7957ba99f4b04fcdbe03b7aac {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DOD MEDIA LIMITED" and (
                pe.signatures[i].serial == "00:9d:d3:b2:f7:95:7b:a9:9f:4b:04:fc:db:e0:3b:7a:ac" or
                pe.signatures[i].serial == "9d:d3:b2:f7:95:7b:a9:9f:4b:04:fc:db:e0:3b:7a:ac"
            ) and
            1646438400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_061051ff2a8afab10347a6f1ff08ecb6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TACHOPARTS SP Z O O" and
            pe.signatures[i].serial == "06:10:51:ff:2a:8a:fa:b1:03:47:a6:f1:ff:08:ec:b6" and
            1606435200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_eda2429083bfafb04e6e7bdda1b08834 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OWLNET LIMITED" and (
                pe.signatures[i].serial == "00:ed:a2:42:90:83:bf:af:b0:4e:6e:7b:dd:a1:b0:88:34" or
                pe.signatures[i].serial == "ed:a2:42:90:83:bf:af:b0:4e:6e:7b:dd:a1:b0:88:34"
            ) and
            1625011200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a590154b5980e566314122987dea548 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Maya logistika d.o.o." and
            pe.signatures[i].serial == "0a:59:01:54:b5:98:0e:56:63:14:12:29:87:de:a5:48" and
            1636416000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_69a72f5591ad78a0825fbb9402ab9543 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PUSH BANK LIMITED" and
            pe.signatures[i].serial == "69:a7:2f:55:91:ad:78:a0:82:5f:bb:94:02:ab:95:43" and
            1581811200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0883db137021b51f3a2a08a76a4bc066 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Divertida Creative Limited" and
            pe.signatures[i].serial == "08:83:db:13:70:21:b5:1f:3a:2a:08:a7:6a:4b:c0:66" and
            1627430400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2b921aaaba777b5a99507196c6f1c46c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Python Software Foundation" and
            pe.signatures[i].serial == "2b:92:1a:aa:ba:77:7b:5a:99:50:71:96:c6:f1:c4:6c" and
            1648425600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0332d5c942869bdcabf5a8266197cd14 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JAWRO SP Z O O" and
            pe.signatures[i].serial == "03:32:d5:c9:42:86:9b:dc:ab:f5:a8:26:61:97:cd:14" and
            1622160000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4679c5398a279318365fd77a84445699 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HURT GROUP HOLDINGS LIMITED" and
            pe.signatures[i].serial == "46:79:c5:39:8a:27:93:18:36:5f:d7:7a:84:44:56:99" and
            1643846400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_101d6a5a29d9a77807553ceac669d853 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIC GROUP LIMITED" and
            pe.signatures[i].serial == "10:1d:6a:5a:29:d9:a7:78:07:55:3c:ea:c6:69:d8:53" and
            1646352000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6000f8c02b0a15b1e53b8399845faddf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SAY LIMITED" and
            pe.signatures[i].serial == "60:00:f8:c0:2b:0a:15:b1:e5:3b:83:99:84:5f:ad:df" and
            1644278400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_121070be1e782f206985543bc7bc58b6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Prod Can Holdings Inc." and
            pe.signatures[i].serial == "12:10:70:be:1e:78:2f:20:69:85:54:3b:c7:bc:58:b6" and
            1647820800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5226a724cfa0b4bc0164ecda3f02a3dc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VALENTE SP Z O O" and
            pe.signatures[i].serial == "52:26:a7:24:cf:a0:b4:bc:01:64:ec:da:3f:02:a3:dc" and
            1647302400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a7be7722b65a866ebcd3bd7f8f10825 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rebound Infotech Limited" and
            pe.signatures[i].serial == "0a:7b:e7:72:2b:65:a8:66:eb:cd:3b:d7:f8:f1:08:25" and
            1637971200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_05634456dbedb3556ca8415e64815c5d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Walden Intertech Inc." and
            pe.signatures[i].serial == "05:63:44:56:db:ed:b3:55:6c:a8:41:5e:64:81:5c:5d" and
            1648425600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2e07a8d6e3b25ae010c8ed2c4ab0fb37 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Emurasoft, Inc." and
            pe.signatures[i].serial == "2e:07:a8:d6:e3:b2:5a:e0:10:c8:ed:2c:4a:b0:fb:37" and
            1650499200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_30b4eeebd88fd205acc8577bbaed8655 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Enforcer Srl" and
            pe.signatures[i].serial == "30:b4:ee:eb:d8:8f:d2:05:ac:c8:57:7b:ba:ed:86:55" and
            1646179200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b3391a6c1b3c6836533959e2384ab4ca {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VERIFIED SOFTWARE LLC" and (
                pe.signatures[i].serial == "00:b3:39:1a:6c:1b:3c:68:36:53:39:59:e2:38:4a:b4:ca" or
                pe.signatures[i].serial == "b3:39:1a:6c:1b:3c:68:36:53:39:59:e2:38:4a:b4:ca"
            ) and
            1595462400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_05d50a0e09bb9a836ffb90a3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Toliz Info Tech Solutions INC." and
            pe.signatures[i].serial == "05:d5:0a:0e:09:bb:9a:83:6f:fb:90:a3" and
            1643892810 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a2787fbb4627c91611573e323584113 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "exxon.com" and
            pe.signatures[i].serial == "0a:27:87:fb:b4:62:7c:91:61:15:73:e3:23:58:41:13" and
            1640822400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1d36c4f439d651503589318f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REDWOOD MARKETING SOLUTIONS INC." and
            pe.signatures[i].serial == "1d:36:c4:f4:39:d6:51:50:35:89:31:8f" and
            1651518469 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_26f855a25890b749578f13e4b9459768 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Boo\\xE2\\x80\\x99s Q & Sweets Corporation" and
            pe.signatures[i].serial == "26:f8:55:a2:58:90:b7:49:57:8f:13:e4:b9:45:97:68" and
            1645401600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0f1ae2239bb96c5aef49d0ae50266912 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aarav Consulting Inc." and
            pe.signatures[i].serial == "0f:1a:e2:23:9b:b9:6c:5a:ef:49:d0:ae:50:26:69:12" and
            1653004800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1deea179f5757fe529043577762419df {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SPIRIT CONSULTING s. r. o." and
            pe.signatures[i].serial == "1d:ee:a1:79:f5:75:7f:e5:29:04:35:77:76:24:19:df" and
            1645401600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5b1f9ec88d185631ab032dbfd5166c0d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TOPFLIGHT GROUP LIMITED" and
            pe.signatures[i].serial == "5b:1f:9e:c8:8d:18:56:31:ab:03:2d:bf:d5:16:6c:0d" and
            1656028800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_58af00ce542760fc116b41fa92e18589 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DICKIE MUSDALE WINDFARM LIMITED" and
            pe.signatures[i].serial == "58:af:00:ce:54:27:60:fc:11:6b:41:fa:92:e1:85:89" and
            1654819200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_25ba18a267d6d8e08ebc6e2457d58d1e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "5Y TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "25:ba:18:a2:67:d6:d8:e0:8e:bc:6e:24:57:d5:8d:1e" and
            1648684800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_12df5ff3460979cec1288d874a9fbf83 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORWARD MUSIC AGENCY SRL" and
            pe.signatures[i].serial == "12:df:5f:f3:46:09:79:ce:c1:28:8d:87:4a:9f:bf:83" and
            1599091200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_df2547b2cab5689a81d61de80eaaa3a2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORWARD MUSIC AGENCY SRL" and (
                pe.signatures[i].serial == "00:df:25:47:b2:ca:b5:68:9a:81:d6:1d:e8:0e:aa:a3:a2" or
                pe.signatures[i].serial == "df:25:47:b2:ca:b5:68:9a:81:d6:1d:e8:0e:aa:a3:a2"
            ) and
            1657756800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_28b691272719b1ee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "2021945 Ontario Inc." and
            pe.signatures[i].serial == "28:b6:91:27:27:19:b1:ee" and
            1616410532 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1c897216e58e83cbe74ad03284e1fb82 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "M-Trans Maciej Caban" and
            pe.signatures[i].serial == "1c:89:72:16:e5:8e:83:cb:e7:4a:d0:32:84:e1:fb:82" and
            1639119705 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5a364c4957d93406f76321c2316f42f0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Board Game Bucket Ltd" and
            pe.signatures[i].serial == "5a:36:4c:49:57:d9:34:06:f7:63:21:c2:31:6f:42:f0" and
            1661337307 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e7e7f7180666546ce7a8da32119f5ce1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "C\\xC3\\x94NG TY TNHH PDF SOFTWARE" and (
                pe.signatures[i].serial == "00:e7:e7:f7:18:06:66:54:6c:e7:a8:da:32:11:9f:5c:e1" or
                pe.signatures[i].serial == "e7:e7:f7:18:06:66:54:6c:e7:a8:da:32:11:9f:5c:e1"
            ) and
            1661558399 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_062b2827500c5df35a83f661b3af5dd3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "*.eos.com" and
            pe.signatures[i].serial == "06:2b:28:27:50:0c:5d:f3:5a:83:f6:61:b3:af:5d:d3" and
            1651449600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7bf27695fd20b588f2b2f173b6caf2ba {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Game Warriors Limited" and
            pe.signatures[i].serial == "7b:f2:76:95:fd:20:b5:88:f2:b2:f1:73:b6:ca:f2:ba" and
            1662112800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1b248c8508042d36bbd5d92d189c61d8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Digital Robin Limited" and
            pe.signatures[i].serial == "1b:24:8c:85:08:04:2d:36:bb:d5:d9:2d:18:9c:61:d8" and
            1663171218 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_032660ee1d49ad35086027473e2614e5e724 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "sunshine.com" and
            pe.signatures[i].serial == "03:26:60:ee:1d:49:ad:35:08:60:27:47:3e:26:14:e5:e7:24" and
            1660238245 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_043052956e1e6dbd5f6ae3d8b82cad2a2ed8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ok.com" and
            pe.signatures[i].serial == "04:30:52:95:6e:1e:6d:bd:5f:6a:e3:d8:b8:2c:ad:2a:2e:d8" and
            1662149613 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_dbc03ca7e6ae6db6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SPIDER DEVELOPMENTS PTY LTD" and (
                pe.signatures[i].serial == "00:db:c0:3c:a7:e6:ae:6d:b6" or
                pe.signatures[i].serial == "db:c0:3c:a7:e6:ae:6d:b6"
            ) and
            1600826873 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7d27332c3cb3a382a4fd232c5c66a2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MALVINA RECRUITMENT LIMITED" and
            pe.signatures[i].serial == "7d:27:33:2c:3c:b3:a3:82:a4:fd:23:2c:5c:66:a2" and
            1655424000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_82d224323efa65060b641f51fadfef02 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SAVAS INVESTMENTS PTY LTD" and (
                pe.signatures[i].serial == "00:82:d2:24:32:3e:fa:65:06:0b:64:1f:51:fa:df:ef:02" or
                pe.signatures[i].serial == "82:d2:24:32:3e:fa:65:06:0b:64:1f:51:fa:df:ef:02"
            ) and
            1665100800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_890570b6b0e2868a53be3f8f904a88ee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "JESEN LESS d.o.o." and (
                pe.signatures[i].serial == "00:89:05:70:b6:b0:e2:86:8a:53:be:3f:8f:90:4a:88:ee" or
                pe.signatures[i].serial == "89:05:70:b6:b0:e2:86:8a:53:be:3f:8f:90:4a:88:ee"
            ) and
            1636588800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2642fe865f7566ce3123a5142c207094 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "C.W.D. INSTAL LTD" and
            pe.signatures[i].serial == "26:42:fe:86:5f:75:66:ce:31:23:a5:14:2c:20:70:94" and
            1666310400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4a2e337fff23e5b2a1321ffde56d1759 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Karolina Klimowska" and
            pe.signatures[i].serial == "4a:2e:33:7f:ff:23:e5:b2:a1:32:1f:fd:e5:6d:17:59" and
            1660314070 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_92d9b92f8cf7a1ba8b2c025be730c300 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "UPLagga Systems s.r.o." and (
                pe.signatures[i].serial == "00:92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00" or
                pe.signatures[i].serial == "92:d9:b9:2f:8c:f7:a1:ba:8b:2c:02:5b:e7:30:c3:00"
            ) and
            1598054400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b8164f7143e1a313003ab0c834562f1f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ekitai Data Inc." and (
                pe.signatures[i].serial == "00:b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f" or
                pe.signatures[i].serial == "b8:16:4f:71:43:e1:a3:13:00:3a:b0:c8:34:56:2f:1f"
            ) and
            1598313600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_24e4a2b3db6be1007b9ddc91995bc0c8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FLY BETTER s.r.o." and
            pe.signatures[i].serial == "24:e4:a2:b3:db:6b:e1:00:7b:9d:dc:91:99:5b:c0:c8" and
            1645142400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_881573fc67ff7395dde5bccfbce5b088 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Trade in Brasil s.r.o." and (
                pe.signatures[i].serial == "00:88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88" or
                pe.signatures[i].serial == "88:15:73:fc:67:ff:73:95:dd:e5:bc:cf:bc:e5:b0:88"
            ) and
            1620000000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_53e1f226cb77574f8fbeb5682da091bb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OdyLab Inc" and
            pe.signatures[i].serial == "53:e1:f2:26:cb:77:57:4f:8f:be:b5:68:2d:a0:91:bb" and
            1654020559 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0772b4d1d63233d2b8771997bc8da5c4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Maya logistika d.o.o." and
            pe.signatures[i].serial == "07:72:b4:d1:d6:32:33:d2:b8:77:19:97:bc:8d:a5:c4" and
            1637971201 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_02b6656292310b84022db5541bc48faf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DILA d.o.o." and
            pe.signatures[i].serial == "02:b6:65:62:92:31:0b:84:02:2d:b5:54:1b:c4:8f:af" and
            1613865600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_64c2505c7306639fc8eae544b0305338 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MANILA Solution as" and
            pe.signatures[i].serial == "64:c2:50:5c:73:06:63:9f:c8:ea:e5:44:b0:30:53:38" and
            1609418043 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2f96a89bfec6e44dd224e8fd7e72d9bb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NAILS UNLIMITED LIMITED" and
            pe.signatures[i].serial == "2f:96:a8:9b:fe:c6:e4:4d:d2:24:e8:fd:7e:72:d9:bb" and
            1625529600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b649a966410f62999c939384af553919 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "F.A.T. SARL" and (
                pe.signatures[i].serial == "00:b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19" or
                pe.signatures[i].serial == "b6:49:a9:66:41:0f:62:99:9c:93:93:84:af:55:39:19"
            ) and
            1590537600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_45245eef53fcf38169c715cf68f44452 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PAPER AND CORE SUPPLIES LTD" and
            pe.signatures[i].serial == "45:24:5e:ef:53:fc:f3:81:69:c7:15:cf:68:f4:44:52" and
            1639958400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1895433ee9e2bd48619d75132262616f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Evetrans Ltd" and
            pe.signatures[i].serial == "18:95:43:3e:e9:e2:bd:48:61:9d:75:13:22:62:61:6f" and
            1619789516 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1ffc9825644caf5b1f521780c5c7f42c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ACTIVUS LIMITED" and
            pe.signatures[i].serial == "1f:fc:98:25:64:4c:af:5b:1f:52:17:80:c5:c7:f4:2c" and
            1615507200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8d52fb12a2511e86bbb0ba75c517eab0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VThink Software Consulting Inc." and (
                pe.signatures[i].serial == "00:8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0" or
                pe.signatures[i].serial == "8d:52:fb:12:a2:51:1e:86:bb:b0:ba:75:c5:17:ea:b0"
            ) and
            1599177600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_332bd5801e8415585e72c87e0e2ec71d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Elite Marketing Strategies, Inc." and
            pe.signatures[i].serial == "33:2b:d5:80:1e:84:15:58:5e:72:c8:7e:0e:2e:c7:1d" and
            1662616824 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e3b80c0932b52a708477939b0d32186f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BISOYETUTU LTD LIMITED" and (
                pe.signatures[i].serial == "00:e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f" or
                pe.signatures[i].serial == "e3:b8:0c:09:32:b5:2a:70:84:77:93:9b:0d:32:18:6f"
            ) and
            1617062400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c79f817f082986bef3209f6723c8da97 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Al-Faris group d.o.o." and (
                pe.signatures[i].serial == "00:c7:9f:81:7f:08:29:86:be:f3:20:9f:67:23:c8:da:97" or
                pe.signatures[i].serial == "c7:9f:81:7f:08:29:86:be:f3:20:9f:67:23:c8:da:97"
            ) and
            1616371200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1e5efa53a14599cc82f56f0790e20b17 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Storeks LLC" and
            pe.signatures[i].serial == "1e:5e:fa:53:a1:45:99:cc:82:f5:6f:07:90:e2:0b:17" and
            1623196800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0cf2d0b5bfdd68cf777a0c12f806a569 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PROTIP d.o.o. - v ste\\xC4\\x8Daju" and
            pe.signatures[i].serial == "0c:f2:d0:b5:bf:dd:68:cf:77:7a:0c:12:f8:06:a5:69" and
            1611705600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f675139ea68b897a865a98f8e4611f00 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BS TEHNIK d.o.o." and (
                pe.signatures[i].serial == "00:f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00" or
                pe.signatures[i].serial == "f6:75:13:9e:a6:8b:89:7a:86:5a:98:f8:e4:61:1f:00"
            ) and
            1606953600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4728189fa0f57793484cdf764f5e283d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Power Save Systems s.r.o." and
            pe.signatures[i].serial == "47:28:18:9f:a0:f5:77:93:48:4c:df:76:4f:5e:28:3d" and
            1647302400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9bd81a9adaf71f1ff081c1f4a05d7fd7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SMART TOYS AND GAMES, INC" and (
                pe.signatures[i].serial == "00:9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7" or
                pe.signatures[i].serial == "9b:d8:1a:9a:da:f7:1f:1f:f0:81:c1:f4:a0:5d:7f:d7"
            ) and
            1601683200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c81319d20c6f1f1aec3398522189d90c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMCERT,LLC" and (
                pe.signatures[i].serial == "00:c8:13:19:d2:0c:6f:1f:1a:ec:33:98:52:21:89:d9:0c" or
                pe.signatures[i].serial == "c8:13:19:d2:0c:6f:1f:1a:ec:33:98:52:21:89:d9:0c"
            ) and
            1643500800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c318d876768258a696ab9dd825e27acd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Genezis" and (
                pe.signatures[i].serial == "00:c3:18:d8:76:76:82:58:a6:96:ab:9d:d8:25:e2:7a:cd" or
                pe.signatures[i].serial == "c3:18:d8:76:76:82:58:a6:96:ab:9d:d8:25:e2:7a:cd"
            ) and
            1615161600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06df5c318759d6ea9d090bfb2faf1d94 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SpiffyTech Inc." and
            pe.signatures[i].serial == "06:df:5c:31:87:59:d6:ea:9d:09:0b:fb:2f:af:1d:94" and
            1634515201 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_02de1cc6c487954592f1bf574ca2b000 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Orca System" and
            pe.signatures[i].serial == "02:de:1c:c6:c4:87:95:45:92:f1:bf:57:4c:a2:b0:00" and
            1613735394 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a32b8b4f1be43c23eb2848ab4ef06bb2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Pak El AB" and (
                pe.signatures[i].serial == "00:a3:2b:8b:4f:1b:e4:3c:23:eb:28:48:ab:4e:f0:6b:b2" or
                pe.signatures[i].serial == "a3:2b:8b:4f:1b:e4:3c:23:eb:28:48:ab:4e:f0:6b:b2"
            ) and
            1673395200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_626735ed30e50e3e0553986d806bfc54 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FISH ACCOUNTING & TRANSLATING LIMITED" and
            pe.signatures[i].serial == "62:67:35:ed:30:e5:0e:3e:05:53:98:6d:80:6b:fc:54" and
            1666742400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_34d42e871ddb1c92fa20b55b384e1259 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VENS CORP" and
            pe.signatures[i].serial == "34:d4:2e:87:1d:db:1c:92:fa:20:b5:5b:38:4e:12:59" and
            1630368000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08d4dc90047b8470ccaf3924dfbd8b5f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Dibies" and
            pe.signatures[i].serial == "08:d4:dc:90:04:7b:84:70:cc:af:39:24:df:bd:8b:5f" and
            1619136000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c2fc83d458e653837fcfc132c9b03062 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Vertical" and (
                pe.signatures[i].serial == "00:c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62" or
                pe.signatures[i].serial == "c2:fc:83:d4:58:e6:53:83:7f:cf:c1:32:c9:b0:30:62"
            ) and
            1602201600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_54c793d2224bdd6ca527bb2b7b9dfe9d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CODE - HANDLE, s. r. o." and
            pe.signatures[i].serial == "54:c7:93:d2:22:4b:dd:6c:a5:27:bb:2b:7b:9d:fe:9d" and
            1629676800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8cece6df54cf6ad63596546d77ba3581 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Mikael LLC" and (
                pe.signatures[i].serial == "00:8c:ec:e6:df:54:cf:6a:d6:35:96:54:6d:77:ba:35:81" or
                pe.signatures[i].serial == "8c:ec:e6:df:54:cf:6a:d6:35:96:54:6d:77:ba:35:81"
            ) and
            1613088000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_984e84cfe362e278f558e2c70aaafac2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Arctic Nights \\xC3\\x84k\\xC3\\xA4slompolo Oy" and (
                pe.signatures[i].serial == "00:98:4e:84:cf:e3:62:e2:78:f5:58:e2:c7:0a:aa:fa:c2" or
                pe.signatures[i].serial == "98:4e:84:cf:e3:62:e2:78:f5:58:e2:c7:0a:aa:fa:c2"
            ) and
            1640304000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ff52eb011bb748fee75153cbe1e50dd6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TASK ANNA LIMITED" and (
                pe.signatures[i].serial == "00:ff:52:eb:01:1b:b7:48:fe:e7:51:53:cb:e1:e5:0d:d6" or
                pe.signatures[i].serial == "ff:52:eb:01:1b:b7:48:fe:e7:51:53:cb:e1:e5:0d:d6"
            ) and
            1647388800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_84a4a0d0657e217b176b455e2465aee0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AATB ApS" and (
                pe.signatures[i].serial == "00:84:a4:a0:d0:65:7e:21:7b:17:6b:45:5e:24:65:ae:e0" or
                pe.signatures[i].serial == "84:a4:a0:d0:65:7e:21:7b:17:6b:45:5e:24:65:ae:e0"
            ) and
            1616457600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b8f726508cf1d7b7913bf4bbd1e5c19c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Merkuri LLC" and (
                pe.signatures[i].serial == "00:b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c" or
                pe.signatures[i].serial == "b8:f7:26:50:8c:f1:d7:b7:91:3b:f4:bb:d1:e5:c1:9c"
            ) and
            1619568000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6a241ffe96a6349df608d22c02942268 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HELP, d.o.o." and
            pe.signatures[i].serial == "6a:24:1f:fe:96:a6:34:9d:f6:08:d2:2c:02:94:22:68" and
            1605052800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aa1d84779792b57f91fe7a4bde041942 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AXIUM NORTHWESTERN HYDRO INC." and (
                pe.signatures[i].serial == "00:aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42" or
                pe.signatures[i].serial == "aa:1d:84:77:97:92:b5:7f:91:fe:7a:4b:de:04:19:42"
            ) and
            1639872000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3c98b6872fbb1f4ae37a4caa749d24c2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO SMART" and
            pe.signatures[i].serial == "3c:98:b6:87:2f:bb:1f:4a:e3:7a:4c:aa:74:9d:24:c2" and
            1613370100 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e4e795fd1fd25595b869ce22aa7dc49f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OASIS COURT LIMITED" and (
                pe.signatures[i].serial == "00:e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f" or
                pe.signatures[i].serial == "e4:e7:95:fd:1f:d2:55:95:b8:69:ce:22:aa:7d:c4:9f"
            ) and
            1608508800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e953ada7e8f1438e5f7680ff599ae43e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KULBYT LLC" and (
                pe.signatures[i].serial == "00:e9:53:ad:a7:e8:f1:43:8e:5f:76:80:ff:59:9a:e4:3e" or
                pe.signatures[i].serial == "e9:53:ad:a7:e8:f1:43:8e:5f:76:80:ff:59:9a:e4:3e"
            ) and
            1614729600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_28c57df09ce7cc3fde2243beb4d00101 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "WATER, s.r.o." and
            pe.signatures[i].serial == "28:c5:7d:f0:9c:e7:cc:3f:de:22:43:be:b4:d0:01:01" and
            1622678400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2d8cfcf04209dc7f771d8d18e462c35a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AA PLUS INVEST d.o.o." and
            pe.signatures[i].serial == "2d:8c:fc:f0:42:09:dc:7f:77:1d:8d:18:e4:62:c3:5a" and
            1631491200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_016836311fc39fbb8e6f308bb03cc2b3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SERVICE STREAM LIMITED" and
            pe.signatures[i].serial == "01:68:36:31:1f:c3:9f:bb:8e:6f:30:8b:b0:3c:c2:b3" and
            1602547200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_435abf46053a0a445c54217a8c233a7f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Kodemika" and
            pe.signatures[i].serial == "43:5a:bf:46:05:3a:0a:44:5c:54:21:7a:8c:23:3a:7f" and
            1616976000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b2f9c693a2e6634565f63c79b01dd8f8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PHL E STATE ApS" and (
                pe.signatures[i].serial == "00:b2:f9:c6:93:a2:e6:63:45:65:f6:3c:79:b0:1d:d8:f8" or
                pe.signatures[i].serial == "b2:f9:c6:93:a2:e6:63:45:65:f6:3c:79:b0:1d:d8:f8"
            ) and
            1620000000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_54a6d33f73129e0ef059ccf51be0c35e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "STAFFORD MEAT COMPANY, INC." and
            pe.signatures[i].serial == "54:a6:d3:3f:73:12:9e:0e:f0:59:cc:f5:1b:e0:c3:5e" and
            1607100127 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_142aac4217e22b525c8587589773ba9b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "A.B. gostinstvo trgovina posredni\\xC5\\xA1tvo in druge storitve, d.o.o." and
            pe.signatures[i].serial == "14:2a:ac:42:17:e2:2b:52:5c:85:87:58:97:73:ba:9b" and
            1614124800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_239664c12baeb5a6d787912888051392 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "FORTH PROPERTY LTD" and
            pe.signatures[i].serial == "23:96:64:c1:2b:ae:b5:a6:d7:87:91:28:88:05:13:92" and
            1618272000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0218ebfd5a9bfd55d2f661f0d18d1d71 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "REI LUX UK LIMITED" and
            pe.signatures[i].serial == "02:18:eb:fd:5a:9b:fd:55:d2:f6:61:f0:d1:8d:1d:71" and
            1608508800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_35590ebe4a02dc23317d8ce47a947a9b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OOO Largos" and
            pe.signatures[i].serial == "35:59:0e:be:4a:02:dc:23:31:7d:8c:e4:7a:94:7a:9b" and
            1602201600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aa07d4f2857119cee514a0bd412f8201 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HANGA GIP d.o.o." and (
                pe.signatures[i].serial == "00:aa:07:d4:f2:85:71:19:ce:e5:14:a0:bd:41:2f:82:01" or
                pe.signatures[i].serial == "aa:07:d4:f2:85:71:19:ce:e5:14:a0:bd:41:2f:82:01"
            ) and
            1615766400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_40f5660a90301e7a8a8c3b42 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Booz Allen Hamilton Inc." and
            pe.signatures[i].serial == "40:f5:66:0a:90:30:1e:7a:8a:8c:3b:42" and
            1641833688 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0400c7614f86d75fe4ee3f6192b6feda {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "StackUp ApS" and
            pe.signatures[i].serial == "04:00:c7:61:4f:86:d7:5f:e4:ee:3f:61:92:b6:fe:da" and
            1626393601 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e573d9c8b403c41bd59ffa0a8efd4168 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\"VERONIKA 2\" OOO" and (
                pe.signatures[i].serial == "00:e5:73:d9:c8:b4:03:c4:1b:d5:9f:fa:0a:8e:fd:41:68" or
                pe.signatures[i].serial == "e5:73:d9:c8:b4:03:c4:1b:d5:9f:fa:0a:8e:fd:41:68"
            ) and
            1563148800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b06bc166fc765dacd2f7448c8cdd9205 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GAS Avto, d.o.o." and (
                pe.signatures[i].serial == "00:b0:6b:c1:66:fc:76:5d:ac:d2:f7:44:8c:8c:dd:92:05" or
                pe.signatures[i].serial == "b0:6b:c1:66:fc:76:5d:ac:d2:f7:44:8c:8c:dd:92:05"
            ) and
            1615507200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e9268ed63a7d7e9dfd40a664ddfbaf18 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Casta, s.r.o." and (
                pe.signatures[i].serial == "00:e9:26:8e:d6:3a:7d:7e:9d:fd:40:a6:64:dd:fb:af:18" or
                pe.signatures[i].serial == "e9:26:8e:d6:3a:7d:7e:9d:fd:40:a6:64:dd:fb:af:18"
            ) and
            1647302400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_425dc3e0ca8bcdce19d00d87e3f0ba28 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Protover LLC" and
            pe.signatures[i].serial == "42:5d:c3:e0:ca:8b:cd:ce:19:d0:0d:87:e3:f0:ba:28" and
            1621900800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_afc0ddb7bdc8207e8c3b7204018eecd3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE9\\x83\\xB4\\xE5\\xB7\\x9E\\xE8\\x9C\\x97\\xE7\\x89\\x9B\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:af:c0:dd:b7:bd:c8:20:7e:8c:3b:72:04:01:8e:ec:d3" or
                pe.signatures[i].serial == "af:c0:dd:b7:bd:c8:20:7e:8c:3b:72:04:01:8e:ec:d3"
            ) and
            1629676800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_38989ec61ecdb7391ff5647f7d58ad18 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RotA Games ApS" and
            pe.signatures[i].serial == "38:98:9e:c6:1e:cd:b7:39:1f:f5:64:7f:7d:58:ad:18" and
            1613088000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bc6c43d206a360f2d6b58537c456b709 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ANKADA GROUP, d.o.o." and (
                pe.signatures[i].serial == "00:bc:6c:43:d2:06:a3:60:f2:d6:b5:85:37:c4:56:b7:09" or
                pe.signatures[i].serial == "bc:6c:43:d2:06:a3:60:f2:d6:b5:85:37:c4:56:b7:09"
            ) and
            1616630400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4929ab561c812af93ddb9758b545f546 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Everything Wow s.r.o." and
            pe.signatures[i].serial == "49:29:ab:56:1c:81:2a:f9:3d:db:97:58:b5:45:f5:46" and
            1594252800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_25c6dbce3d5499f65d9df16e9007465d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMCERT,LLC" and
            pe.signatures[i].serial == "25:c6:db:ce:3d:54:99:f6:5d:9d:f1:6e:90:07:46:5d" and
            1626566400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bc6a1812e001362469541108973bbd52 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMCERT,LLC" and (
                pe.signatures[i].serial == "00:bc:6a:18:12:e0:01:36:24:69:54:11:08:97:3b:bd:52" or
                pe.signatures[i].serial == "bc:6a:18:12:e0:01:36:24:69:54:11:08:97:3b:bd:52"
            ) and
            1623801600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_bde1d6dc3622724f427a39e6a34f5124 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMCERT,LLC" and (
                pe.signatures[i].serial == "00:bd:e1:d6:dc:36:22:72:4f:42:7a:39:e6:a3:4f:51:24" or
                pe.signatures[i].serial == "bd:e1:d6:dc:36:22:72:4f:42:7a:39:e6:a3:4f:51:24"
            ) and
            1628553600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5c9f5f96726a6e6fc3b8bb153ac82af2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "1105 SOFTWARE LLC" and
            pe.signatures[i].serial == "5c:9f:5f:96:72:6a:6e:6f:c3:b8:bb:15:3a:c8:2a:f2" and
            1679061408 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6e889bb3b7f7194b674c6a0335a608e0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CLEVERCONTROL LLC" and
            pe.signatures[i].serial == "6e:88:9b:b3:b7:f7:19:4b:67:4c:6a:03:35:a6:08:e0" and
            1646956800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0f62f760704bdf8dc30c7baa7376f484 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shanghai XuSong investment partnership Enterprise(Limited)" and
            pe.signatures[i].serial == "0f:62:f7:60:70:4b:df:8d:c3:0c:7b:aa:73:76:f4:84" and
            1659398400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_071202dbfda40b629c5e7acac947c2d3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Crossfire Industries, LLC" and
            pe.signatures[i].serial == "07:12:02:db:fd:a4:0b:62:9c:5e:7a:ca:c9:47:c2:d3" and
            1658620801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_98ab9585c04d7f0e4cf4de98c14b684d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMCERT,LLC" and (
                pe.signatures[i].serial == "00:98:ab:95:85:c0:4d:7f:0e:4c:f4:de:98:c1:4b:68:4d" or
                pe.signatures[i].serial == "98:ab:95:85:c0:4d:7f:0e:4c:f4:de:98:c1:4b:68:4d"
            ) and
            1656547200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4631713e66e91347f0388b98cf747794 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\xB9\\xBF\\xE5\\xB7\\x9E\\xE6\\x98\\x8A\\xE5\\x8A\\xA8\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "46:31:71:3e:66:e9:13:47:f0:38:8b:98:cf:74:77:94" and
            1488240000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e963f8983d21b4c1a69c66a9d37498e5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Max Steinhard" and (
                pe.signatures[i].serial == "00:e9:63:f8:98:3d:21:b4:c1:a6:9c:66:a9:d3:74:98:e5" or
                pe.signatures[i].serial == "e9:63:f8:98:3d:21:b4:c1:a6:9c:66:a9:d3:74:98:e5"
            ) and
            1656288000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6e44fcedd49f22f7a28cecc99104f61a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "M-Trans Maciej Caban" and
            pe.signatures[i].serial == "6e:44:fc:ed:d4:9f:22:f7:a2:8c:ec:c9:91:04:f6:1a" and
            1672923378 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_35b49ee870aea532e6ef0a4987105c8f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kancelaria Adwokacka Adwokat Aleksandra Krzemi\\xC5\\x84ska" and
            pe.signatures[i].serial == "35:b4:9e:e8:70:ae:a5:32:e6:ef:0a:49:87:10:5c:8f" and
            1663151018 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_063dcd7d7b0bc77cac844c7213be3989 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "HANNAH SISK LIMITED" and
            pe.signatures[i].serial == "06:3d:cd:7d:7b:0b:c7:7c:ac:84:4c:72:13:be:39:89" and
            1656892801 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6f8777aa866142ad7120e5e1c9321e37 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CLOUD SOFTWARE LINE CO., LTD." and
            pe.signatures[i].serial == "6f:87:77:aa:86:61:42:ad:71:20:e5:e1:c9:32:1e:37" and
            1629676800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4a7f07c5d4ad2e23f9e8e03f0e229dd4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Danalis LLC" and
            pe.signatures[i].serial == "4a:7f:07:c5:d4:ad:2e:23:f9:e8:e0:3f:0e:22:9d:d4" and
            1608681600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f5f9c8f8c33e4ce84dd48fcb03ccb075 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Abdulkadir \\xC5\\x9Eahin" and (
                pe.signatures[i].serial == "00:f5:f9:c8:f8:c3:3e:4c:e8:4d:d4:8f:cb:03:cc:b0:75" or
                pe.signatures[i].serial == "f5:f9:c8:f8:c3:3e:4c:e8:4d:d4:8f:cb:03:cc:b0:75"
            ) and
            1545004800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_57fc55239f21f139978609e323097132 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aidem Media Limited" and
            pe.signatures[i].serial == "57:fc:55:23:9f:21:f1:39:97:86:09:e3:23:09:71:32" and
            1501632000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_eeefec4308abe63323600e1608f5e6f2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "YUPITER-STROI, OOO" and (
                pe.signatures[i].serial == "00:ee:ef:ec:43:08:ab:e6:33:23:60:0e:16:08:f5:e6:f2" or
                pe.signatures[i].serial == "ee:ef:ec:43:08:ab:e6:33:23:60:0e:16:08:f5:e6:f2"
            ) and
            1491177600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0ecd460ce14bd8ef2926da2cd9a44176 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Rabah Azrarak" and
            pe.signatures[i].serial == "0e:cd:46:0c:e1:4b:d8:ef:29:26:da:2c:d9:a4:41:76" and
            1463035153 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5e75e997f3d70bb8c182d56b25b7d836 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Primetech Ltd." and
            pe.signatures[i].serial == "5e:75:e9:97:f3:d7:0b:b8:c1:82:d5:6b:25:b7:d8:36" and
            1324252800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d5690d94f15315e143db10af35497dc5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PET SERVICES d.o.o." and (
                pe.signatures[i].serial == "00:d5:69:0d:94:f1:53:15:e1:43:db:10:af:35:49:7d:c5" or
                pe.signatures[i].serial == "d5:69:0d:94:f1:53:15:e1:43:db:10:af:35:49:7d:c5"
            ) and
            1576195200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_8223c74185add0927246f5e33ebac467 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TOV Virikton" and (
                pe.signatures[i].serial == "00:82:23:c7:41:85:ad:d0:92:72:46:f5:e3:3e:ba:c4:67" or
                pe.signatures[i].serial == "82:23:c7:41:85:ad:d0:92:72:46:f5:e3:3e:ba:c4:67"
            ) and
            1463616000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_dd9e9e1d7c573714e3f567c5380ae6d0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CREA&COM d.o.o." and (
                pe.signatures[i].serial == "00:dd:9e:9e:1d:7c:57:37:14:e3:f5:67:c5:38:0a:e6:d0" or
                pe.signatures[i].serial == "dd:9e:9e:1d:7c:57:37:14:e3:f5:67:c5:38:0a:e6:d0"
            ) and
            1575849600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3d5e71 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "OF.PL sp. z o.o." and
            pe.signatures[i].serial == "3d:5e:71" and
            1066997730 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c33187fe848a65e8484ea492cb2cbb18 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SELCUK GUNDOGDU" and (
                pe.signatures[i].serial == "00:c3:31:87:fe:84:8a:65:e8:48:4e:a4:92:cb:2c:bb:18" or
                pe.signatures[i].serial == "c3:31:87:fe:84:8a:65:e8:48:4e:a4:92:cb:2c:bb:18"
            ) and
            1426204800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6fc143ba34cabf1de7a4c7f8f4cdad6d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "World Telecom International Inc." and
            pe.signatures[i].serial == "6f:c1:43:ba:34:ca:bf:1d:e7:a4:c7:f8:f4:cd:ad:6d" and
            1147046400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6ac6268b2e431a2c1369346d175d0e30 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Install Sync" and
            pe.signatures[i].serial == "6a:c6:26:8b:2e:43:1a:2c:13:69:34:6d:17:5d:0e:30" and
            1436140800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fc4d9178b8df2c19e269ac6f43dd708 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PK Partnership, OOO" and
            pe.signatures[i].serial == "0f:c4:d9:17:8b:8d:f2:c1:9e:26:9a:c6:f4:3d:d7:08" and
            1466553600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e01407871e2146c9baab1ae7ab8ab172 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TOV Intalev Ukraina" and (
                pe.signatures[i].serial == "00:e0:14:07:87:1e:21:46:c9:ba:ab:1a:e7:ab:8a:b1:72" or
                pe.signatures[i].serial == "e0:14:07:87:1e:21:46:c9:ba:ab:1a:e7:ab:8a:b1:72"
            ) and
            1464220800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_effc6d19d6fc85872e4e5b3ccee6d301 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "C\\xC3\\x93IR IP LIMITED" and (
                pe.signatures[i].serial == "00:ef:fc:6d:19:d6:fc:85:87:2e:4e:5b:3c:ce:e6:d3:01" or
                pe.signatures[i].serial == "ef:fc:6d:19:d6:fc:85:87:2e:4e:5b:3c:ce:e6:d3:01"
            ) and
            1572307200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2f4a25d52b16eb4c9dfe71ebbd8121bb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Blist LLC" and
            pe.signatures[i].serial == "2f:4a:25:d5:2b:16:eb:4c:9d:fe:71:eb:bd:81:21:bb" and
            1629763200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6889aab6202bcc5f11caedf4d04f435b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "C4DL Media" and
            pe.signatures[i].serial == "68:89:aa:b6:20:2b:cc:5f:11:ca:ed:f4:d0:4f:43:5b" and
            1231891200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3be63083fbb1787b445da97583721419 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\"SMART GREY\" LLC" and
            pe.signatures[i].serial == "3b:e6:30:83:fb:b1:78:7b:44:5d:a9:75:83:72:14:19" and
            1493942400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6e2d3449272b6b96b8b9f728e87580d5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RADIANT, OOO" and
            pe.signatures[i].serial == "6e:2d:34:49:27:2b:6b:96:b8:b9:f7:28:e8:75:80:d5" and
            1421107200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_268c0d7028a154ac3b6349c5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "26:8c:0d:70:28:a1:54:ac:3b:63:49:c5" and
            1474266712 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2daa8d629cc0410a9482e62a0f8bf8fc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DON'T MISS A WORD LIMITED" and
            pe.signatures[i].serial == "2d:aa:8d:62:9c:c0:41:0a:94:82:e6:2a:0f:8b:f8:fc" and
            1543449600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_9a727e200ea76570 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Alexsandro Da Rosa - ME" and (
                pe.signatures[i].serial == "00:9a:72:7e:20:0e:a7:65:70" or
                pe.signatures[i].serial == "9a:72:7e:20:0e:a7:65:70"
            ) and
            1539056530 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0954a3c876df9262cde5817f9870f0c6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dialer Access" and
            pe.signatures[i].serial == "09:54:a3:c8:76:df:92:62:cd:e5:81:7f:98:70:f0:c6" and
            1160438400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3c30930e53bb026f9a5d7440155f7118 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CPM Media, Ltd." and
            pe.signatures[i].serial == "3c:30:93:0e:53:bb:02:6f:9a:5d:74:40:15:5f:71:18" and
            1064534400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_432eefc0d4dc0326eb277a518cc4310a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and
            pe.signatures[i].serial == "43:2e:ef:c0:d4:dc:03:26:eb:27:7a:51:8c:c4:31:0a" and
            1466121600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_470d6ce21a6940320261f09e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "47:0d:6c:e2:1a:69:40:32:02:61:f0:9e" and
            1474523038 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7e6bc7e5a49e2c28e6f5d042 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shang Hai Jian Ji Wang Luo Ke Ji You Xian Gong Si" and
            pe.signatures[i].serial == "7e:6b:c7:e5:a4:9e:2c:28:e6:f5:d0:42" and
            1560995284 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4c5020899147c850196c4ebf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "4c:50:20:89:91:47:c8:50:19:6c:4e:bf" and
            1476693792 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4efcf7adc21f070e590d49ddb8081397 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ding Ruan" and
            pe.signatures[i].serial == "4e:fc:f7:ad:c2:1f:07:0e:59:0d:49:dd:b8:08:13:97" and
            1476921600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cbd37c0a651913ee25a6860d7d5ccdf2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Amma" and (
                pe.signatures[i].serial == "00:cb:d3:7c:0a:65:19:13:ee:25:a6:86:0d:7d:5c:cd:f2" or
                pe.signatures[i].serial == "cb:d3:7c:0a:65:19:13:ee:25:a6:86:0d:7d:5c:cd:f2"
            ) and
            1431734400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5fe0ad6b03c57ab67a352159004ca3db {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SpectorSoft Corp." and
            pe.signatures[i].serial == "5f:e0:ad:6b:03:c5:7a:b6:7a:35:21:59:00:4c:a3:db" and
            1402272000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_642ad8e5ef8b3ac767f0d5c1a999bdaa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Itgms Ltd" and
            pe.signatures[i].serial == "64:2a:d8:e5:ef:8b:3a:c7:67:f0:d5:c1:a9:99:bd:aa" and
            1447804800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5333d3079d8afda715703775e1389991 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Trambambon LLC" and
            pe.signatures[i].serial == "53:33:d3:07:9d:8a:fd:a7:15:70:37:75:e1:38:99:91" and
            1239148800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_139a7ee1f1a7735c151089755df5d373 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yongli Li" and
            pe.signatures[i].serial == "13:9a:7e:e1:f1:a7:73:5c:15:10:89:75:5d:f5:d3:73" and
            1476057600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_74dbe83082e1b3dfa29f9c24 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EVANGEL TECHNOLOGY(HK) LIMITED" and
            pe.signatures[i].serial == "74:db:e8:30:82:e1:b3:df:a2:9f:9c:24" and
            1468817578 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a466553a6391aafd181b400266c7b18 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PhaseQ Limited" and
            pe.signatures[i].serial == "0a:46:65:53:a6:39:1a:af:d1:81:b4:00:26:6c:7b:18" and
            1555545600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0d3dec8794fa7228d1ee40eeb8187149 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Financial Security Institute, Inc." and
            pe.signatures[i].serial == "0d:3d:ec:87:94:fa:72:28:d1:ee:40:ee:b8:18:71:49" and
            1582675200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_24af70b5d17a63ad053e5821 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "24:af:70:b5:d1:7a:63:ad:05:3e:58:21" and
            1474179615 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_402e9fcba61e5eaf9c0c7b3bfd6259d9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yongli Li" and
            pe.signatures[i].serial == "40:2e:9f:cb:a6:1e:5e:af:9c:0c:7b:3b:fd:62:59:d9" and
            1477440000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2c84f9136059e96134f8766670eacd52 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, DIEGO MANUEL RODRIGUEZ" and
            pe.signatures[i].serial == "2c:84:f9:13:60:59:e9:61:34:f8:76:66:70:ea:cd:52" and
            1442215311 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6716a9c195987d5cfe53a094779461e7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Inter Technologies Ltd." and
            pe.signatures[i].serial == "67:16:a9:c1:95:98:7d:5c:fe:53:a0:94:77:94:61:e7" and
            1169424000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_876c00bd665df98b35554f67a5c1c32a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lossera-M, OOO" and (
                pe.signatures[i].serial == "00:87:6c:00:bd:66:5d:f9:8b:35:55:4f:67:a5:c1:c3:2a" or
                pe.signatures[i].serial == "87:6c:00:bd:66:5d:f9:8b:35:55:4f:67:a5:c1:c3:2a"
            ) and
            1493078400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4b093cb60d4b992266f550934a4ac7d0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LCB SISTEMAS LTDA ME" and
            pe.signatures[i].serial == "4b:09:3c:b6:0d:4b:99:22:66:f5:50:93:4a:4a:c7:d0" and
            1478649600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2050b54146b011ed30f60f61 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "20:50:b5:41:46:b0:11:ed:30:f6:0f:61" and
            1476773926 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_73e2f34c9c2435f29bbe0a3c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "73:e2:f3:4c:9c:24:35:f2:9b:be:0a:3c" and
            1480312984 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_68c457d7495d2a8d0d7b9042836135c2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "68:c4:57:d7:49:5d:2a:8d:0d:7b:90:42:83:61:35:c2" and
            1476921600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6b72ca367d40fbef16e73e6eba6a9a59 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "6b:72:ca:36:7d:40:fb:ef:16:e7:3e:6e:ba:6a:9a:59" and
            1476748800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_736b7663d322533413f36e3e7e55f920 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Net Technology" and
            pe.signatures[i].serial == "73:6b:76:63:d3:22:53:34:13:f3:6e:3e:7e:55:f9:20" and
            1159488000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_54a170102461fdc967acfafe4bbbc7f0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "54:a1:70:10:24:61:fd:c9:67:ac:fa:fe:4b:bb:c7:f0" and
            1476748800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0c501b8b113209c96c8119cf7a6b8b79 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "0c:50:1b:8b:11:32:09:c9:6c:81:19:cf:7a:6b:8b:79" and
            1474329600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0300ee4a4c52443147821a8186d04309 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Buster Ind Com Imp e Exp de Acessorios P Autos Ltda" and
            pe.signatures[i].serial == "03:00:ee:4a:4c:52:44:31:47:82:1a:81:86:d0:43:09" and
            1494892800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_202cf8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DATALINE LTD." and
            pe.signatures[i].serial == "20:2c:f8" and
            1087841761 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6651cc8b4850d4dec61961503ea7956b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "NUSAAPPINSTALL(APPS INSTALLER S.L.)" and
            pe.signatures[i].serial == "66:51:cc:8b:48:50:d4:de:c6:19:61:50:3e:a7:95:6b" and
            1436175828 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_25bef28467e4750331d2f403458113b8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and
            pe.signatures[i].serial == "25:be:f2:84:67:e4:75:03:31:d2:f4:03:45:81:13:b8" and
            1474156800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0296cf3314f434c5b74d0c3e36616dd1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "02:96:cf:33:14:f4:34:c5:b7:4d:0c:3e:36:61:6d:d1" and
            1474934400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_045d57d63e13775c8f812e1864797f5a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yuanyuan Mei" and
            pe.signatures[i].serial == "04:5d:57:d6:3e:13:77:5c:8f:81:2e:18:64:79:7f:5a" and
            1485043200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6d633df9bb6015fc3ecea99dff309ee7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "6d:63:3d:f9:bb:60:15:fc:3e:ce:a9:9d:ff:30:9e:e7" and
            1474156800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_22e2a66e63b8cb4ec6989bf7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sivi Technology Limited" and
            pe.signatures[i].serial == "22:e2:a6:6e:63:b8:cb:4e:c6:98:9b:f7" and
            1466995365 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_654b406de388ec2aec253ff2ba4c4bbd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yijiajian (Amoy) Jiankan Tech Co.,LTD." and
            pe.signatures[i].serial == "65:4b:40:6d:e3:88:ec:2a:ec:25:3f:f2:ba:4c:4b:bd" and
            1398902400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_78d1817ebcf338b4e9c810f9740a726b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CONSTRUTORA NOVO PARQUE LTDA - ME" and
            pe.signatures[i].serial == "78:d1:81:7e:bc:f3:38:b4:e9:c8:10:f9:74:0a:72:6b" and
            1431734400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_45fbcdb1fbd3d702fb77257b45d8c58e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ding Ruan" and
            pe.signatures[i].serial == "45:fb:cd:b1:fb:d3:d7:02:fb:77:25:7b:45:d8:c5:8e" and
            1476662400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4b5d8ed5ca011679f141f124 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "4b:5d:8e:d5:ca:01:16:79:f1:41:f1:24" and
            1480644725 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_33671f1bcbd0f5e231fc386f4895000e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALAIS, OOO" and
            pe.signatures[i].serial == "33:67:1f:1b:cb:d0:f5:e2:31:fc:38:6f:48:95:00:0e" and
            1491868800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_32bc299f0694c19ec21e71265b1d7e17 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "32:bc:29:9f:06:94:c1:9e:c2:1e:71:26:5b:1d:7e:17" and
            1474416000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7b75c6b0a09afdb9787f6dff75ae7844 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "7b:75:c6:b0:a0:9a:fd:b9:78:7f:6d:ff:75:ae:78:44" and
            1476662400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_167fd1295b3bb102dbb37292c838e7cd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "16:7f:d1:29:5b:3b:b1:02:db:b3:72:92:c8:38:e7:cd" and
            1476921600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_253ad25e39abe8f8fda9fcf6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DVERI FADO, TOV" and
            pe.signatures[i].serial == "25:3a:d2:5e:39:ab:e8:f8:fd:a9:fc:f6" and
            1538662130 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a9c1523cb2c73a82771d318124963e87 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ULTERA" and (
                pe.signatures[i].serial == "00:a9:c1:52:3c:b2:c7:3a:82:77:1d:31:81:24:96:3e:87" or
                pe.signatures[i].serial == "a9:c1:52:3c:b2:c7:3a:82:77:1d:31:81:24:96:3e:87"
            ) and
            1499731200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_68e1b2c210b19bb1f2a24176709b165b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "68:e1:b2:c2:10:b1:9b:b1:f2:a2:41:76:70:9b:16:5b" and
            1474502400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5c88313bd98bde99c9b9ac1408a63249 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "5c:88:31:3b:d9:8b:de:99:c9:b9:ac:14:08:a6:32:49" and
            1474243200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7a632a6ecfc6c49ec1f42f76 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "7a:63:2a:6e:cf:c6:c4:9e:c1:f4:2f:76" and
            1474959780 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_f57df6a6eee3854d513d0ba8585049b7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "smnetworks" and (
                pe.signatures[i].serial == "00:f5:7d:f6:a6:ee:e3:85:4d:51:3d:0b:a8:58:50:49:b7" or
                pe.signatures[i].serial == "f5:7d:f6:a6:ee:e3:85:4d:51:3d:0b:a8:58:50:49:b7"
            ) and
            1277769600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0ac5ac5d323122e6d8e92d6e191b1432 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Certified Software" and
            pe.signatures[i].serial == "0a:c5:ac:5d:32:31:22:e6:d8:e9:2d:6e:19:1b:14:32" and
            1140134400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2433d9df7efbccb870ee5904d62a0101 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Conpavi AG" and
            pe.signatures[i].serial == "24:33:d9:df:7e:fb:cc:b8:70:ee:59:04:d6:2a:01:01" and
            1322438400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_462baada57570f70df76d10b9e7bf2b7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DVERI FADO, TOV" and
            pe.signatures[i].serial == "46:2b:aa:da:57:57:0f:70:df:76:d1:0b:9e:7b:f2:b7" and
            1551744000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_83320d93dd8cf16d11f99b1078b0a7cb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TRANS LTD" and (
                pe.signatures[i].serial == "00:83:32:0d:93:dd:8c:f1:6d:11:f9:9b:10:78:b0:a7:cb" or
                pe.signatures[i].serial == "83:32:0d:93:dd:8c:f1:6d:11:f9:9b:10:78:b0:a7:cb"
            ) and
            1524614400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_10bae1d20cb4cc36a0ffac86 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "10:ba:e1:d2:0c:b4:cc:36:a0:ff:ac:86" and
            1476773830 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_230716bfe915dd6203b2e2a35674c2ee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jiang Liu" and
            pe.signatures[i].serial == "23:07:16:bf:e9:15:dd:62:03:b2:e2:a3:56:74:c2:ee" and
            1472169600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_36a77d37e68e02fd3d043c7197e044ca {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Direct Systems Ltd" and
            pe.signatures[i].serial == "36:a7:7d:37:e6:8e:02:fd:3d:04:3c:71:97:e0:44:ca" and
            1515542400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_73bff2fb714f986c1707165f0b0f2e0e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Tecnopolis Consulting Ltd" and
            pe.signatures[i].serial == "73:bf:f2:fb:71:4f:98:6c:17:07:16:5f:0b:0f:2e:0e" and
            1090886400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_33b24170694ca0cf4d2bdf4aadf475a3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "33:b2:41:70:69:4c:a0:cf:4d:2b:df:4a:ad:f4:75:a3" and
            1474934400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3a9bdec10e00e780316baaebfe7a772c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "PLAN ALPHA LIMITED" and
            pe.signatures[i].serial == "3a:9b:de:c1:0e:00:e7:80:31:6b:aa:eb:fe:7a:77:2c" and
            1556582400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7cad9c37f7affa8f4d8229f97607e265 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Funbit" and
            pe.signatures[i].serial == "7c:ad:9c:37:f7:af:fa:8f:4d:82:29:f9:76:07:e2:65" and
            1122508800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_098a57 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ELECTRONIC GROUP" and
            pe.signatures[i].serial == "09:8a:57" and
            1032855179 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5389cc6286da3bfa1dc4df498bf68361 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Joerm.com" and
            pe.signatures[i].serial == "53:89:cc:62:86:da:3b:fa:1d:c4:df:49:8b:f6:83:61" and
            1495497600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ed9caeb7911b31bd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE4\\xB8\\x8A\\xE6\\xB5\\xB7\\xE5\\xA4\\xA9\\xE6\\xB8\\xB8\\xE8\\xBD\\xAF\\xE4\\xBB\\xB6\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and (
                pe.signatures[i].serial == "00:ed:9c:ae:b7:91:1b:31:bd" or
                pe.signatures[i].serial == "ed:9c:ae:b7:91:1b:31:bd"
            ) and
            1506001740 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0fd2b19a941b7009cc728a37cb1b10b9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BEAR AND CILLA LTD" and
            pe.signatures[i].serial == "0f:d2:b1:9a:94:1b:70:09:cc:72:8a:37:cb:1b:10:b9" and
            1560470400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2d88c0af1fe2609961c171213c03bd23 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Zhuzhou Lizhong Precision Manufacturing Technology Co., Ltd." and
            pe.signatures[i].serial == "2d:88:c0:af:1f:e2:60:99:61:c1:71:21:3c:03:bd:23" and
            1683676800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6e7cc176062d91225cfdcbdf5b5f0ea5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SG Internet" and
            pe.signatures[i].serial == "6e:7c:c1:76:06:2d:91:22:5c:fd:cb:df:5b:5f:0e:a5" and
            1317945600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_cecedd2efc985c2dbf0019669d270079 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TRANS LTD" and (
                pe.signatures[i].serial == "00:ce:ce:dd:2e:fc:98:5c:2d:bf:00:19:66:9d:27:00:79" or
                pe.signatures[i].serial == "ce:ce:dd:2e:fc:98:5c:2d:bf:00:19:66:9d:27:00:79"
            ) and
            1527811200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_61fe6f00bd79684210534050ff46bc92 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xingning Dexin Network Technology Co., Ltd." and
            pe.signatures[i].serial == "61:fe:6f:00:bd:79:68:42:10:53:40:50:ff:46:bc:92" and
            1512000000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0323cc4e38735b0e6efba76ea25c73b7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xingning Dexin Network Technology Co., Ltd." and
            pe.signatures[i].serial == "03:23:cc:4e:38:73:5b:0e:6e:fb:a7:6e:a2:5c:73:b7" and
            1512000000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1f9aca069ac1b6bfb0e14861ec857bf6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "1f:9a:ca:06:9a:c1:b6:bf:b0:e1:48:61:ec:85:7b:f6" and
            1477440000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3e9d26dcf703ca3b140d7e7ad48312e2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dong Qian" and
            pe.signatures[i].serial == "3e:9d:26:dc:f7:03:ca:3b:14:0d:7e:7a:d4:83:12:e2" and
            1440580240 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4e2523e76ea455941e75fb8240474a75 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "4e:25:23:e7:6e:a4:55:94:1e:75:fb:82:40:47:4a:75" and
            1476403200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6102468293ba7308d17efb43ad6bfb58 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and
            pe.signatures[i].serial == "61:02:46:82:93:ba:73:08:d1:7e:fb:43:ad:6b:fb:58" and
            1470960000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6ded1a7ff6da152a98a57a2f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "6d:ed:1a:7f:f6:da:15:2a:98:a5:7a:2f" and
            1479094343 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3ce65ea057b975d2c17eaf2c2297b1eb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TRANS LTD" and
            pe.signatures[i].serial == "3c:e6:5e:a0:57:b9:75:d2:c1:7e:af:2c:22:97:b1:eb" and
            1528243200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5d085a9a288549d09edc4941 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "5d:08:5a:9a:28:85:49:d0:9e:dc:49:41" and
            1478757821 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7d20dec3797a1ac30649ebb184265b79 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jiang Liu" and
            pe.signatures[i].serial == "7d:20:de:c3:79:7a:1a:c3:06:49:eb:b1:84:26:5b:79" and
            1474156800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_187d92861076e469b5b7a19e2a9fd4ba {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "18:7d:92:86:10:76:e4:69:b5:b7:a1:9e:2a:9f:d4:ba" and
            1476748800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_199a9476feca3c004ff889d34545de07 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Funcall" and
            pe.signatures[i].serial == "19:9a:94:76:fe:ca:3c:00:4f:f8:89:d3:45:45:de:07" and
            1138060800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1efe65 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Software Plugin Ltd." and
            pe.signatures[i].serial == "1e:fe:65" and
            1063224491 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0af7e2b6a3deb99291dcaf66 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "0a:f7:e2:b6:a3:de:b9:92:91:dc:af:66" and
            1474523112 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_45e27c4dfa5e6175566a13b1b6ddf3f5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Selig Michael Irfan" and
            pe.signatures[i].serial == "45:e2:7c:4d:fa:5e:61:75:56:6a:13:b1:b6:dd:f3:f5" and
            1465474542 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_37d36a4e61c0ac68ceb8bfcef2dbf283 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ANAVERIS LIMITED" and
            pe.signatures[i].serial == "37:d3:6a:4e:61:c0:ac:68:ce:b8:bf:ce:f2:db:f2:83" and
            1532476800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4321de10738278b93683ca542407f103 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "We Build Toolbars LLC" and
            pe.signatures[i].serial == "43:21:de:10:73:82:78:b9:36:83:ca:54:24:07:f1:03" and
            1367884800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2a6b2df210be14f4e18e10c7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "2a:6b:2d:f2:10:be:14:f4:e1:8e:10:c7" and
            1472095404 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_412ab2a50e8028ddcbc499ddf45f2045 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Ding Ruan" and
            pe.signatures[i].serial == "41:2a:b2:a5:0e:80:28:dd:cb:c4:99:dd:f4:5f:20:45" and
            1479340800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0747f6a8c3542f954b113fd98c7607cf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "07:47:f6:a8:c3:54:2f:95:4b:11:3f:d9:8c:76:07:cf" and
            1474329600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2572b484fa0a61be7288d785d7bda7d3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "SILVA, OOO" and
            pe.signatures[i].serial == "25:72:b4:84:fa:0a:61:be:72:88:d7:85:d7:bd:a7:d3" and
            1495152000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6726bd04204746c46857887f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "67:26:bd:04:20:47:46:c4:68:57:88:7f" and
            1474352405 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4463d8b31e0f87c14233d4d0d2c487a0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "44:63:d8:b3:1e:0f:87:c1:42:33:d4:d0:d2:c4:87:a0" and
            1477612800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_387982605e542d6d52f231ca6f5657cc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jiang Liu" and
            pe.signatures[i].serial == "38:79:82:60:5e:54:2d:6d:52:f2:31:ca:6f:56:57:cc" and
            1475884800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e0134c41e7eda6863c4eee5b003976dd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "5000 LIMITED" and (
                pe.signatures[i].serial == "00:e0:13:4c:41:e7:ed:a6:86:3c:4e:ee:5b:00:39:76:dd" or
                pe.signatures[i].serial == "e0:13:4c:41:e7:ed:a6:86:3c:4e:ee:5b:00:39:76:dd"
            ) and
            1528070400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5b47a4739dd8ffe81d9b5307 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "5b:47:a4:73:9d:d8:ff:e8:1d:9b:53:07" and
            1476953007 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4f5a9bf75da76b949645475473793a7d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EXEC CONTROL LIMITED" and
            pe.signatures[i].serial == "4f:5a:9b:f7:5d:a7:6b:94:96:45:47:54:73:79:3a:7d" and
            1553817600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_081df56c9a48d02571f08907 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "08:1d:f5:6c:9a:48:d0:25:71:f0:89:07" and
            1474870728 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_77d5c1a3e623575999c74409dc19753c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "77:d5:c1:a3:e6:23:57:59:99:c7:44:09:dc:19:75:3c" and
            1475884800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e9756b3f38b1172ea89fdbdfdba5f979 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Kreamer Ltd" and (
                pe.signatures[i].serial == "00:e9:75:6b:3f:38:b1:17:2e:a8:9f:db:df:db:a5:f9:79" or
                pe.signatures[i].serial == "e9:75:6b:3f:38:b1:17:2e:a8:9f:db:df:db:a5:f9:79"
            ) and
            1492732800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_09fb28 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "New Dial spa" and
            pe.signatures[i].serial == "09:fb:28" and
            1046968418 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_197dc32d915458953562d2fe78bf2468 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Y.L. Knafo, Ltd." and
            pe.signatures[i].serial == "19:7d:c3:2d:91:54:58:95:35:62:d2:fe:78:bf:24:68" and
            1575331200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7c0be3d14787351e3156f5f37f2b3663 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Apex Tech, SIA" and
            pe.signatures[i].serial == "7c:0b:e3:d1:47:87:35:1e:31:56:f5:f3:7f:2b:36:63" and
            1523318400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_05054fdea356f3dd7db479fa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "05:05:4f:de:a3:56:f3:dd:7d:b4:79:fa" and
            1474436511 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08aaa069e92517f21ce67ca713f6ea63 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "pioneersoft" and
            pe.signatures[i].serial == "08:aa:a0:69:e9:25:17:f2:1c:e6:7c:a7:13:f6:ea:63" and
            1368403200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1b7b54e0dd4d7e45a0b46834de52658d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "1b:7b:54:e0:dd:4d:7e:45:a0:b4:68:34:de:52:65:8d" and
            1476662400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b63e4299d0b0e2dcdaeb976167a23235 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Baltservis LLC" and (
                pe.signatures[i].serial == "00:b6:3e:42:99:d0:b0:e2:dc:da:eb:97:61:67:a2:32:35" or
                pe.signatures[i].serial == "b6:3e:42:99:d0:b0:e2:dc:da:eb:97:61:67:a2:32:35"
            ) and
            1604102400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1dabae616705f5a51152eac48423f354 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "1d:ab:ae:61:67:05:f5:a5:11:52:ea:c4:84:23:f3:54" and
            1470960000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_50d08f3c9bf86fba52cf592b4fe6eacf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CLEVERCYBER LTD" and
            pe.signatures[i].serial == "50:d0:8f:3c:9b:f8:6f:ba:52:cf:59:2b:4f:e6:ea:cf" and
            1518134400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7c7fc3616f3157a28f702cc1df275dcd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CFES Projects Ltd" and
            pe.signatures[i].serial == "7c:7f:c3:61:6f:31:57:a2:8f:70:2c:c1:df:27:5d:cd" and
            1522972800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_73ed1b2f4bf8dd37a8ad9bb775774592 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "5000 LIMITED" and
            pe.signatures[i].serial == "73:ed:1b:2f:4b:f8:dd:37:a8:ad:9b:b7:75:77:45:92" and
            1528243200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_211b5dfe65bc6f34bc9d3a54 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RAFO TECHNOLOGY INC" and
            pe.signatures[i].serial == "21:1b:5d:fe:65:bc:6f:34:bc:9d:3a:54" and
            1526717931 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5400d1c1406528b1ef625976 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "54:00:d1:c1:40:65:28:b1:ef:62:59:76" and
            1474266628 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_013472d7d665557bfa0dc21b350a361b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yongli Zhang" and
            pe.signatures[i].serial == "01:34:72:d7:d6:65:55:7b:fa:0d:c2:1b:35:0a:36:1b" and
            1470960000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_66c758a22bfbbce327616815616ddd07 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TIM Konstrakshn, TOV" and
            pe.signatures[i].serial == "66:c7:58:a2:2b:fb:bc:e3:27:61:68:15:61:6d:dd:07" and
            1469404800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_e61b0366d940896430bcfe3e93baac5b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TRANS LTD" and (
                pe.signatures[i].serial == "00:e6:1b:03:66:d9:40:89:64:30:bc:fe:3e:93:ba:ac:5b" or
                pe.signatures[i].serial == "e6:1b:03:66:d9:40:89:64:30:bc:fe:3e:93:ba:ac:5b"
            ) and
            1528156800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6294b8acc35dea7d32a95ac5d4536f8f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE9\\x87\\x8D\\xE5\\xBA\\x86\\xE6\\x8E\\xA2\\xE9\\x95\\xBF\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "62:94:b8:ac:c3:5d:ea:7d:32:a9:5a:c5:d4:53:6f:8f" and
            1517443200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_485e4626c32493c16283cfd9e30d17ad {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "48:5e:46:26:c3:24:93:c1:62:83:cf:d9:e3:0d:17:ad" and
            1473292800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d0312f9177cd46b943df3ef22db4608b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "United Systems Technology, Inc." and (
                pe.signatures[i].serial == "00:d0:31:2f:91:77:cd:46:b9:43:df:3e:f2:2d:b4:60:8b" or
                pe.signatures[i].serial == "d0:31:2f:91:77:cd:46:b9:43:df:3e:f2:2d:b4:60:8b"
            ) and
            1341273600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_202702 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RDCTO Ltd" and
            pe.signatures[i].serial == "20:27:02" and
            1087391361 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_369a02e5d90b2649040e7f87 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "36:9a:02:e5:d9:0b:26:49:04:0e:7f:87" and
            1479094204 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_60497070ff4a83bc87bdea24da5b431d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "60:49:70:70:ff:4a:83:bc:87:bd:ea:24:da:5b:43:1d" and
            1477008000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a333e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Coulomb Limited" and
            pe.signatures[i].serial == "0a:33:3e" and
            1052750648 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1cb6519b2528d006d1da987153dad2b3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "D and D Internet Services" and
            pe.signatures[i].serial == "1c:b6:51:9b:25:28:d0:06:d1:da:98:71:53:da:d2:b3" and
            1012780800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_621e696c3a6371e77a678cbf0ee34ab2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "62:1e:69:6c:3a:63:71:e7:7a:67:8c:bf:0e:e3:4a:b2" and
            1467072000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_21b991 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Web Nexus d.o.o." and
            pe.signatures[i].serial == "21:b9:91" and
            1125477041 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1cc37de5dbed097f98f56dbc {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "1c:c3:7d:e5:db:ed:09:7f:98:f5:6d:bc" and
            1476693977 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_50f66ab0d7ed19b69d48f635e69572fa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Wei Liu" and
            pe.signatures[i].serial == "50:f6:6a:b0:d7:ed:19:b6:9d:48:f6:35:e6:95:72:fa" and
            1467158400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_11212f502836a784752160351defb136cf09 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "EVANGEL TECHNOLOGY(HK) LIMITED" and
            pe.signatures[i].serial == "11:21:2f:50:28:36:a7:84:75:21:60:35:1d:ef:b1:36:cf:09" and
            1463726573 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2c16be9a7ce2a23ab7a4b4eb7da3400c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Prince city music bar" and
            pe.signatures[i].serial == "2c:16:be:9a:7c:e2:a2:3a:b7:a4:b4:eb:7d:a3:40:0c" and
            1371081600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_22accad235fb1ac7422ebe5ea7ac9bc5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IMS INTERACTIVE MEDIA SOLUTIONS" and
            pe.signatures[i].serial == "22:ac:ca:d2:35:fb:1a:c7:42:2e:be:5e:a7:ac:9b:c5" and
            1019001600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4d29757c4fbfc32b97091d96e3723002 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "4d:29:75:7c:4f:bf:c3:2b:97:09:1d:96:e3:72:30:02" and
            1474848000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3a949ef03d9dd2d150b24b274ff6d7b4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "3a:94:9e:f0:3d:9d:d2:d1:50:b2:4b:27:4f:f6:d7:b4" and
            1474156800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_954d0577d5ce8999e0387a5364829f66 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Soblosol Limited" and (
                pe.signatures[i].serial == "00:95:4d:05:77:d5:ce:89:99:e0:38:7a:53:64:82:9f:66" or
                pe.signatures[i].serial == "95:4d:05:77:d5:ce:89:99:e0:38:7a:53:64:82:9f:66"
            ) and
            1543968000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_df5121dc99d1ab6b7e5229f6832123ef {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "INC SALYUT" and (
                pe.signatures[i].serial == "00:df:51:21:dc:99:d1:ab:6b:7e:52:29:f6:83:21:23:ef" or
                pe.signatures[i].serial == "df:51:21:dc:99:d1:ab:6b:7e:52:29:f6:83:21:23:ef"
            ) and
            1613433600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_760cef386b63406751ae83a9eae92342 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Gidrokon LLC" and
            pe.signatures[i].serial == "76:0c:ef:38:6b:63:40:67:51:ae:83:a9:ea:e9:23:42" and
            1601942400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5c2625fa836a64f4882c56cc7a45f0ed {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "5c:26:25:fa:83:6a:64:f4:88:2c:56:cc:7a:45:f0:ed" and
            1474416000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7df6fa580f84493c414ee0e431086737 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "7d:f6:fa:58:0f:84:49:3c:41:4e:e0:e4:31:08:67:37" and
            1477440000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_309d2e115f1fe2993ee2e063 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "30:9d:2e:11:5f:1f:e2:99:3e:e2:e0:63" and
            1467102525 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_90e33c1068f54913315b6ce9311141b9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GERMES, OOO" and (
                pe.signatures[i].serial == "00:90:e3:3c:10:68:f5:49:13:31:5b:6c:e9:31:11:41:b9" or
                pe.signatures[i].serial == "90:e3:3c:10:68:f5:49:13:31:5b:6c:e9:31:11:41:b9"
            ) and
            1487635200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3f15c3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Certified Software" and
            pe.signatures[i].serial == "3f:15:c3" and
            1110577130 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_285eccbd1d0000e640b84307ef88cd9f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DRAGON BUSINESS EQUIPMENT LIMITED" and
            pe.signatures[i].serial == "28:5e:cc:bd:1d:00:00:e6:40:b8:43:07:ef:88:cd:9f" and
            1611619200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_55ab71a3f9dde3ef20c788dd1d5ff6c3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Zhengzhoushi Tiekelian Information Technology Co.,Ltd" and
            pe.signatures[i].serial == "55:ab:71:a3:f9:dd:e3:ef:20:c7:88:dd:1d:5f:f6:c3" and
            1323907200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4beca26210737a5442ff8b47 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "4b:ec:a2:62:10:73:7a:54:42:ff:8b:47" and
            1476437049 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0f203839a9c63b8798a7cb31 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "0f:20:38:39:a9:c6:3b:87:98:a7:cb:31" and
            1480923809 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_dc992ea8e6bb4926931df656d5eef8a0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MEGAPOLISELIT, OOO" and (
                pe.signatures[i].serial == "00:dc:99:2e:a8:e6:bb:49:26:93:1d:f6:56:d5:ee:f8:a0" or
                pe.signatures[i].serial == "dc:99:2e:a8:e6:bb:49:26:93:1d:f6:56:d5:ee:f8:a0"
            ) and
            1497916800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_41bd49bb456644d8183b3dae72ec8f22 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "41:bd:49:bb:45:66:44:d8:18:3b:3d:ae:72:ec:8f:22" and
            1468454400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a8d40da6708679c08aebddea6d3f6b8a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VELES LTD." and (
                pe.signatures[i].serial == "00:a8:d4:0d:a6:70:86:79:c0:8a:eb:dd:ea:6d:3f:6b:8a" or
                pe.signatures[i].serial == "a8:d4:0d:a6:70:86:79:c0:8a:eb:dd:ea:6d:3f:6b:8a"
            ) and
            1547424000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_307642e1f3a92c6cc2e7fb6e18f2ddcb {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "IBM" and
            pe.signatures[i].serial == "30:76:42:e1:f3:a9:2c:6c:c2:e7:fb:6e:18:f2:dd:cb" and
            1500422400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_52379131a1c69263c795a7d398db0997 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and
            pe.signatures[i].serial == "52:37:91:31:a1:c6:92:63:c7:95:a7:d3:98:db:09:97" and
            1476748800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_44312cb9a927b4111360762b4d4bdd6d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BEAR ADAMS CONSULTING LIMITED" and
            pe.signatures[i].serial == "44:31:2c:b9:a9:27:b4:11:13:60:76:2b:4d:4b:dd:6d" and
            1554768000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_123a5074069162f4ed68fc7d48f464c2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "12:3a:50:74:06:91:62:f4:ed:68:fc:7d:48:f4:64:c2" and
            1472428800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_64eb04b8def382b5efa75f63e0e85ad0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "TOV \"MARIYA\"" and
            pe.signatures[i].serial == "64:eb:04:b8:de:f3:82:b5:ef:a7:5f:63:e0:e8:5a:d0" and
            1535587200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_76d8d908eed2f9857dc5676a680ceac9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "76:d8:d9:08:ee:d2:f9:85:7d:c5:67:6a:68:0c:ea:c9" and
            1467158400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_083e3f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Telefonicasa" and
            pe.signatures[i].serial == "08:3e:3f" and
            999002664 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_79227311acdd575759198dbd3544cca7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "79:22:73:11:ac:dd:57:57:59:19:8d:bd:35:44:cc:a7" and
            1478131200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_13ae38c9ae21a8576c0d024d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "13:ae:38:c9:ae:21:a8:57:6c:0d:02:4d" and
            1475062802 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_557b0abf44045827f1f36efbc96271ec {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "55:7b:0a:bf:44:04:58:27:f1:f3:6e:fb:c9:62:71:ec" and
            1480291200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7903870184e18a80899740845a15e2b2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Qool Aid, LLC" and
            pe.signatures[i].serial == "79:03:87:01:84:e1:8a:80:89:97:40:84:5a:15:e2:b2" and
            1079654400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5fba9b373f812c16aef531d4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "5f:ba:9b:37:3f:81:2c:16:ae:f5:31:d4" and
            1473329076 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_616a5205238590b01d7b761e444e4ad9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Lerges" and
            pe.signatures[i].serial == "61:6a:52:05:23:85:90:b0:1d:7b:76:1e:44:4e:4a:d9" and
            1421452800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_29be2278113dd062eadca32de6b242d0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BLADES" and
            pe.signatures[i].serial == "29:be:22:78:11:3d:d0:62:ea:dc:a3:2d:e6:b2:42:d0" and
            1536883200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_05f70a557afd4a443f44d0baf0bc8c60 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "05:f7:0a:55:7a:fd:4a:44:3f:44:d0:ba:f0:bc:8c:60" and
            1477440000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4e0665d61997072294a70c662f72eae3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "4e:06:65:d6:19:97:07:22:94:a7:0c:66:2f:72:ea:e3" and
            1474502400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_74702dff5d4056b847d009a2265fb1b3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shulan Hou" and
            pe.signatures[i].serial == "74:70:2d:ff:5d:40:56:b8:47:d0:09:a2:26:5f:b1:b3" and
            1469664000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_353b1cf7866ee0b0acdd532d0bb1a220 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Network Freak Limited" and
            pe.signatures[i].serial == "35:3b:1c:f7:86:6e:e0:b0:ac:dd:53:2d:0b:b1:a2:20" and
            1558915200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_093ff2870fa33eaf47259457ee58c2e0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AEEPZ Limited" and
            pe.signatures[i].serial == "09:3f:f2:87:0f:a3:3e:af:47:25:94:57:ee:58:c2:e0" and
            1503532800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_719c17a823839dca813ee85888b3b39a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "71:9c:17:a8:23:83:9d:ca:81:3e:e8:58:88:b3:b3:9a" and
            1479686400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6dc86ebf5863568e2237b2d89582d705 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Dening Hu" and
            pe.signatures[i].serial == "6d:c8:6e:bf:58:63:56:8e:22:37:b2:d8:95:82:d7:05" and
            1471305600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_214df59fe53874cc011dd45727035f51 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "21:4d:f5:9f:e5:38:74:cc:01:1d:d4:57:27:03:5f:51" and
            1468800000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_37ca4f66fdcc8732992723199859886c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aleman Ltd" and
            pe.signatures[i].serial == "37:ca:4f:66:fd:cc:87:32:99:27:23:19:98:59:88:6c" and
            1505952000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_be2f22c152bb218b898c4029056816a9 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Marts GmbH" and (
                pe.signatures[i].serial == "00:be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9" or
                pe.signatures[i].serial == "be:2f:22:c1:52:bb:21:8b:89:8c:40:29:05:68:16:a9"
            ) and
            1676246400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_fc7065abf8303fb472b8af85918f5c24 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DIG IN VISION SP Z O O" and (
                pe.signatures[i].serial == "00:fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24" or
                pe.signatures[i].serial == "fc:70:65:ab:f8:30:3f:b4:72:b8:af:85:91:8f:5c:24"
            ) and
            1604361600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_698ff388adb50b88afb832e76b0a0ad1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BELLAP LIMITED" and
            pe.signatures[i].serial == "69:8f:f3:88:ad:b5:0b:88:af:b8:32:e7:6b:0a:0a:d1" and
            1675070541 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_391ae38670ab188a5de26e07 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DVERI FADO, TOV" and
            pe.signatures[i].serial == "39:1a:e3:86:70:ab:18:8a:5d:e2:6e:07" and
            1540832872 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_d08d83ff118df3777e371c5c482cce7b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "AMO-K Limited Liability Company" and (
                pe.signatures[i].serial == "00:d0:8d:83:ff:11:8d:f3:77:7e:37:1c:5c:48:2c:ce:7b" or
                pe.signatures[i].serial == "d0:8d:83:ff:11:8d:f3:77:7e:37:1c:5c:48:2c:ce:7b"
            ) and
            1444780800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_06ce209477f1ac19a2049bdc5846a831 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Select'Assistance Pro" and
            pe.signatures[i].serial == "06:ce:20:94:77:f1:ac:19:a2:04:9b:dc:58:46:a8:31" and
            1426710344 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_447f449121b883211663b7b7e2ead868 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3 AM CHP" and
            pe.signatures[i].serial == "44:7f:44:91:21:b8:83:21:16:63:b7:b7:e2:ea:d8:68" and
            1443052800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6366a9ac97df4de17366943c9b291aaa {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "xlgames" and
            pe.signatures[i].serial == "63:66:a9:ac:97:df:4d:e1:73:66:94:3c:9b:29:1a:aa" and
            1326796477 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_66e3f0b4459f15ac7f2a2b44990dd709 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "KOG Co., Ltd." and
            pe.signatures[i].serial == "66:e3:f0:b4:45:9f:15:ac:7f:2a:2b:44:99:0d:d7:09" and
            1320288125 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_610039d6349ee531e4caa3a65d100c7d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Wemade Entertainment" and
            pe.signatures[i].serial == "61:00:39:d6:34:9e:e5:31:e4:ca:a3:a6:5d:10:0c:7d" and
            1341792000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1caa0d0dadf32a2404a75195ae47820a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LivePlex Corp" and
            pe.signatures[i].serial == "1c:aa:0d:0d:ad:f3:2a:24:04:a7:51:95:ae:47:82:0a" and
            1324425600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_140d2c515e8ee9739bb5f1b2637dc478 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Guangzhou YuanLuo Technology Co.,Ltd" and
            pe.signatures[i].serial == "14:0d:2c:51:5e:8e:e9:73:9b:b5:f1:b2:63:7d:c4:78" and
            1386806400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_58015acd501fc9c344264eace2ce5730 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Nanjing Ranyi Technology Co., Ltd. " and
            pe.signatures[i].serial == "58:01:5a:cd:50:1f:c9:c3:44:26:4e:ac:e2:ce:57:30" and
            1352246400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0b7279068beb15ffe8060d2c56153c35 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Guangzhou YuanLuo Technology Co.,Ltd" and
            pe.signatures[i].serial == "0b:72:79:06:8b:eb:15:ff:e8:06:0d:2c:56:15:3c:35" and
            1350864000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0bc0f18da36702e302db170d91dc9202 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Foresee Consulting Inc." and
            pe.signatures[i].serial == "0b:c0:f1:8d:a3:67:02:e3:02:db:17:0d:91:dc:92:02" and
            1637712000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ca9b6f49b8b41204a174c751c73dc393 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "CodeDance Ltd" and (
                pe.signatures[i].serial == "00:ca:9b:6f:49:b8:b4:12:04:a1:74:c7:51:c7:3d:c3:93" or
                pe.signatures[i].serial == "ca:9b:6f:49:b8:b4:12:04:a1:74:c7:51:c7:3d:c3:93"
            ) and
            1654646400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_aaf65b8e7a2e68bc8c9e8f27331b795c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALISA L LIMITED" and (
                pe.signatures[i].serial == "00:aa:f6:5b:8e:7a:2e:68:bc:8c:9e:8f:27:33:1b:79:5c" or
                pe.signatures[i].serial == "aa:f6:5b:8e:7a:2e:68:bc:8c:9e:8f:27:33:1b:79:5c"
            ) and
            1549324800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_c6ed0efe2844fa44aae350c6845c3331 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "THE COMPANY OF WORDS LTD" and (
                pe.signatures[i].serial == "00:c6:ed:0e:fe:28:44:fa:44:aa:e3:50:c6:84:5c:33:31" or
                pe.signatures[i].serial == "c6:ed:0e:fe:28:44:fa:44:aa:e3:50:c6:84:5c:33:31"
            ) and
            1549324800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_ede6cfbf9fa18337b0fdb49c1f693020 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "START ARCHITECTURE LTD" and (
                pe.signatures[i].serial == "00:ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20" or
                pe.signatures[i].serial == "ed:e6:cf:bf:9f:a1:83:37:b0:fd:b4:9c:1f:69:30:20"
            ) and
            1554940800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_eda0f47b3b38e781cdf6ef6be5d3f6ee {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ADVANCED ACCESS SERVICES LTD" and (
                pe.signatures[i].serial == "00:ed:a0:f4:7b:3b:38:e7:81:cd:f6:ef:6b:e5:d3:f6:ee" or
                pe.signatures[i].serial == "ed:a0:f4:7b:3b:38:e7:81:cd:f6:ef:6b:e5:d3:f6:ee"
            ) and
            1650931200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5da173eb1ac76340ac058e1ff4bf5e1b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ALISA LTD" and
            pe.signatures[i].serial == "5d:a1:73:eb:1a:c7:63:40:ac:05:8e:1f:f4:bf:5e:1b" and
            1550793600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1380a7ccf2bf36bc496b00d8 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "13:80:a7:cc:f2:bf:36:bc:49:6b:00:d8" and
            1478069976 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_02eaf27e6f1575e365fc7fe4e0be43f7 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Theravada Solutions Ltd" and
            pe.signatures[i].serial == "02:ea:f2:7e:6f:15:75:e3:65:fc:7f:e4:e0:be:43:f7" and
            1562889600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6eb02ac2beb9611ed57eb12e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\x9D\\xA8\\xE5\\x87\\x8C\\xE4\\xBC\\xAF\\xE4\\xB9\\x90\\xE7\\xBD\\x91\\xE7\\xBB\\x9C\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "6e:b0:2a:c2:be:b9:61:1e:d5:7e:b1:2e" and
            1585023767 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_010000000001297dba69dd {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ROSSO INDEX K.K." and
            pe.signatures[i].serial == "01:00:00:00:00:01:29:7d:ba:69:dd" and
            1277713154 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_7def22ef4c645b1decfb36b6d3539dbf {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and
            pe.signatures[i].serial == "7d:ef:22:ef:4c:64:5b:1d:ec:fb:36:b6:d3:53:9d:bf" and
            1474416000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3e39c2ccc494438bb8c2560f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "3e:39:c2:cc:c4:94:43:8b:b8:c2:56:0f" and
            1466142876 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6e3b09f43c3a0fd53b7d600f08fae2b5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Divisible Limited" and
            pe.signatures[i].serial == "6e:3b:09:f4:3c:3a:0f:d5:3b:7d:60:0f:08:fa:e2:b5" and
            1507248000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_21220646c639d62c16992f46 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Sivi Technology Limited" and
            pe.signatures[i].serial == "21:22:06:46:c6:39:d6:2c:16:99:2f:46" and
            1466130984 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_738663f2c9e4adb3ad5306aa5e7cc548 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "GIN-Konsalt" and
            pe.signatures[i].serial == "73:86:63:f2:c9:e4:ad:b3:ad:53:06:aa:5e:7c:c5:48" and
            1498435200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_4280f2c8ce1d98e5f8da7ecb005eeae5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and
            pe.signatures[i].serial == "42:80:f2:c8:ce:1d:98:e5:f8:da:7e:cb:00:5e:ea:e5" and
            1476316800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2946397be9c5ae44e95c99af {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "29:46:39:7b:e9:c5:ae:44:e9:5c:99:af" and
            1476092708 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2df453588177cf1c0c297ff4 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shenzhen Yunhuitianxia Technology Co.,Ltd." and
            pe.signatures[i].serial == "2d:f4:53:58:81:77:cf:1c:0c:29:7f:f4" and
            1479735173 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0619c5e39a4fc60a32f9b07f6a4ca328 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yuanyuan Zhang" and
            pe.signatures[i].serial == "06:19:c5:e3:9a:4f:c6:0a:32:f9:b0:7f:6a:4c:a3:28" and
            1475884800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_2bffef48e6a321b418041310fdb9b0d0 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "A&D DOMUS LIMITED" and
            pe.signatures[i].serial == "2b:ff:ef:48:e6:a3:21:b4:18:04:13:10:fd:b9:b0:d0" and
            1554681600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_34ec9565805f34204c6966fb81e36ba1 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "34:ec:95:65:80:5f:34:20:4c:69:66:fb:81:e3:6b:a1" and
            1476921600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_b2b934b7f01e0ac1e577814992243709 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "MS CORP SOFTWARE LTD" and (
                pe.signatures[i].serial == "00:b2:b9:34:b7:f0:1e:0a:c1:e5:77:81:49:92:24:37:09" or
                pe.signatures[i].serial == "b2:b9:34:b7:f0:1e:0a:c1:e5:77:81:49:92:24:37:09"
            ) and
            1590710400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3a1b397fd9451e3b5891fc69681ed73d {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yongli Zhang" and
            pe.signatures[i].serial == "3a:1b:39:7f:d9:45:1e:3b:58:91:fc:69:68:1e:d7:3d" and
            1470614400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1eb816aa49e4894d9e9f78729e53cd48 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE5\\x96\\x84\\xE5\\x90\\x9B \\xE9\\x9F\\xA6" and
            pe.signatures[i].serial == "1e:b8:16:aa:49:e4:89:4d:9e:9f:78:72:9e:53:cd:48" and
            1429056000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_383ca88d6d9379c740609560 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "38:3c:a8:8d:6d:93:79:c7:40:60:95:60" and
            1478250214 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6731cb1430f18b8c0c43ab40e1154169 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "3 AM CHP" and
            pe.signatures[i].serial == "67:31:cb:14:30:f1:8b:8c:0c:43:ab:40:e1:15:41:69" and
            1436313600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_159505e6456b9a9352f7c47168d89b96 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Shan Feng" and
            pe.signatures[i].serial == "15:95:05:e6:45:6b:9a:93:52:f7:c4:71:68:d8:9b:96" and
            1469404800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_04a0e92b0b9ebbb797df6ef52bd5ad05 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and
            pe.signatures[i].serial == "04:a0:e9:2b:0b:9e:bb:b7:97:df:6e:f5:2b:d5:ad:05" and
            1479081600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_25f222ab2613dc4270b2aabc2519a101 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Aeroscan TOV" and
            pe.signatures[i].serial == "25:f2:22:ab:26:13:dc:42:70:b2:aa:bc:25:19:a1:01" and
            1445299200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_212ca239866f88c3d5b000b3004a569c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "XECURE LAB CO., LTD." and
            pe.signatures[i].serial == "21:2c:a2:39:86:6f:88:c3:d5:b0:00:b3:00:4a:56:9c" and
            1347840000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_18b700a319aa98ae71b279d4e8030b82 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "18:b7:00:a3:19:aa:98:ae:71:b2:79:d4:e8:03:0b:82" and
            1479686400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_169138a86954be1d9b264f47 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "BIG JOURNEY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "16:91:38:a8:69:54:be:1d:9b:26:4f:47" and
            1477636474 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_33412168eeb3c0e4c7dd0508a9ffecd5 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Beijing Caiyunshidai Technology Co., Ltd." and
            pe.signatures[i].serial == "33:41:21:68:ee:b3:c0:e4:c7:dd:05:08:a9:ff:ec:d5" and
            1467590400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_422ab71ac7fb125ad7171b0c99510b0e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "42:2a:b7:1a:c7:fb:12:5a:d7:17:1b:0c:99:51:0b:0e" and
            1475193600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_6f18946e5b773b7e32d9e7b4fb8d434c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VECTOR LLC (VEKTOR, OOO)" and
            pe.signatures[i].serial == "6f:18:94:6e:5b:77:3b:7e:32:d9:e7:b4:fb:8d:43:4c" and
            1454716800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3596dfc23b9a42c66700982250da2906 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Open Source Developer, Song WU" and
            pe.signatures[i].serial == "35:96:df:c2:3b:9a:42:c6:67:00:98:22:50:da:29:06" and
            1397219344 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_486bbddc8c5ee99f051ecaeb3f99d2a3 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "48:6b:bd:dc:8c:5e:e9:9f:05:1e:ca:eb:3f:99:d2:a3" and
            1473292800 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_11211eea9d0d1d1a325b5eae1b2b1951120f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "LLC HERMES" and
            pe.signatures[i].serial == "11:21:1e:ea:9d:0d:1d:1a:32:5b:5e:ae:1b:2b:19:51:12:0f" and
            1460147212 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_172fea8cb06ffced6bfac7f2f6b77754 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Xin Zhou" and
            pe.signatures[i].serial == "17:2f:ea:8c:b0:6f:fc:ed:6b:fa:c7:f2:f6:b7:77:54" and
            1467936000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_3ee50bb98fadca2d662a0920e76685a2 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ABDULKADIR SAHIN" and
            pe.signatures[i].serial == "3e:e5:0b:b9:8f:ad:ca:2d:66:2a:09:20:e7:66:85:a2" and
            1330041600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_21bfddb6a66435d1adce2ceb23ed7c9a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE6\\x9D\\xA8\\xE6\\xB7\\x87\\xE6\\x99\\xBA" and
            pe.signatures[i].serial == "21:bf:dd:b6:a6:64:35:d1:ad:ce:2c:eb:23:ed:7c:9a" and
            1395297334 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_5b1c3f7bbaa91ca49b06a5c1004ee5be {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Jin Yuguang" and
            pe.signatures[i].serial == "5b:1c:3f:7b:ba:a9:1c:a4:9b:06:a5:c1:00:4e:e5:be" and
            1440643213 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0a2089 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "RocketMedia S.r.l." and
            pe.signatures[i].serial == "0a:20:89" and
            1050073884 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_1f84e030a0ed10d5ffe2b81b {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "VANKY TECHNOLOGY LIMITED" and
            pe.signatures[i].serial == "1f:84:e0:30:a0:ed:10:d5:ff:e2:b8:1b" and
            1476869735 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_88346267057c0a82e2f39851d1b9694c {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Hudson LLC" and (
                pe.signatures[i].serial == "00:88:34:62:67:05:7c:0a:82:e2:f3:98:51:d1:b9:69:4c" or
                pe.signatures[i].serial == "88:34:62:67:05:7c:0a:82:e2:f3:98:51:d1:b9:69:4c"
            ) and
            1595376000 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_a46f9d8784778baa48167c48bbc56f30 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Mapping OOO" and (
                pe.signatures[i].serial == "00:a4:6f:9d:87:84:77:8b:aa:48:16:7c:48:bb:c5:6f:30" or
                pe.signatures[i].serial == "a4:6f:9d:87:84:77:8b:aa:48:16:7c:48:bb:c5:6f:30"
            ) and
            1618963200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_525b5529db20d17a85be284d6b7952ea {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Buster Ind Com Imp e Exp de Acessorios P Autos Ltda" and
            pe.signatures[i].serial == "52:5b:55:29:db:20:d1:7a:85:be:28:4d:6b:79:52:ea" and
            1508198400 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_70ae0e517d2ef6d5eed06b56730a1a9a {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Yu Bao" and
            pe.signatures[i].serial == "70:ae:0e:51:7d:2e:f6:d5:ee:d0:6b:56:73:0a:1a:9a" and
            1475193600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_57c3717c5e2ce9a2e0cf0340c03f458e {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "Citizen Travel Ltd" and
            pe.signatures[i].serial == "57:c3:71:7c:5e:2c:e9:a2:e0:cf:03:40:c0:3f:45:8e" and
            1450915200 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_0761110efe0b688c469d687512828c1f {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "ENP Games Co., Ltd." and
            pe.signatures[i].serial == "07:61:11:0e:fe:0b:68:8c:46:9d:68:75:12:82:8c:1f" and
            1433721600 <= pe.signatures[i].not_after
        )
}

rule cert_blocklist_08aa03f385f870e3a6d243b74b1dadf6 {
    meta:
        author      = "ReversingLabs"
        source      = "ReversingLabs"
        status      = "RELEASED"
        sharing     = "TLP:WHITE"
        category    = "INFO"
        description = "Certificate used for digitally signing malware."

    condition:
        uint16(0) == 0x5A4D and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "\\xE4\\xB8\\x9C\\xE8\\x8E\\x9E\\xE5\\xB8\\x82\\xE8\\x85\\xBE\\xE4\\xBA\\x91\\xE8\\xAE\\xA1\\xE7\\xAE\\x97\\xE6\\x9C\\xBA\\xE7\\xA7\\x91\\xE6\\x8A\\x80\\xE6\\x9C\\x89\\xE9\\x99\\x90\\xE5\\x85\\xAC\\xE5\\x8F\\xB8" and
            pe.signatures[i].serial == "08:aa:03:f3:85:f8:70:e3:a6:d2:43:b7:4b:1d:ad:f6" and
            1352678400 <= pe.signatures[i].not_after
        )
}