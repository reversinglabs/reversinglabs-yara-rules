import "pe"

rule Win32_Virus_Mocket : tc_detection malicious
{
    meta:
        id = "1OWjTxI9E05dFXITLtXzEN"
        fingerprint = "b5c7d1edf84bbe99a362c956d57a5881b6940d9976fdfec1f5c6dbd0a09644f5"
        version = "1.0"
        yara_version = "3.2.0"
        first_imported = "2020-07-11"
        last_modified = "2020-07-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects Mocket virus."
        category = "MALWARE"
        malware = "MOCKET"
        malware_type = "VIRUS"
        tc_detection_type = "Virus"
        tc_detection_name = "Mocket"
        tc_detection_factor = 5

    strings:
        $mocket_body_1 = {
            E8 00 00 00 00 5B 81 EB ?? ?? ?? ?? 8B 34 24 81 E6 00 00 FF FF E8 31 00 00 00 89 83 ?? ?? ?? ?? E8 4C 00 00 00 89 83 ??
            ?? ?? ?? E8 A2 00 00 00 E8 CD 00 00 00 E8 05 01 00 00 87 CB E3 0C B8 ?? ?? ?? ?? 05 ?? ?? ?? ?? FF E0 C3 66 81 3E 4D 5A
            75 0E 8B 7E 3C 03 FE 66 81 3F 50 45 75 02 96 C3 81 EE 00 00 01 00 81 FE 00 00 00 70 73 DD 33 C0 C3 8B 70 3C 03 F0 8B 76
            78 03 F0 56 8B 76 20 03 F0 8B C6 33 D2 33 C9 8A 8B ?? ?? ?? ?? 8D BB ?? ?? ?? ?? 8B 34 02 03 B3 ?? ?? ?? ?? 83 C2 04 F3
            A6 75 E2 5E 8B C6 83 EA 04 D1 EA 8B 40 24 03 83 ?? ?? ?? ?? 33 C9 66 8B 0C 02 8B C6 8B 40 1C 03 83 ?? ?? ?? ?? C1 E1 02
            8B 04 01 03 83 ?? ?? ?? ?? C3 8D BB ?? ?? ?? ?? 8D B3 ?? ?? ?? ?? 57 8B 83 ?? ?? ?? ?? 50 8B 83 ?? ?? ?? ?? FF D0 89 06
            83 C6 04 B9 FF FF FF FF 32 C0 F2 AE 80 3F 90 75 DD C3 8D BB ?? ?? ?? ?? 57 68 80 00 00 00 8B 83 ?? ?? ?? ?? FF D0 81 C7
            80 00 00 00 57 68 80 00 00 00 8B 83 ?? ?? ?? ?? FF D0 81 C7 80 00 00 00 57 68 80 00 00 00 8B 83 ?? ?? ?? ?? FF D0 C3 33
            C9 B1 03 8D BB ?? ?? ?? ?? 57 8B 83 ?? ?? ?? ?? FF D0 E8 01 00 00 00 C3 C7 83 ?? ?? ?? ?? 00 00 00 00 8D 83 ?? ?? ?? ??
        }

        $mocket_body_2 = {
            50 8D 83 ?? ?? ?? ?? 50 8B 83 ?? ?? ?? ?? FF D0 40 0B C0 74 53 48 89 83 ?? ?? ?? ?? E8 48 00 00 00 FE 83 ?? ?? ?? ?? 80
            BB ?? ?? ?? ?? 0A 74 29 8D BB ?? ?? ?? ?? B9 ?? ?? ?? ?? 32 C0 F3 AA 8D 83 ?? ?? ?? ?? 50 8B 83 ?? ?? ?? ?? 50 8B 83 ??
            ?? ?? ?? FF D0 0B C0 75 C3 8B 83 ?? ?? ?? ?? 50 8B 83 ?? ?? ?? ?? FF D0 C3 60 8D B3 ?? ?? ?? ?? 56 8B 83 ?? ?? ?? ?? FF
            D0 89 83 ?? ?? ?? ?? 68 80 00 00 00 56 8B 83 ?? ?? ?? ?? FF D0 E8 B7 01 00 00 40 0B C0 0F 84 75 01 00 00 48 89 83 ?? ??
            ?? ?? 8B 8B ?? ?? ?? ?? E8 B4 01 00 00 0B C0 0F 84 4D 01 00 00 89 83 ?? ?? ?? ?? 8B 8B ?? ?? ?? ?? E8 B4 01 00 00 0B C0
            0F 84 26 01 00 00 89 83 ?? ?? ?? ?? 8B 70 3C 03 F0 66 81 3E 50 45 0F 85 F7 00 00 00 81 7E 4C 4B 43 4F 4D 0F 84 EA 00 00
            00 8B 4E 3C 51 8B 46 28 89 83 ?? ?? ?? ?? 8B 46 34 89 83 ?? ?? ?? ?? FF B3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? FF D0 FF B3 ??
            ?? ?? ?? 8B 83 ?? ?? ?? ?? FF D0 59 8B 83 ?? ?? ?? ?? 05 ?? ?? ?? ?? E8 5C 01 00 00 89 83 ?? ?? ?? ?? 91 E8 21 01 00 00
            40 0B C0 0F 84 B9 00 00 00 48 89 83 ?? ?? ?? ?? 8B 8B ?? ?? ?? ?? E8 1F 01 00 00 0B C0 0F 84 91 00 00 00 89 83 ?? ?? ??
        }

        $mocket_body_3 = {
            ?? 8B 70 3C 03 F0 8B FE 83 C6 78 8B 57 74 C1 E2 03 03 F2 0F B7 47 06 48 6B C0 28 03 F0 8B 56 10 8B CA 03 56 14 52 8B C1
            03 46 0C 89 47 28 8B 46 10 05 ?? ?? ?? ?? 8B 4F 3C E8 EA 00 00 00 89 46 10 89 46 08 8B 46 10 03 46 0C 89 47 50 81 4E 24
            20 00 00 A0 C7 47 4C 4B 43 4F 4D 8D B3 ?? ?? ?? ?? 5A 87 FA 03 BB ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A4 EB 0B 8B 8B ?? ?? ??
            ?? E8 41 00 00 00 FF B3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? FF D0 FF B3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? FF D0 FF B3 ?? ?? ?? ??
            8B 83 ?? ?? ?? ?? FF D0 FF B3 ?? ?? ?? ?? 8D 83 ?? ?? ?? ?? 50 8B 83 ?? ?? ?? ?? FF D0 61 C3 33 C0 50 50 51 FF B3 ?? ??
            ?? ?? 8B 83 ?? ?? ?? ?? FF D0 FF B3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? FF D0 C3 33 C0 50 50 6A 03 50 6A 01 68 00 00 00 C0 56
            8B 83 ?? ?? ?? ?? FF D0 C3 6A 00 51 6A 00 6A 04 6A 00 8B 83 ?? ?? ?? ?? 50 8B 83 ?? ?? ?? ?? FF D0 C3 51 6A 00 6A 00 6A
            02 FF B3 ?? ?? ?? ?? 8B 83 ?? ?? ?? ?? FF D0 C3 33 D2 F7 F1 0B D2 74 01 40 F7 E1 C3
        }

    condition:
        uint16(0) == 0x5A4D and ($mocket_body_1 at pe.entry_point) and $mocket_body_2 and $mocket_body_3
}
