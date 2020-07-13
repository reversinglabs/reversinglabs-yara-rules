import "pe"

rule Win32_Ransomware_CryptoWall : tc_detection malicious
{
    meta:
        id = "1J3d8nYE3nWc0cTdWGJjEN"
        fingerprint = "1d5134cadddcfdea2c260534901c270421aec1907bf009bca73c398ef6652c15"
        version = "1.0"
        yara_version = "3.2.0"
        first_imported = "2020-07-11"
        last_modified = "2020-07-12"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "REVERSINGLABS"
        author = "ReversingLabs"
        description = "Yara rule that detects CryptoWall ransomware."
        category = "MALWARE"
        malware = "CRYPTOWALL"
        malware_type = "RANSOMWARE"
        tc_detection_type = "Ransomware"
        tc_detection_name = "CryptoWall"
        tc_detection_factor = 5

    strings:
        $v30_entrypoint = {
            55 8B EC 83 EC ?? E8 ?? ?? ?? ?? 85 C0 0F 84 9A 00 00 00 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 75 7E C7 45 ?? ?? ?? ?? ?? 
            8D 45 ?? 50 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 65 8B 4D ?? 51 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 
            E8 ?? ?? ?? ?? 8B 40 ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 
            75 19 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 6A 
            ?? 6A ?? E8 ?? ?? ?? ?? 8B 50 ?? FF D2 33 C0 8B E5 5D C2
        }

        $v20_entrypoint = {
            55 8B EC 83 EC ?? E8 ?? ?? ?? ?? 85 C0 0F 84 A3 00 00 00 E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 0F 85 83 00 00 00 C7 45 ?? 
            ?? ?? ?? ?? 8D 45 ?? 50 6A ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 6A 8B 4D ?? 51 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B 90 ?? ?? 
            ?? ?? FF D2 E8 ?? ?? ?? ?? 8B 40 ?? A3 ?? ?? ?? ?? C7 05 ?? ?? ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 85 C0 75 19 C7 05 ?? ?? ?? ?? ?? ?? ?? ?? 6A ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 51 
            E8 ?? ?? ?? ?? 83 C4 ?? 6A ?? 6A ?? E8 ?? ?? ?? ?? 8B 50 ?? FF D2 33 C0 8B E5 5D C2
        }

        $v30_api_load = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 06 83 7D ?? ?? 75 08 8B 45 ?? E9 50 01 00 00 8B 45 ?? 50 E8 ?? ?? 
            ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? ?? 0F 84 34 01 00 00 B9 ?? ?? ?? ?? 6B D1 ?? 8B 45 ?? 8B 4D ?? 03 4C 10 ?? 89 4D ?? 8B 
            55 ?? 8B 45 ?? 03 42 ?? 89 45 ?? 8B 4D ?? 8B 55 ?? 03 51 ?? 89 55 ?? 8B 45 ?? 8B 4D ?? 03 48 ?? 89 4D ?? C7 45 ?? ?? ?? 
            ?? ?? EB 09 8B 55 ?? 83 C2 ?? 89 55 ?? 8B 45 ?? 8B 4D ?? 3B 48 ?? 0F 83 DA 00 00 00 8B 55 ?? 8B 45 ?? 8B 4D ?? 03 0C 90 
            51 E8 ?? ?? ?? ?? 83 C4 ?? 3B 45 ?? 0F 85 B7 00 00 00 BA ?? ?? ?? ?? 6B C2 ?? 8B 4D ?? 8B 54 01 ?? 8B 44 01 ?? 89 55 ?? 
            89 45 ?? 8B 4D ?? 8B 55 ?? 0F B7 04 4A 8B 4D ?? 8B 14 81 3B 55 ?? 76 71 8B 45 ?? 8B 4D ?? 0F B7 14 41 8B 45 ?? 03 45 ?? 
            8B 4D ?? 39 04 91 73 59 8B 55 ?? 8B 45 ?? 0F B7 0C 50 8B 55 ?? 8B 45 ?? 03 04 8A 89 45 ?? 74 3F 6A ?? 8B 4D ?? 51 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8B 55 ?? 8D 44 02 ?? 50 8D 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 8D 45 ?? 50 6A ?? 8D 4D ?? 
            51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 40 ?? FF D0 EB 16 8B 4D ?? 8B 55 ?? 0F B7 04 4A 8B 4D ?? 8B 55 ?? 03 14 81 89 55 ?? EB 
            05 E9 0E FF FF FF 8B 45 ?? 8B E5 5D C3
        }

        $v30_dll_load = {
            55 8B EC 83 EC ?? E8 ?? ?? ?? ?? 89 45 ?? 83 7D ?? ?? 74 58 8B 45 ?? 8B 48 ?? 89 4D ?? 8B 55 ?? 83 C2 ?? 89 55 ?? 8B 45 
            ?? 8B 08 89 4D ?? 8B 55 ?? 3B 55 ?? 74 36 8B 45 ?? 89 45 ?? 8B 4D ?? 0F B7 51 ?? D1 EA 52 8B 45 ?? 8B 48 ?? 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? 3B 45 ?? 75 08 8B 55 ?? 8B 42 ?? EB 0C 8B 45 ?? 8B 08 89 4D ?? EB C2 33 C0 8B E5 5D C3
        }

        $v30_calculate_hash = {
            55 8B EC 83 EC ?? 56 C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 5E 83 7D ?? ?? 74 58 8B 45 ?? 89 45 ?? 8B 4D ?? 89 4D ?? 8B 55 
            ?? 83 EA ?? 89 55 ?? 83 7D ?? ?? 74 3D 8B 45 ?? 66 8B 08 66 89 4D ?? 8B 75 ?? C1 EE ?? 0F B7 55 ?? 52 E8 ?? ?? ?? ?? 83 
            C4 ?? 0F B7 C0 33 45 ?? 25 ?? ?? ?? ?? 33 34 85 ?? ?? ?? ?? 89 75 ?? 8B 4D ?? 83 C1 ?? 89 4D ?? EB AE 8B 45 ?? 83 F0 ?? 
            5E 8B E5 5D C3
        }

        $v30_1_find_file_1 = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 06 83 7D ?? ?? 75 08 8B 45 ?? E9 47 02 00 00 E8 ?? ?? ?? ?? 89 45 
            ?? 83 7D ?? ?? 0F 84 32 02 00 00 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 8B 45 ?? 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? 8B 4D ?? 0F B7 54 41 ?? 83 FA ?? 74 16 68 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 68 
            ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? 
            ?? 0F 84 B2 01 00 00 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 89 45 ?? 83 7D ?? ?? 0F 84 84 01 00 
            00 C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 8B 11 83 E2 ?? 0F 85 A0 00 00 00 C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 83 C0 ?? 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? 85 C0 0F 85 80 00 00 00 8D 4D ?? 51 8B 55 ?? 83 C2 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 69 C7 45 ?? ?? ?? 
            ?? ?? 8D 45 ?? 50 8B 4D ?? 83 C1 ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 47 8B 45 ?? 50 8B 4D ?? 8B 11 52 8B 
            45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? ?? 75 1C 8B 4D ?? 83 C1 ?? 89 4D ?? 8B 55 ?? 8B 42 ?? 50 8B 4D ?? 51
        }

        $v30_1_find_file_2 = { 
            E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? EB 67 8B 45 ?? 83 C0 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 
            54 C7 45 ?? ?? ?? ?? ?? 8D 4D ?? 51 8B 55 ?? 83 C2 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 32 8B 4D ?? 51 E8 
            ?? ?? ?? ?? 83 C4 ?? 85 C0 75 16 8B 55 ?? 52 8B 45 ?? 50 E8 30 FE FF FF 83 C4 ?? 03 45 ?? 89 45 ?? 8B 4D ?? 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 85 C0 0F 85 CE FE FF FF 8B 55 ?? 52 E8 ?? 
            ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 83 7D ?? ?? 74 2E 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 50 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 
            C4 ?? 3D ?? ?? ?? ?? 74 0E 6A ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 89 4D ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 
            ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 8B E5 5D C3 
        }

        $v30_2_find_file_1 = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 06 83 7D ?? ?? 75 08 8B 45 ?? E9 ( 3B | 3D ) 02 00 00 E8 ?? ?? ??
            ?? 89 45 ?? 83 7D ?? ?? 0F 84 ( 26 | 28 ) 02 00 00 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 8B 45
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 0F B7 54 41 ?? 83 FA ?? 74 16 68 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ??
            ?? ?? ?? FF D1 68 ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ??
            89 45 ?? 83 7D ?? ?? 0F 84 ( A6 | A8 ) 01 00 00 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 89 45 ??
            83 7D ?? ?? 0F 84 ( 78 | 7A ) 01 00 00 C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 8B 11 83 E2 ?? 0F 85 94 00 00 00 C7 45 ?? ?? ?? ??
            ?? 8B 45 ?? 83 C0 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 78 8B 4D ?? 83 C1 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 65 C7
            45 ?? ?? ?? ?? ?? 8D 55 ?? 52 8B 45 ?? 83 C0 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 43 8B 55 ?? 8B 02 50 8B
        }

        $v30_2_find_file_2 = {
            4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? ?? 75 1C 8B 55 ?? 83 C2 ?? 89 55 ?? 8B 45 ?? 8B 48 ?? 51 8B 55 ?? 52
            E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? EB 67 8B 4D ?? 83 C1 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75
            54 C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 8B 45 ?? 83 C0 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 32 8B 55 ?? 52 E8
            ?? ?? ?? ?? 83 C4 ?? 85 C0 75 16 8B 45 ?? 50 8B 4D ?? 51 E8 3C FE FF FF 83 C4 ?? 03 45 ?? 89 45 ?? 8B 55 ?? 52 E8 ?? ??
            ?? ?? 83 C4 ?? 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 85 C0 0F 85 DA FE FF FF 8B 45 ?? 50 E8 ??
            ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 83 7D ?? ?? 74 ( 2E | 30 ) 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 50 8B 45 ?? 50 E8 ?? ??
            ?? ?? 83 C4 ?? 3D ?? ?? ?? ?? 74 ( 0E | 10 ) 6A ?? [0-2] 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 89 55 ?? 8B 45 ??
            50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 8B E5 5D C3
        }

        $v30_3_find_file_1 = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 06 83 7D ?? ?? 75 08 8B 45 ?? E9 7C 02 00 00 E8 ?? ?? ?? ?? 89 45 
            ?? 83 7D ?? ?? 0F 84 67 02 00 00 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 8B 45 ?? 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? 8B 4D ?? 0F B7 54 41 ?? 83 FA ?? 74 16 68 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 68 
            ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? 
            ?? 0F 84 E7 01 00 00 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 89 45 ?? 83 7D ?? ?? 0F 84 B9 01 00 
            00 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 83 C1 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 85 91 00 00 00 8D 55 
            ?? 52 8B 45 ?? 83 C0 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 7A 8B 4D ?? 8B 11 83 E2 ?? 75 70 C7 45 ?? ?? ?? ?? ?? 8D 45 
            ?? 50 8B 4D ?? 83 C1 ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 49 8B 45 ?? 8B 48 ?? 51 8B 55 ?? 52 8B 45 ?? 8B
        }

        $v30_3_find_file_2 = {
            08 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 1C 8B 45 ?? 83 C0 ?? 89 45 ?? 8B 4D ?? 8B 51 ?? 52 8B 45 ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? E9 88 00 00 00 8B 55 ?? 8B 02 83 E0 ?? 74 7E 8B 4D ?? 83 79 ?? ?? 
            74 75 8B 55 ?? 83 C2 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 62 C7 45 ?? ?? ?? ?? ?? 8D 45 ?? 50 8B 4D ?? 83 C1 ?? 51 8B 
            55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 40 8B 45 ?? 50 8B 4D ?? 8B 51 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 1D 8B 45 
            ?? 50 8B 4D ?? 51 E8 15 FE FF FF 83 C4 ?? 85 C0 74 09 8B 55 ?? 83 C2 ?? 89 55 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 
            4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 85 C0 0F 85 AC FE FF FF 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? 
            ?? ?? ?? FF D2 8B 45 ?? 50 8B 4D ?? 8B 51 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 74 2E 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 
            C4 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 3D ?? ?? ?? ?? 74 0E 6A ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 89 
            45 ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 8B E5 5D C3
        }

        $v20_1_encrypt_file_1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 56 C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 06 83 7D ?? ?? 75 08 8B 45 ?? E9 99 05 00 00 8B 45 ?? 
            83 38 ?? 74 1B 8B 4D ?? 83 79 ?? ?? 74 12 8B 55 ?? 83 7A ?? ?? 74 09 8B 45 ?? 83 78 ?? ?? 75 08 8B 45 ?? E9 6E 05 00 00 
            8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 89 45 ?? 6A ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 C7 
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? 
            ?? ?? ?? FF D0 89 45 ?? 83 7D ?? ?? 0F 84 F4 04 00 00 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 8B 
            4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 85 C0 74 07 C7 45 ?? ?? ?? ?? ?? 66 0F 57 C0 66 0F 13 45 ?? 8D 45 ?? 50 
            8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 85 E7 03 00 00 66 0F 57 C0 66 0F 13 85 ?? ?? ?? ?? 6A ?? 6A ?? 
            8B 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 83 F8 ?? 0F 84 AF 03 00 00 
            8D 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 97 03 00 00 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 
            45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 89 45 ?? 83 7D ?? ?? 0F 84 6A 03 00 00 C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 
            E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 2C 03 00 00 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? 8D 45 ?? 50 8D 4D ?? 51 8D 55 ?? 52 8D 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 D9 02 00 00
        }

        $v20_1_encrypt_file_2 = {
            C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 8D 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 8B 48 ?? 51 8B 55 ?? 
            8B 02 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 81 02 00 00 C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 4D ?? 51 8B 55 ?? 8B 42 ?? 50 8B 
            4D ?? 8B 51 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 85 C0 0F 84 41 02 00 00 8B 55 ?? 8B 45 ?? 3B 42 ?? 
            0F 85 32 02 00 00 6A ?? 8D 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 85 C0 0F 
            84 0B 02 00 00 8B 45 ?? 3B 45 ?? 0F 85 FF 01 00 00 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 C7 45 ?? ?? ?? ?? 
            ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? ?? 0F 84 CE 01 00 00 66 0F 57 C0 66 0F 13 45 ?? C7 45 ?? ?? ?? 
            ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 3B 4D ?? 75 0C 8B 55 ?? 3B 55 ?? 0F 84 73 01 00 00 C7 45 ?? ?? 
            ?? ?? ?? 8B 45 ?? 33 C9 8B 55 ?? 2B 55 ?? 8B 75 ?? 1B 75 ?? 89 85 ?? ?? ?? ?? 89 4D ?? 89 55 ?? 89 75 ?? 8B 45 ?? 3B 45 
            ?? 77 1A 72 0B 8B 8D ?? ?? ?? ?? 3B 4D ?? 73 0D 8B 55 ?? 33 C0 89 55 ?? 89 45 ?? EB 12 8B 4D ?? 2B 4D ?? 8B 55 ?? 1B 55 
            ?? 89 4D ?? 89 55 ?? 8B 45 ?? 89 45 ?? 8B 4D ?? 33 D2 03 4D ?? 13 55 ?? 89 8D ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8B 85 ?? ?? 
            ?? ?? 3B 45 ?? 75 12 8B 8D ?? ?? ?? ?? 3B 4D ?? 75 07 C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B
        }

        $v20_1_encrypt_file_3 = { 
            55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 85 C0 0F 84 A2 00 00 00 8B 4D ?? 3B 4D ?? 0F 85 96 00 00 00 C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 8D 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 E8 ?? 
            ?? ?? ?? 83 C4 ?? 85 C0 74 60 6A ?? 8D 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF 
            D1 85 C0 74 31 8B 55 ?? 3B 55 ?? 75 29 8B 45 ?? 33 C9 03 45 ?? 13 4D ?? 89 45 ?? 89 4D ?? C7 45 ?? ?? ?? ?? ?? 8B 55 ?? 
            52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 75 02 EB 0D 83 7D ?? ?? 74 02 
            EB 05 E9 79 FE FF FF 83 7D ?? ?? 74 17 8B 55 ?? 3B 55 ?? 75 0F 8B 45 ?? 3B 45 ?? 75 07 C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 51 
            E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 51 E8 ?? ?? ?? 
            ?? 8B 90 ?? ?? ?? ?? FF D2 6A ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? 
            ?? ?? ?? FF D0 83 7D ?? ?? 74 0C 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 
            83 7D ?? ?? 75 22 6A ?? 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 85 C0 75 07 C7 45 ?? ?? ?? ?? ?? 
            8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 74 60 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 
            68 ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 89 45 ?? 83 7D ?? ?? 74 37 8D 95 ?? ?? ?? ?? 52 8D 85 
            ?? ?? ?? ?? 50 8D 8D ?? ?? ?? ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 
            ?? ?? ?? ?? FF D2 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 8B 45 ?? 5E 8B E5 5D C3 
        }

        $v30_1_encrypt_file_1 = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 06 83 7D ?? ?? 75 08 8B 45 ?? E9 02 05 00 00 8B 45 ?? 83 38 ?? 74 
            09 8B 4D ?? 83 79 ?? ?? 75 08 8B 45 ?? E9 E9 04 00 00 C7 45 ?? ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 
            FF D0 89 45 ?? 6A ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 
            45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 89 45 ?? 83 7D ?? ?? 0F 84 6F 04 00 00 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 
            C4 ?? 85 C0 0F 85 90 03 00 00 6A ?? 6A ?? 6A ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 83 F8 ?? 0F 84 70 03 
            00 00 6A ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 89 45 ?? 83 7D ?? ?? 0F 84 50 03 00 00 8D 55 ?? 52 8B 45 
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 38 03 00 00 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 4D ?? 51 E8 ?? ?? 
            ?? ?? 8B 90 ?? ?? ?? ?? FF D2 89 45 ?? 83 7D ?? ?? 0F 84 04 03 00 00 6A ?? 6A ?? 8B 45 ?? 8B 48 ?? 51 8B 55 ?? 52 E8 ?? 
            ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 83 F8 ?? 0F 84 CC 02 00 00 8B 4D ?? 3B 4D ?? 73 08 8B 55 ?? 89 55 ?? EB 06 8B 45 ?? 89 
            45 ?? 8B 4D ?? 89 4D ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 6A ?? 6A ?? 8B 45 ?? 8B 08 51 E8 ?? ?? ?? 
            ?? 8B 90 ?? ?? ?? ?? FF D2 85 C0 0F 84 73 01 00 00 8B 45 ?? 8B 48 ?? 83 E9 ?? 89 4D ?? 8B 55 ?? D1 E2 89 55 ?? 8B 45 ??
        }

        $v30_1_encrypt_file_2 = {
            50 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? ?? 0F 84 35 01 00 00 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 2B 4D ?? 39 4D ?? 73 08 8B 55 ?? 89 55 ?? EB 09 8B 45 ?? 2B 45 ?? 89 45 ?? 8B 4D 
            ?? 89 4D ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 
            FF D0 85 C0 0F 84 94 00 00 00 8B 4D ?? 3B 4D ?? 0F 85 88 00 00 00 8B 55 ?? 3B 55 ?? 73 07 C7 45 ?? ?? ?? ?? ?? 83 7D ?? 
            ?? 74 73 8B 45 ?? 89 45 ?? 8B 4D ?? 51 8D 55 ?? 52 8B 45 ?? 50 6A ?? 8B 4D ?? 51 6A ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 
            ?? ?? ?? ?? FF D0 85 C0 74 44 6A ?? 8D 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF 
            D2 85 C0 74 21 8B 45 ?? 3B 45 ?? 75 19 8B 4D ?? 03 4D ?? 89 4D ?? 8B 55 ?? 03 55 ?? 89 55 ?? C7 45 ?? ?? ?? ?? ?? 83 7D 
            ?? ?? 74 06 83 7D ?? ?? 74 02 EB 0C 8B 45 ?? 3B 45 ?? 0F 85 FB FE FF FF 8B 4D ?? 3B 4D ?? 75 07 C7 45 ?? ?? ?? ?? ?? 8B 
            55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 83 7D ?? ?? 0F 85 02 01 00 00 C7 45 
            ?? ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 83 F8 ?? 0F 84 DB 00 00 00 6A ?? 8D 
            4D ?? 51 8B 55 ?? 8B 42 ?? 50 8B 4D ?? 8B 51 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 85 C0 0F 84 AE 00
        }

        $v30_1_encrypt_file_3 = { 
            00 00 8B 55 ?? 8B 45 ?? 3B 42 ?? 0F 85 9F 00 00 00 6A ?? 8D 4D ?? 51 6A ?? 8D 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 
            ?? ?? ?? ?? FF D1 85 C0 74 7E 83 7D ?? ?? 75 78 8B 55 ?? 3B 55 ?? 74 1B 8B 45 ?? 8B 4D ?? 03 48 ?? 89 4D ?? 8B 55 ?? 2B 
            55 ?? 89 55 ?? 8B 45 ?? 89 45 ?? 6A ?? 8D 4D ?? 51 6A ?? 8D 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 
            85 C0 74 34 83 7D ?? ?? 75 2E 6A ?? 8D 55 ?? 52 6A ?? 8D 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 85 
            C0 74 0D 83 7D ?? ?? 75 07 C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 EB 07 C7 45 ?? ?? ?? 
            ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 83 7D ?? ?? 75 71 83 7D ?? ?? 75 28 83 7D ?? ?? 75 22 68 ?? ?? 
            ?? ?? 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 07 C7 45 ?? ?? ?? ?? ?? EB 43 83 7D ?? ?? 74 36 83 7D ?? 
            ?? 74 30 C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 
            74 07 C7 45 ?? ?? ?? ?? ?? EB 07 C7 45 ?? ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 
            C4 ?? EB 07 C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 8B 45 ?? 8B E5 5D C3
        }

        $v30_2_encrypt_file_1 = {
            55 8B EC 81 EC ?? ?? ?? ?? 56 C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 06 83 7D ?? ?? 75 08 8B 45 ?? E9 BF 05 00 00 8B 45 ?? 
            83 38 ?? 74 1B 8B 4D ?? 83 79 ?? ?? 74 12 8B 55 ?? 83 7A ?? ?? 74 09 8B 45 ?? 83 78 ?? ?? 75 08 8B 45 ?? E9 94 05 00 00 
            8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 89 45 ?? 6A ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 C7 
            45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? 
            ?? ?? ?? FF D0 89 45 ?? 83 7D ?? ?? 0F 84 1A 05 00 00 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? ?? ?? 52 8D 85 ?? ?? ?? ?? 50 8B 
            4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 85 C0 74 07 C7 45 ?? ?? ?? ?? ?? 66 0F 57 C0 66 0F 13 45 ?? 8D 45 ?? 50 
            8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 85 0D 04 00 00 66 0F 57 C0 66 0F 13 85 ?? ?? ?? ?? 6A ?? 6A ?? 
            8B 85 ?? ?? ?? ?? 50 8B 8D ?? ?? ?? ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 83 F8 ?? 0F 84 D5 03 00 00 
            8D 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 BD 03 00 00 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 
            45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 89 45 ?? 83 7D ?? ?? 0F 84 90 03 00 00 C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 
            E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 52 03 00 00 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? 8D 45 ?? 50 8D 4D ?? 51 8D 55 ?? 52 8D 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 FF 02 00 00 
        }

        $v30_2_encrypt_file_2 = {
            C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 8D 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 8B 48 ?? 51 8B 55 ?? 
            8B 02 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 A7 02 00 00 C7 45 ?? ?? ?? ?? ?? 6A ?? 8D 4D ?? 51 8B 55 ?? 8B 42 ?? 50 8B 
            4D ?? 8B 51 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 85 C0 0F 84 67 02 00 00 8B 55 ?? 8B 45 ?? 3B 42 ?? 
            0F 85 58 02 00 00 6A ?? 8D 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 85 C0 0F 
            84 31 02 00 00 8B 45 ?? 3B 45 ?? 0F 85 25 02 00 00 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 C7 45 ?? ?? ?? ?? 
            ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? ?? 0F 84 F4 01 00 00 66 0F 57 C0 66 0F 13 45 ?? C7 45 ?? ?? ?? 
            ?? ?? 66 0F 57 C0 66 0F 13 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 3B 4D ?? 75 0C 8B 55 ?? 3B 55 ?? 0F 
            84 90 01 00 00 C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 33 C9 8B 55 ?? 2B 55 ?? 8B 75 ?? 1B 75 ?? 89 85 ?? ?? ?? ?? 89 8D ?? ?? ?? 
            ?? 89 95 ?? ?? ?? ?? 89 75 ?? 8B 85 ?? ?? ?? ?? 3B 45 ?? 77 1D 72 0E 8B 8D ?? ?? ?? ?? 3B 8D ?? ?? ?? ?? 73 0D 8B 55 ?? 
            33 C0 89 55 ?? 89 45 ?? EB 12 8B 4D ?? 2B 4D ?? 8B 55 ?? 1B 55 ?? 89 4D ?? 89 55 ?? 8B 45 ?? 89 45 ?? 8B 4D ?? 33 D2 03 
            4D ?? 13 55 ?? 89 8D ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 8B 85 ?? ?? ?? ?? 3B 45 ?? 75 12 8B 8D ?? ?? ?? ?? 3B 4D ?? 75 07 C7 
            45 ?? ?? ?? ?? ?? 6A ?? 8D 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 85 C0 0F 
            84 B3 00 00 00 8B 4D ?? 3B 4D ?? 0F 85 A7 00 00 00 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8D 55 ?? 52 8D 45 ?? 50 8B
        }

        $v30_2_encrypt_file_3 = {
            4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 74 71 6A ?? 8D 45 ?? 50 8B 4D ?? 
            51 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 85 C0 74 42 8B 55 ?? 3B 55 ?? 75 3A 8B 45 ?? 33 C9 03 
            45 ?? 13 4D ?? 89 45 ?? 89 4D ?? C7 45 ?? ?? ?? ?? ?? 8B 55 ?? 33 C0 03 55 ?? 13 45 ?? 89 55 ?? 89 45 ?? 8B 4D ?? 51 E8 
            ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 75 02 EB 0D 83 7D ?? ?? 74 02 EB 05 
            E9 5C FE FF FF 83 7D ?? ?? 74 17 8B 4D ?? 3B 4D ?? 75 0F 8B 55 ?? 3B 55 ?? 75 07 C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 
            88 ?? ?? ?? ?? FF D1 6A ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? 
            ?? FF D2 83 7D ?? ?? 74 0C 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 83 7D 
            ?? ?? 75 22 6A ?? 8B 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 85 C0 75 07 C7 45 ?? ?? ?? ?? ?? 8B 45 
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 74 60 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? 
            ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 89 45 ?? 83 7D ?? ?? 74 37 8D 8D ?? ?? ?? ?? 51 8D 95 ?? ?? 
            ?? ?? 52 8D 85 ?? ?? ?? ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? 
            ?? ?? FF D1 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 8B 45 ?? 5E 8B E5 5D C3 
        }

        $v30_3_encrypt_file_1 = {
            55 8B EC 83 EC ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 75 08 8B 45 ?? E9 48 04 00 00 83 7D ?? ?? 75 08 8B 45 ?? E9 3A 04 00 
            00 8B 45 ?? 83 78 ?? ?? 74 11 8B 4D ?? 83 39 ?? 74 09 8B 55 ?? 83 7A ?? ?? 75 08 8B 45 ?? E9 18 04 00 00 C7 45 ?? ?? ?? 
            ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 89 45 ?? 6A ?? 8B 55 
            ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 6A ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 
            90 ?? ?? ?? ?? FF D2 89 45 ?? 83 7D ?? ?? 0F 84 90 03 00 00 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 0F 84 
            83 00 00 00 8B 45 ?? 8B 48 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? ?? 74 6B 6A ?? 8D 55 ?? 52 8B 45 ?? 8B 48 ?? 
            51 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 85 C0 74 39 8B 55 ?? 3B 15 ?? ?? ?? ?? 75 2E 8B 45 ?? 
            8B 48 ?? 51 8B 55 ?? 8B 42 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 50 ?? FF D2 85 C0 75 0E C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? 
            ?? ?? ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 7D ?? ?? 0F 84 9A 02 00 00 6A ?? 6A ?? 6A ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 
            8B 90 ?? ?? ?? ?? FF D2 6A ?? 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 89 45 ?? 83 7D ?? ?? 0F 84 63 02 00 00 
            8B 55 ?? 3B 55 ?? 0F 87 57 02 00 00 8D 45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 3F 02 00 00 6A ?? 6A
        }

        $v30_3_encrypt_file_2 = {
            6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 89 45 ?? 83 7D ?? ?? 0F 84 0B 02 00 
            00 C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 81 E1 ?? ?? ?? ?? 74 1C 6A ?? 6A ?? 8B 15 ?? ?? ?? ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 
            88 ?? ?? ?? ?? FF D1 C7 45 ?? ?? ?? ?? ?? 68 ?? ?? ?? ?? 6A ?? 6A ?? 6A ?? 8D 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 
            FF D0 85 C0 0F 84 52 01 00 00 C7 45 ?? ?? ?? ?? ?? 8D 4D ?? 51 6A ?? 6A ?? 8B 55 ?? 8B 02 50 8B 4D ?? 8B 51 ?? 52 8B 45 
            ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 85 C0 0F 84 0A 01 00 00 8B 55 ?? 8B 42 ?? 83 E8 ?? 89 45 ?? 8B 4D ?? D1 E1 
            89 4D ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 89 45 ?? 83 7D ?? ?? 0F 84 CC 00 00 00 C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? 
            ?? ?? 6A ?? 8D 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 85 C0 74 76 8B 55 ?? 
            3B 55 ?? 73 07 C7 45 ?? ?? ?? ?? ?? 83 7D ?? ?? 74 5F 8B 45 ?? 50 8D 4D ?? 51 8B 55 ?? 52 6A ?? 8B 45 ?? 50 6A ?? 8B 4D 
            ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 85 C0 74 21 6A ?? 8D 45 ?? 50 8B 4D ?? 51 8B 55 ?? 52 8B 45 ?? 50 E8 ?? ?? 
            ?? ?? 8B 88 ?? ?? ?? ?? FF D1 EB 15 83 7D ?? ?? 74 0D 83 7D ?? ?? 74 07 C7 45 ?? ?? ?? ?? ?? EB 0E EB 02 EB 0A 83 7D ?? 
            ?? 0F 84 54 FF FF FF 83 7D ?? ?? 74 07 C7 45 ?? ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 ?? 50 E8 ?? ?? ??
        }

        $v30_3_encrypt_file_3 = { 
            ?? 8B 88 ?? ?? ?? ?? FF D1 6A ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 83 7D ?? ?? 75 47 8B 4D ?? 81 E1 ?? 
            ?? ?? ?? 74 3C 6A ?? 6A ?? 6A ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 6A ?? 8D 4D ?? 51 8B 55 ?? 8B 42 ?? 
            50 8B 4D ?? 8B 51 ?? 52 8B 45 ?? 50 E8 ?? ?? ?? ?? 8B 88 ?? ?? ?? ?? FF D1 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? 
            FF D0 EB 07 C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 51 E8 ?? ?? ?? ?? 8B 90 ?? ?? ?? ?? FF D2 83 7D ?? ?? 75 20 68 ?? ?? ?? ?? 8B 
            45 ?? 50 8B 4D ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 07 C7 45 ?? ?? ?? ?? ?? 8B 55 ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B 45 
            ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? EB 07 C7 45 ?? ?? ?? ?? ?? 8B 4D ?? 51 8B 55 ?? 52 E8 ?? ?? ?? ?? 8B 80 ?? ?? ?? ?? FF D0 
            8B 45 ?? 8B E5 5D C3 
        }

    condition:
        uint16(0) == 0x5A4D and ((($v30_entrypoint at pe.entry_point) and $v30_api_load and $v30_calculate_hash and $v30_dll_load and
          $v30_1_find_file_1 and $v30_1_find_file_2 and $v30_1_encrypt_file_1 and $v30_1_encrypt_file_2 and $v30_1_encrypt_file_3) or
        (($v30_entrypoint at pe.entry_point) and $v30_api_load and $v30_calculate_hash and $v30_dll_load and
        $v30_2_find_file_1 and $v30_2_find_file_2 and $v30_2_encrypt_file_1 and $v30_2_encrypt_file_2 and $v30_2_encrypt_file_3) or
        (($v20_entrypoint at pe.entry_point) and $v30_api_load and $v30_calculate_hash and $v30_dll_load and
        $v30_2_find_file_1 and $v30_2_find_file_2 and $v20_1_encrypt_file_1 and $v20_1_encrypt_file_2 and $v20_1_encrypt_file_3) or
        (($v30_entrypoint at pe.entry_point) and $v30_api_load and $v30_calculate_hash and $v30_dll_load and
        $v30_3_find_file_1 and $v30_3_find_file_2 and $v30_3_encrypt_file_1 and $v30_3_encrypt_file_2 and $v30_3_encrypt_file_3))
}
