rule Linux_Ransomware_Kraken : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        description         = "Yara rule that detects Kraken ransomware."
		malware				= "Kraken"
		malware_type		= "Ransomware"
        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Kraken"
        tc_detection_factor = 5

    strings:

        $enum_volumes = {
            55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? ?? ?? ?? ?? 04 ?? 00 A1 ?? ?? ?? ?? 
            33 C5 89 45 ?? 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? ?? ?? ?? ?? 50 45 4C 00 C7 45 
            FC 00 00 00 00 B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8D 85 ?? ?? 
            ?? ?? 50 68 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 8D B5 ?? ?? ?? ?? 0F 1F 84 00 ?? ?? ?? ?? 
            8A 06 84 C0 0F 84 ?? ?? ?? ?? 3C ?? 0F 84 ?? ?? ?? ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 8B D6 8B C8 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 EC ?? 8B D4 
            C7 42 ?? ?? ?? ?? ?? C7 42 ?? ?? ?? ?? ?? 83 7A ?? ?? 72 ?? 8B 02 EB ?? 8B C2 C6 00 
            ?? 80 3E ?? 75 ?? 33 C9 EB ?? 8B CE 8D 79 ?? 8A 01 41 84 C0 75 ?? 2B CF 51 56 8B CA 
            E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            8B D6 8B C8 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 83 C6 ?? E9 ?? ?? ?? ?? BA ?? 
            ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C8 E8 ?? ?? ?? ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 83 EC ?? 8B CC C7 41 ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? 83 79 ?? 
            ?? 72 ?? 8B 01 EB ?? 8B C1 6A ?? 68 ?? ?? ?? ?? C6 00 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 83 C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? BA ?? ?? ?? ?? 8B C8 E8 ?? 
            ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 
            E8 ?? ?? ?? ?? 83 C4 ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 
            ?? ?? ?? ?? 8B E5 5D C3 BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? 83 C4 ?? B8 ?? ?? ?? ?? C3 
        }

        $enum_shares_p1 = {
            50 56 6A ?? 6A ?? 6A ?? FF 15 ?? ?? ?? ?? 85 C0 74 ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? 
            E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 32 C0 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 
            5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 66 0F 1F 44 00 ?? FF 75 ?? 6A ?? FF 
            15 ?? ?? ?? ?? 8B F0 8D 45 ?? 50 56 8D 45 ?? 89 75 ?? 50 FF 75 ?? FF 15 ?? ?? ?? ?? 
            85 C0 0F 85 ?? ?? ?? ?? 33 FF 0F 1F 40 ?? 3B 7D ?? 0F 83 ?? ?? ?? ?? 8B C7 C1 E0 ?? 
            03 F0 F7 46 ?? ?? ?? ?? ?? 74 ?? 6A ?? E8 ?? ?? ?? ?? 0F 10 06 83 C4 ?? 8B C8 0F 11 
            00 0F 10 46 ?? 0F 11 40 ?? E8 ?? ?? ?? ?? 8B 75 ?? B3 ?? 47 EB ?? F7 46 ?? ?? ?? ?? 
            ?? 0F 84 ?? ?? ?? ?? 8B 56 ?? 85 D2 0F 84 ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? 
            ?? ?? ?? ?? C6 45 ?? ?? 80 3A ?? 75 ?? 33 C9 EB ?? 8B CA 8D 71 ?? 8A 01 41 84 C0 75 
            ?? 2B CE 51 52 8D 4D ?? E8 ?? ?? ?? ?? 51 8D 55 ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? 
            ?? 83 C4 ?? 8B F0 BA ?? ?? ?? ?? C6 45 ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D6 8B 
            C8 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? C6 45 ?? ?? 83 C4 ?? 8B 45 ?? 83 F8 ?? 72 ?? 8B
        }

        $enum_shares_p2 = {
            4D ?? 40 3D ?? ?? ?? ?? 72 ?? F6 C1 ?? 74 ?? E8 ?? ?? ?? ?? 8B 41 ?? 3B C1 72 ?? E8 
            ?? ?? ?? ?? 2B C8 83 F9 ?? 73 ?? E8 ?? ?? ?? ?? 83 F9 ?? 76 ?? E8 ?? ?? ?? ?? 8B C8 
            51 E8 ?? ?? ?? ?? 83 C4 ?? 83 EC ?? 8D 55 ?? 8B CC 51 E8 ?? ?? ?? ?? 83 C4 ?? E8 ?? 
            ?? ?? ?? 83 C4 ?? 8D 55 ?? 51 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B F0 BA ?? ?? ?? ?? 
            C6 45 ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B D6 8B C8 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? 
            ?? C6 45 ?? ?? 83 C4 ?? 8B 45 ?? 83 F8 ?? 72 ?? 8B 4D ?? 40 3D ?? ?? ?? ?? 72 ?? F6 
            C1 ?? 74 ?? E8 ?? ?? ?? ?? 8B 41 ?? 3B C1 72 ?? E8 ?? ?? ?? ?? 2B C8 83 F9 ?? 73 ?? 
            E8 ?? ?? ?? ?? 83 F9 ?? 76 ?? E8 ?? ?? ?? ?? 8B C8 51 E8 ?? ?? ?? ?? 83 C4 ?? C6 45 
            ?? ?? 8B 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 83 F8 ?? 72 ?? 
            8B 4D ?? 40 3D ?? ?? ?? ?? 72 ?? F6 C1 ?? 74 ?? E8 ?? ?? ?? ?? 8B 41 ?? 3B C1 72 ?? 
            E8 ?? ?? ?? ?? 2B C8 83 F9 ?? 73 ?? E8 ?? ?? ?? ?? 83 F9 ?? 76 ?? E8 ?? ?? ?? ?? 8B 
            C8 51 E8 ?? ?? ?? ?? 83 C4 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C6 45 ?? ?? 
            8B 75 ?? B3 ?? 47 E9 ?? ?? ?? ?? 56 FF 15 ?? ?? ?? ?? FF 75 ?? FF 15 ?? ?? ?? ?? BA 
            ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8A C3 E9 ?? ?? 
            ?? ?? BA ?? ?? ?? ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? B8 ?? 
            ?? ?? ?? C3 
        }

        $find_files = {
              55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? ?? ?? ?? 
              ?? EC 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? ?? ?? ?? ?? 45 FC 00 00 00 00 8D 4D ?? 
              C6 45 ?? ?? 8B 75 ?? 83 FE ?? 8B 7D ?? 8B 55 ?? 0F 43 CF 6A ?? 68 ?? ?? ?? ?? E8 ?? 
              ?? ?? ?? 83 C4 ?? 8D 4D ?? 85 C0 0F 84 ?? ?? ?? ?? 83 FE ?? 6A ?? 0F 43 CF 68 ?? ?? 
              ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? 85 C0 0F 84 ?? ?? ?? ?? 83 FE ?? 6A ?? 0F 43 
              CF 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? 85 C0 0F 84 ?? ?? ?? ?? 83 FE ?? 
              6A ?? 0F 43 CF 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 0F 57 
              C0 C7 45 ?? ?? ?? ?? ?? 66 0F D6 45 ?? C7 45 ?? ?? ?? ?? ?? C7 45 ?? ?? ?? ?? ?? C7 
              45 ?? ?? ?? ?? ?? 83 FE ?? C6 45 ?? ?? 8D 4D ?? 0F 43 CF E8 ?? ?? ?? ?? 8B F0 89 75 
              ?? 85 F6 0F 84 ?? ?? ?? ?? 8D 45 ?? 8B D6 50 8B CE E8 ?? ?? ?? ?? 8B 5D ?? 83 C4 ?? 
              85 DB 0F 84 ?? ?? ?? ?? 8D 7B ?? B9 ?? ?? ?? ?? 8B C7 66 0F 1F 44 00 ?? 8A 10 3A 11 
              75 ?? 84 D2 74 ?? 8A 50 ?? 3A 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 84 D2 75 ?? 33 F6 EB ?? 
              1B F6 83 CE ?? B9 ?? ?? ?? ?? 8B C7 0F 1F 40 ?? 8A 10 3A 11 75 ?? 84 D2 74 ?? 8A 50 
              ?? 3A 51 ?? 75 ?? 83 C0 ?? 83 C1 ?? 84 D2 75 ?? 33 C0 EB ?? 1B C0 83 C8 ?? 3B F0 8B 
              75 ?? 0F 85 ?? ?? ?? ?? 8B 43 ?? 85 C0 0F 84 ?? ?? ?? ?? 8D 4D ?? 57 3D ?? ?? ?? ?? 
              75 ?? E8 ?? ?? ?? ?? 50 8D 55 ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 EC 
              ?? C6 45 ?? ?? 8B CC 8B D0 51 E8 ?? ?? ?? ?? 83 C4 ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D 
              ?? E8 ?? ?? ?? ?? 8D 4D ?? C6 45 ?? ?? E8 ?? ?? ?? ?? E9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
              83 EC ?? C6 45 ?? ?? 8B CC 8D 55 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? E8 ?? ?? ?? ?? 83 C4 
              ?? C6 45 ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 75 ?? E9 ?? ?? ?? ?? 8B CE E8 ?? ?? ?? ?? 
              83 EC ?? 8D 45 ?? 8B CC 50 E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? EB ?? BA ?? ?? ?? 
              ?? B9 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8D 55 ?? 8B C8 E8 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 
              C4 ?? B8 ?? ?? ?? ?? C3 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8D 4D ?? E8 ?? ?? ?? 
              ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 4D ?? 64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD 
              E8 ?? ?? ?? ?? 8B E5 5D C3 
        }

        $encrypt_files_p1 = {
              55 8B EC 6A ?? 68 ?? ?? ?? ?? 64 A1 ?? ?? ?? ?? ?? ?? ?? ?? A1 ?? ?? ?? ?? ?? ?? ?? 
              ?? EC 53 56 57 50 8D 45 ?? 64 A3 ?? ?? ?? ?? ?? ?? ?? ?? 45 FC 00 00 00 00 C6 45 ?? 
              ?? 83 05 ?? ?? ?? ?? ?? 83 15 ?? ?? ?? ?? ?? 83 EC ?? 8B CC C7 41 ?? ?? ?? ?? ?? C7 
              41 ?? ?? ?? ?? ?? 83 79 ?? ?? 72 ?? 8B 01 EB ?? 8B C1 6A ?? C6 00 ?? 8D 45 ?? 6A ?? 
              50 E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? 83 EC ?? C6 45 ?? ?? 8B CC C7 41 
              ?? ?? ?? ?? ?? C7 41 ?? ?? ?? ?? ?? 83 79 ?? ?? 72 ?? 8B 01 EB ?? 8B C1 6A ?? C6 00 
              ?? 8D 45 ?? 6A ?? 50 E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 83 C4 ?? C6 45 ?? ?? 8D 
              4D ?? 83 3D ?? ?? ?? ?? ?? B8 ?? ?? ?? ?? 8B 7D ?? 0F 43 05 ?? ?? ?? ?? 83 FF ?? FF 
              35 ?? ?? ?? ?? 8B 75 ?? 0F 43 CE 8B 55 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? 
              ?? ?? ?? 83 FF ?? 8D 4D ?? 6A ?? 0F 43 CE 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 
              C0 0F 84 ?? ?? ?? ?? 83 FF ?? 8D 4D ?? 6A ?? 0F 43 CE 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
              83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? 83 FF ?? 8D 4D ?? 6A ?? 0F 43 CE 68 ?? ?? ?? ?? E8 
              ?? ?? ?? ?? 83 C4 ?? 85 C0 0F 84 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 4D ?? E8
        }

        $encrypt_files_p2 = {
              84 C0 0F 85 ?? ?? ?? ?? BA ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? 
              ?? BA ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 83 7D ?? ?? 8D 45 
              ?? 6A ?? 0F 43 45 ?? 6A ?? 6A ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 50 FF 15 ?? ?? ?? ?? 8B 
              D8 83 FB ?? 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 99 6A ?? 8B F0 8B FA 8D 45 ?? 50 68 ?? 
              ?? ?? ?? FF 35 ?? ?? ?? ?? 53 FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 99 2B C6 1B D7 01 05 
              ?? ?? ?? ?? 11 15 ?? ?? ?? ?? 83 65 ?? ?? 0F 84 ?? ?? ?? ?? E8 ?? ?? ?? ?? 99 8B FA 
              8B F0 8B 55 ?? E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 99 2B C6 6A ?? 1B D7 01 05 ?? ?? ?? ?? 
              8B 45 ?? 11 15 ?? ?? ?? ?? 01 05 ?? ?? ?? ?? 6A ?? 83 15 ?? ?? ?? ?? ?? 6A ?? 53 FF 
              15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 99 6A ?? 8B F0 8B FA 8D 45 ?? 50 FF 75 ?? FF 35 ?? ?? 
              ?? ?? 53 FF 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 99 2B C6 53 1B D7 01 05 ?? ?? ?? ?? 11 15 
              ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 51 8D 55 ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B C8 83 C4 ?? 83 
              79 ?? ?? 72 ?? 8B 09 83 7D ?? ?? 8D 45 ?? 51 0F 43 45 ?? 50 FF 15 ?? ?? ?? ?? 8D 4D 
              ?? E8 ?? ?? ?? ?? 83 05 ?? ?? ?? ?? ?? 83 15 ?? ?? ?? ?? ?? EB ?? 53 FF 15 ?? ?? ?? 
              ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8D 4D ?? E8 ?? ?? ?? ?? 8B 4D ?? 
              64 89 0D ?? ?? ?? ?? 59 5F 5E 5B 8B 4D ?? 33 CD E8 ?? ?? ?? ?? 8B E5 5D C3 
        }


    condition:
        uint16(0) == 0x5A4D and 
        (
            $enum_volumes and  
            $find_files and 
            (
                all of ($enum_shares_p*)
            ) and
            (
                all of ($encrypt_files_p*)
            )
        )
        
}