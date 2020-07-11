rule Win32_Ransomware_Ransoc : tc_detection malicious
{
    meta:

        author              = "ReversingLabs"

        source              = "ReversingLabs"
        status              = "RELEASED"
        sharing             = "TLP:WHITE"
        category            = "MALWARE"
        description         = "Yara rule that detects Ransoc ransomware."
		malware				= "Ransoc"
		malware_type		= "Ransomware"
        tc_detection_type   = "Ransomware"
        tc_detection_name   = "Ransoc"
        tc_detection_factor = 5

    strings:

      $scan_for_services = {
            E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? B8 ?? ?? ?? ?? 66 A3 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            66 39 2D ?? ?? ?? ?? 73 ?? 66 01 1D ?? ?? ?? ?? 03 F3 E8 ?? ?? ?? ?? 6A ?? 6A ?? 68 
            ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? B9 ?? ?? ?? ?? 66 89 
            0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 39 2D ?? ?? ?? ?? 73 ?? 66 01 1D ?? ?? ?? ?? 03 F3 
            E8 ?? ?? ?? ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 
            C0 75 ?? BA ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 39 2D ?? ?? ?? ?? 73 
            ?? 66 01 1D ?? ?? ?? ?? 03 F3 E8 ?? ?? ?? ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? 
            ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? B8 ?? ?? ?? ?? 66 A3 ?? ?? ?? ?? E8 ?? ?? ?? 
            ?? 66 39 2D ?? ?? ?? ?? 73 ?? 66 01 1D ?? ?? ?? ?? 03 F3 E8 ?? ?? ?? ?? 6A ?? 6A ?? 
            68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? B9 ?? ?? ?? ?? 66 
            89 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 39 2D ?? ?? ?? ?? 73 ?? 66 01 1D ?? ?? ?? ?? 03 
            F3 E8 ?? ?? ?? ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 
            85 C0 75 ?? BA ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 FF 66 39 2D ?? ?? 
            ?? ?? 73 ?? A1 ?? ?? ?? ?? 50 8D 4C 24 ?? 51 E8 ?? ?? ?? ?? 66 01 1D ?? ?? ?? ?? 8B 
            FB 03 F3 E8 ?? ?? ?? ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 
            C4 ?? 85 C0 75 ?? BA ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 66 39 2D ?? ?? 
            ?? ?? 73 ?? 85 FF 75 ?? A1 ?? ?? ?? ?? 50 8D 4C 24 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 66 
            01 1D ?? ?? ?? ?? 03 F3 E8 ?? ?? ?? ?? 6A ?? 6A ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 
            ?? ?? ?? ?? 83 C4 ?? 85 C0 75 ?? BA ?? ?? ?? ?? 66 89 15 ?? ?? ?? ?? E8 ?? ?? ?? ?? 
            EB ?? 85 FF 74 ?? 8D 44 24 ?? 50 E8
      }

      $remote_connection = {
            8B 44 24 ?? 83 EC ?? 53 8B 5C 24 ?? 56 8B 74 24 ?? 50 56 E8 ?? ?? ?? ?? 8B D8 83 C4 
            ?? 83 FB ?? 75 ?? 5E B8 ?? ?? ?? ?? 5B 83 C4 ?? C3 8B 4C 24 ?? 55 8B 6C 24 ?? 57 55 
            56 51 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 83 C4 ?? 8B F0 56 FF 15 ?? ?? ?? ?? 50 56 53 E8 
            ?? ?? ?? ?? 56 8B F8 E8 ?? ?? ?? ?? 83 C4 ?? 83 FF ?? 75 ?? 53 FF 15 ?? ?? ?? ?? 8D 
            47 ?? 5F 5D 5E 5B 83 C4 ?? C3 8B 44 24 ?? 85 C0 74 ?? 85 ED 74 ?? 55 50 53 E8 ?? ?? 
            ?? ?? 83 C4 ?? 83 F8 ?? 75 ?? 53 FF 15 ?? ?? ?? ?? 5F 5D 5E B8 ?? ?? ?? ?? 5B 83 C4 
            ?? C3 8D 54 24 ?? 52 E8 ?? ?? ?? ?? 8B 2D ?? ?? ?? ?? 83 C4 ?? 8D 49 ?? 8B 74 24 ?? 
            8B C6 2B 44 24 ?? 75 ?? 8D 4C 24 ?? 6A ?? 51 E8 ?? ?? ?? ?? 8B 74 24 ?? 83 C4 ?? 2B 
            74 24 ?? 6A ?? 56 8D 54 24 ?? 56 52 E8 ?? ?? ?? ?? 83 C4 ?? 50 53 FF D5 8B F8 85 FF 
            78 ?? 2B C6 01 44 24 ?? EB ?? 29 74 24 ?? 83 FF ?? 74 ?? 85 FF 75 ?? 53 FF 15 ?? ?? 
            ?? ?? 85 FF 79 ?? 8D 4C 24 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 5F 5D 5E B8 ?? ?? ?? ?? 5B 
            83 C4 ?? C3 8D 54 24 ?? 6A ?? 52 E8 ?? ?? ?? ?? 8B 44 24 ?? 83 C4 ?? 68 ?? ?? ?? ?? 
            50 FF 15 ?? ?? ?? ?? 8B F0 85 F6 75 ?? 8D 4C 24 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 5F 5D 
            8D 46 ?? 5E 5B 83 C4 ?? C3 8B 54 24 ?? 83 C2 ?? 6A ?? 52 E8 ?? ?? ?? ?? 8B 4C 24 ?? 
            8B 54 24 ?? 8B F8 8B 44 24 ?? 2B F0 83 C6 ?? 2B CE 51 03 F0 56 52 E8 ?? ?? ?? ?? 8D 
            44 24 ?? 50 E8 
      }

      $encrypt_files = {
            81 EC ?? ?? ?? ?? 53 55 56 8B 35 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? FF D6 68 ?? ?? ?? ?? 
            8B F8 FF D6 8B 8C 24 ?? ?? ?? ?? 8B E8 8B 84 24 ?? ?? ?? ?? 50 51 57 8D 94 24 ?? ?? 
            ?? ?? 68 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 6A ?? 50 
            E8 ?? ?? ?? ?? 8B BC 24 ?? ?? ?? ?? 8B 8C 24 ?? ?? ?? ?? 83 C4 ?? 89 4C 24 ?? BB ?? 
            ?? ?? ?? 85 FF 0F 84 ?? ?? ?? ?? EB ?? 8D 49 ?? 55 68 ?? ?? ?? ?? 83 FB ?? 7E ?? 8D 
            94 24 ?? ?? ?? ?? B9 ?? ?? ?? ?? 8D 74 24 ?? 8D BC 24 ?? ?? ?? ?? 52 F3 A5 E8 ?? ?? 
            ?? ?? 8B BC 24 ?? ?? ?? ?? 88 9C 2C ?? ?? ?? ?? 8D 75 ?? EB ?? 8D 84 24 ?? ?? ?? ?? 
            50 E8 ?? ?? ?? ?? 88 9C 2C ?? ?? ?? ?? 8D 75 ?? 83 C4 ?? 6A ?? 8D 4C 24 ?? 6A ?? 51 
            E8 ?? ?? ?? ?? 6A ?? 8D 94 24 ?? ?? ?? ?? 52 8D 44 24 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 
            8D 44 24 ?? B9 ?? ?? ?? ?? 80 30 ?? 40 49 75 ?? 8D 4C 24 ?? 51 E8 ?? ?? ?? ?? 6A ?? 
            8D 54 24 ?? 52 8D 84 24 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 56 8D 8C 24 ?? ?? ?? ?? 51 8D 
            94 24 ?? ?? ?? ?? 52 E8 ?? ?? ?? ?? 8D 84 24 ?? ?? ?? ?? 50 8D 4C 24 ?? 51 E8 ?? ?? 
            ?? ?? 83 C4 ?? 8D 44 24 ?? B9 ?? ?? ?? ?? 8B FF 80 30 ?? 40 49 75 ?? 8D 54 24 ?? 52 
            E8 ?? ?? ?? ?? 6A ?? 8D 44 24 ?? 50 8D 8C 24 ?? ?? ?? ?? 51 E8 ?? ?? ?? ?? 6A ?? 8D 
            54 24 ?? 52 8D 84 24 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 8D 8C 24 ?? ?? ?? ?? 51 8D 54 24 
            ?? 52 E8 ?? ?? ?? ?? 83 C4 ?? 8B F7 83 FF ?? 72 ?? BE ?? ?? ?? ?? 8B 4C 24 ?? 56 8D 
            44 24 ?? 50 51 E8 ?? ?? ?? ?? 01 74 24 ?? 2B FE 83 C4 ?? 43 89 BC 24 ?? ?? ?? ?? 85 
            FF 0F 85 ?? ?? ?? ?? 5F 5E 5D 5B 81 C4 ?? ?? ?? ?? C3 
      }

      $find_files = {
            83 EC ?? 53 55 56 57 33 DB 68 ?? ?? ?? ?? 6A ?? 89 5C 24 ?? 89 5C 24 ?? E8 ?? ?? ?? 
            ?? 8B E8 8D 44 24 ?? 50 89 6C 24 ?? E8 ?? ?? ?? ?? 8D 4C 24 ?? 55 51 E8 ?? ?? ?? ?? 
            8B 74 24 ?? 6A ?? 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 55 68 ?? ?? ?? 
            ?? 89 5C 24 ?? 89 5C 24 ?? E8 ?? ?? ?? ?? 8B F8 57 8D 54 24 ?? 52 8D 44 24 ?? 50 E8 
            ?? ?? ?? ?? 83 C4 ?? 89 44 24 ?? 3B C3 75 ?? 8B 4C 24 ?? 51 8D 54 24 ?? 52 E8 ?? ?? 
            ?? ?? 83 C4 ?? 57 E8 ?? ?? ?? ?? 6A ?? 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? 
            ?? ?? 8B 44 24 ?? 50 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B 4C 24 ?? 
            51 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B 54 24 ?? 52 56 E8 ?? ?? ?? 
            ?? 83 C4 ?? 33 FF 39 5C 24 ?? 76 ?? 8D 64 24 ?? 8B 44 24 ?? 8B 0C B8 51 56 E8 ?? ?? 
            ?? ?? 47 83 C4 ?? 3B 7C 24 ?? 72 ?? 39 5C 24 ?? 75 ?? 8B 44 24 ?? 3B C3 74 ?? 50 E8 
            ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 8B 54 24 ?? 52 56 E8 ?? ?? ?? 
            ?? 8B 44 24 ?? 83 C4 ?? 89 5C 24 ?? 3B C3 0F 86 ?? ?? ?? ?? EB ?? 8D 9B ?? ?? ?? ?? 
            8B 44 24 ?? 8B 4C 24 ?? 8B 1C 88 53 55 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 8B F8 57 68 ?? 
            ?? ?? ?? E8 ?? ?? ?? ?? 57 68 ?? ?? ?? ?? 8B E8 E8 ?? ?? ?? ?? 6A ?? 56 89 44 24 ?? 
            E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? ?? 53 56 E8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 
            56 E8 ?? ?? ?? ?? 33 C0 8D 54 24 ?? 55 52 C7 44 24 ?? ?? ?? ?? ?? 89 44 24 ?? 89 84 
            24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 89 84 
            24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? 89 84 24 ?? ?? ?? ?? E8 ?? 
            ?? ?? ?? 83 C4 ?? 85 C0 74 ?? 50 56 E8 ?? ?? ?? ?? 83 C4 ?? EB ?? 8D 44 24 ?? 50 56 
            E8 ?? ?? ?? ?? 8D 4C 24 ?? 51 E8 ?? ?? ?? ?? 83 C4 ?? 68 ?? ?? ?? ?? 56 E8 ?? ?? ?? 
            ?? 8B 5C 24 ?? E8 ?? ?? ?? ?? 57 E8 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 8B D3 52 E8 ?? ?? 
            ?? ?? 8B 4C 24 ?? 8B 44 24 ?? 8B 6C 24 ?? 41 83 C4 ?? 89 4C 24 ?? 3B C8 0F 82 ?? ?? 
            ?? ?? 33 DB 33 F6 3B C3 76 ?? 8B 44 24 ?? 8B 0C B0 51 E8 ?? ?? ?? ?? 46 83 C4 ?? 3B 
            74 24 ?? 72 ?? 8D 54 24 ?? 52 E8 ?? ?? ?? ?? 55 E8 ?? ?? ?? ?? 8B 44 24 ?? 83 C4 ?? 
            3B C3 74 ?? 50 E8 ?? ?? ?? ?? 83 C4 ?? 8B 44 24 ?? 5F 5E 5D 3B C3 5B 74 ?? 50 E8 ?? 
            ?? ?? ?? 83 C4 ?? 83 C4 ?? C3 
      }

    condition:
        uint16(0) == 0x5A4D and $scan_for_services and $find_files and $encrypt_files and $remote_connection
}