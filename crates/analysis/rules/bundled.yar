// ByteBouncer bundled rules.
// Source: written for ByteBouncer. License: MIT OR Apache-2.0 (same as the project).
//
// Every rule carries metadata the analyzer turns into a finding:
//   category   closed category from SPEC §7 (e.g. security.downloader)
//   severity   info | low | medium | high | critical
//   title      one-line finding title
//   legitimate possible legitimate purpose (optional)
// Rules describe capability or content, not intent. Keep them conservative:
// a rule that fires on ordinary software must be info/low.

rule bb_eicar_test_file {
    meta:
        category = "security.signature_match"
        severity = "info"
        title = "EICAR antivirus test file"
        legitimate = "Standard harmless file used to test antivirus software"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule bb_reverse_shell {
    meta:
        category = "security.capability"
        severity = "high"
        title = "Reverse shell command pattern"
        legitimate = "Penetration-testing tools and CTF material"
    strings:
        $bash_tcp = /bash -i\s*>&\s*\/dev\/tcp\/[0-9a-zA-Z.\-]+\/[0-9]+/
        $nc_e = /\bnc(at)?\s+(-[a-z]*e\s+\/bin\/(ba)?sh|[0-9.]+\s+[0-9]+\s+-e\s+\/bin\/(ba)?sh)/
        $py_pty = "pty.spawn(\"/bin/sh\")"
        $mkfifo = /mkfifo\s+\/tmp\/[a-z]+;\s*nc\s/
    condition:
        any of them
}

rule bb_crypto_miner {
    meta:
        category = "security.capability"
        severity = "medium"
        title = "Cryptocurrency mining configuration or stratum pool reference"
        legitimate = "Explicitly installed mining software"
    strings:
        $stratum = /stratum\+(tcp|ssl|tls):\/\/[a-zA-Z0-9.\-]+:[0-9]+/
        $xmrig = "xmrig" nocase
        $donate = "\"donate-level\""
    condition:
        $stratum or ($xmrig and $donate)
}

rule bb_chat_webhook_exfil {
    meta:
        category = "privacy.recipients"
        severity = "medium"
        title = "Discord webhook or Telegram bot API endpoint embedded"
        legitimate = "Notification bots and chat integrations"
    strings:
        $discord = /discord(app)?\.com\/api\/webhooks\/[0-9]{8,}\/[A-Za-z0-9_\-]{20,}/
        $telegram = /api\.telegram\.org\/bot[0-9]{6,}:[A-Za-z0-9_\-]{30,}/
    condition:
        any of them
}

rule bb_browser_credential_stores {
    meta:
        category = "privacy.sensitive_collection"
        severity = "high"
        title = "References several browser credential/cookie stores"
        legitimate = "Browser migration and password-manager import tools"
    strings:
        $chrome_login = "\\Login Data" ascii wide
        $chrome_cookies = "\\Network\\Cookies" ascii wide
        $local_state = "Local State" ascii wide
        $enc_key = "encrypted_key" ascii wide
        $ff_logins = "logins.json" ascii wide
        $ff_key4 = "key4.db" ascii wide
        $linux_chrome = ".config/google-chrome/Default/Login Data" ascii
    condition:
        3 of them
}

rule bb_crypto_wallet_paths {
    meta:
        category = "privacy.sensitive_collection"
        severity = "medium"
        title = "References cryptocurrency wallet files or extensions"
        legitimate = "Wallet software and backup tools"
    strings:
        $wallet_dat = "wallet.dat" ascii wide
        $exodus = "Exodus\\exodus.wallet" ascii wide
        $electrum = "Electrum\\wallets" ascii wide
        $metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii wide
        $phantom = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii wide
    condition:
        2 of them
}

rule bb_defender_tampering {
    meta:
        category = "security.evasion"
        severity = "high"
        title = "Disables or excludes paths from Microsoft Defender"
        legitimate = "Enterprise configuration scripts"
    strings:
        $excl = "Add-MpPreference -ExclusionPath" ascii wide nocase
        $rtm = "Set-MpPreference -DisableRealtimeMonitoring" ascii wide nocase
        $reg = "DisableAntiSpyware" ascii wide
    condition:
        any of them
}

rule bb_shadow_copy_deletion {
    meta:
        category = "security.capability"
        severity = "high"
        title = "Deletes Windows shadow copies or backups"
        legitimate = "Backup administration tools"
    strings:
        $vss = /vssadmin(\.exe)?\s+delete\s+shadows/ ascii wide nocase
        $wmic = /wmic(\.exe)?\s+shadowcopy\s+delete/ ascii wide nocase
        $bcd = /bcdedit(\.exe)?\s+\/set\s+\{default\}\s+recoveryenabled\s+no/ ascii wide nocase
    condition:
        any of them
}

rule bb_ld_preload_persistence {
    meta:
        category = "security.persistence"
        severity = "high"
        title = "Writes or references /etc/ld.so.preload"
        legitimate = "System instrumentation tools"
    strings:
        $preload = "/etc/ld.so.preload"
    condition:
        $preload
}

rule bb_anti_vm_checks {
    meta:
        category = "security.evasion"
        severity = "low"
        title = "Checks for virtual-machine or sandbox artifacts"
        legitimate = "Licensing and anti-cheat code; VM guest tools"
    strings:
        $vbox1 = "VBoxService.exe" ascii wide nocase
        $vbox2 = "VBoxTray.exe" ascii wide nocase
        $vmware = "vmtoolsd.exe" ascii wide nocase
        $sbie = "SbieDll.dll" ascii wide nocase
        $wine = "wine_get_unix_file_name" ascii
    condition:
        2 of them
}

rule bb_paste_site_payload {
    meta:
        category = "security.downloader"
        severity = "low"
        title = "References raw paste or tunnel services"
        legitimate = "Developer tools and documentation"
    strings:
        $pastebin = /pastebin\.com\/raw\/[A-Za-z0-9]{6,}/ ascii wide
        $ngrok = /[a-z0-9\-]+\.ngrok(-free)?\.(io|app)/ ascii wide
        $transfer = /transfer\.sh\/[A-Za-z0-9]+/ ascii wide
    condition:
        any of them
}
