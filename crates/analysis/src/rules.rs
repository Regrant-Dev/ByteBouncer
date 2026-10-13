//! Built-in Phase 0 rule tables. YARA-X rule bundles replace and extend these
//! in Phase 0's next step; these exist so the evidence pipeline is exercised.

use bytebouncer_core::Severity;

pub struct ImportRule {
    pub id: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub severity: Severity,
    pub imports: &'static [&'static str],
    pub require_all: bool,
    pub legitimate: &'static str,
}

pub const IMPORT_RULES: &[ImportRule] = &[
    ImportRule {
        id: "win-remote-thread-injection",
        category: "security.capability",
        title: "Imports APIs used for remote process injection",
        severity: Severity::Medium,
        imports: &["WriteProcessMemory", "CreateRemoteThread"],
        require_all: true,
        legitimate: "Debuggers, accessibility tools, and game overlays use these APIs",
    },
    ImportRule {
        id: "win-keyboard-hook",
        category: "privacy.sensitive_collection",
        title: "Imports APIs that can observe keyboard input globally",
        severity: Severity::Medium,
        imports: &["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState"],
        require_all: false,
        legitimate: "Hotkey handlers, games, and accessibility tools use these APIs",
    },
    ImportRule {
        id: "win-dpapi-unprotect",
        category: "privacy.sensitive_collection",
        title: "Imports DPAPI decryption (used for stored credentials and browser secrets)",
        severity: Severity::Medium,
        imports: &["CryptUnprotectData"],
        require_all: false,
        legitimate: "Applications decrypting their own stored secrets use DPAPI",
    },
    ImportRule {
        id: "win-clipboard-read",
        category: "privacy.sensitive_collection",
        title: "Imports clipboard read API",
        severity: Severity::Low,
        imports: &["GetClipboardData"],
        require_all: false,
        legitimate: "Any application supporting paste reads the clipboard",
    },
    ImportRule {
        id: "elf-ptrace",
        category: "security.capability",
        title: "Imports ptrace (process inspection/manipulation)",
        severity: Severity::Low,
        imports: &["ptrace"],
        require_all: false,
        legitimate: "Debuggers, crash handlers, and anti-debug checks use ptrace",
    },
];

pub const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".themida", "Themida"),
    (".enigma1", "Enigma Protector"),
    (".aspack", "ASPack"),
];

pub struct TelemetryDomain {
    pub domain: &'static str,
    pub provider: &'static str,
    pub category: &'static str,
    pub legitimate: &'static str,
}

const ANALYTICS: &str = "Product analytics and usage measurement";
const CRASH: &str = "Crash and error reporting";

pub const TELEMETRY_DOMAINS: &[TelemetryDomain] = &[
    TelemetryDomain {
        domain: "google-analytics.com",
        provider: "Google Analytics",
        category: "privacy.telemetry",
        legitimate: ANALYTICS,
    },
    TelemetryDomain {
        domain: "analytics.google.com",
        provider: "Google Analytics",
        category: "privacy.telemetry",
        legitimate: ANALYTICS,
    },
    TelemetryDomain {
        domain: "app-measurement.com",
        provider: "Firebase Analytics",
        category: "privacy.telemetry",
        legitimate: ANALYTICS,
    },
    TelemetryDomain {
        domain: "api.segment.io",
        provider: "Segment",
        category: "privacy.telemetry",
        legitimate: ANALYTICS,
    },
    TelemetryDomain {
        domain: "api.mixpanel.com",
        provider: "Mixpanel",
        category: "privacy.telemetry",
        legitimate: ANALYTICS,
    },
    TelemetryDomain {
        domain: "api.amplitude.com",
        provider: "Amplitude",
        category: "privacy.telemetry",
        legitimate: ANALYTICS,
    },
    TelemetryDomain {
        domain: "posthog.com",
        provider: "PostHog",
        category: "privacy.telemetry",
        legitimate: ANALYTICS,
    },
    TelemetryDomain {
        domain: "in.appcenter.ms",
        provider: "App Center",
        category: "privacy.telemetry",
        legitimate: ANALYTICS,
    },
    TelemetryDomain {
        domain: "sentry.io",
        provider: "Sentry",
        category: "privacy.crash_reporting",
        legitimate: CRASH,
    },
    TelemetryDomain {
        domain: "bugsnag.com",
        provider: "Bugsnag",
        category: "privacy.crash_reporting",
        legitimate: CRASH,
    },
    TelemetryDomain {
        domain: "crashlytics.com",
        provider: "Crashlytics",
        category: "privacy.crash_reporting",
        legitimate: CRASH,
    },
];
