//! MSIX/APPX packages and bundles: a zip plus `AppxManifest.xml` (or
//! `AppxMetadata/AppxBundleManifest.xml`). The manifest's identity,
//! capabilities (restricted ones such as `runFullTrust` and
//! `broadFileSystemAccess` reported separately) and extension categories
//! (startup tasks, services, full-trust processes, protocol handlers) become
//! metadata. Inner packages of a bundle are ordinary children for recursion.

use crate::util::Sink;
use crate::{ContainerKind, Expanded, FormatError, Limits};

const RESCAP_NS: &str =
    "http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities";

pub(crate) fn expand(bytes: &[u8], limits: &Limits) -> Result<Expanded, FormatError> {
    let mut sink = Sink::new(ContainerKind::Msix, limits, bytes.len());
    crate::zip::read_into(bytes, &mut sink, "")
        .map_err(|e| FormatError::malformed(ContainerKind::Msix, e))?;
    let manifest = ["AppxManifest.xml", "AppxMetadata/AppxBundleManifest.xml"]
        .iter()
        .find_map(|p| {
            sink.out
                .child(p)
                .map(|c| String::from_utf8_lossy(&c.data).into_owned())
        });
    match manifest {
        Some(xml) => manifest_metadata(&xml, &mut sink),
        None => sink.problem("msix: no AppxManifest.xml or AppxBundleManifest.xml found"),
    }
    if sink.out.child("AppxSignature.p7x").is_some() {
        sink.meta("msix.signature", "AppxSignature.p7x present (not verified)");
    } else {
        sink.meta("msix.signature", "none");
    }
    Ok(sink.finish())
}

fn manifest_metadata(xml: &str, sink: &mut Sink) {
    let doc = match crate::util::xml(xml) {
        Ok(d) => d,
        Err(e) => return sink.problem(format!("msix: manifest XML is malformed: {e}")),
    };
    for node in doc.descendants().filter(|n| n.is_element()) {
        let attr = |a: &str| node.attribute(a).unwrap_or_default().to_owned();
        match node.tag_name().name() {
            "Identity" => {
                for a in ["Name", "Publisher", "Version", "ProcessorArchitecture"] {
                    if let Some(v) = node.attribute(a) {
                        sink.meta(format!("msix.identity.{a}"), v);
                    }
                }
            }
            n @ ("DisplayName" | "PublisherDisplayName" | "Description")
                if node
                    .parent()
                    .is_some_and(|p| p.tag_name().name() == "Properties") =>
            {
                sink.meta(format!("msix.{n}"), node.text().unwrap_or_default().trim());
            }
            "Capability" if node.tag_name().namespace() == Some(RESCAP_NS) => {
                sink.meta("msix.restricted_capability", attr("Name"))
            }
            "Capability" | "CustomCapability" => sink.meta("msix.capability", attr("Name")),
            "DeviceCapability" => sink.meta("msix.device_capability", attr("Name")),
            "Application" => sink.meta(
                "msix.application",
                format!(
                    "{} exe={} entry={}",
                    attr("Id"),
                    attr("Executable"),
                    attr("EntryPoint")
                ),
            ),
            "Extension" if node.has_attribute("Category") => {
                let target = node
                    .attribute("Executable")
                    .map(|e| format!(" exe={e}"))
                    .unwrap_or_default();
                sink.meta("msix.extension", format!("{}{target}", attr("Category")));
            }
            "PackageDependency" => sink.meta(
                "msix.dependency",
                format!("{} >= {}", attr("Name"), attr("MinVersion")),
            ),
            "Package" if node.has_attribute("FileName") => {
                sink.meta("msix.bundle.package", attr("FileName"))
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10"
  xmlns:rescap="http://schemas.microsoft.com/appx/manifest/foundation/windows10/restrictedcapabilities"
  xmlns:desktop="http://schemas.microsoft.com/appx/manifest/desktop/windows10">
  <Identity Name="Contoso.App" Publisher="CN=Contoso" Version="1.2.3.0" ProcessorArchitecture="x64"/>
  <Properties><DisplayName>Contoso App</DisplayName><PublisherDisplayName>Contoso</PublisherDisplayName></Properties>
  <Applications><Application Id="App" Executable="app.exe" EntryPoint="Windows.FullTrustApplication">
    <Extensions><desktop:Extension Category="windows.startupTask" Executable="app.exe"/></Extensions>
  </Application></Applications>
  <Capabilities>
    <Capability Name="internetClient"/>
    <rescap:Capability Name="runFullTrust"/>
    <rescap:Capability Name="broadFileSystemAccess"/>
    <DeviceCapability Name="webcam"/>
  </Capabilities>
</Package>"#;

    #[test]
    fn manifest_to_metadata() {
        let bytes = crate::zip::tests::build(&[
            ("AppxManifest.xml", MANIFEST.as_bytes(), true),
            ("app.exe", b"MZ", false),
        ]);
        assert_eq!(crate::detect(&bytes, "x.zip"), Some(ContainerKind::Msix));
        let out = expand(&bytes, &Limits::default()).unwrap();
        assert_eq!(out.meta("msix.identity.Name"), Some("Contoso.App"));
        assert_eq!(out.meta("msix.DisplayName"), Some("Contoso App"));
        let rescap: Vec<_> = out
            .metadata
            .iter()
            .filter(|(k, _)| k == "msix.restricted_capability")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(rescap, ["runFullTrust", "broadFileSystemAccess"]);
        assert_eq!(out.meta("msix.capability"), Some("internetClient"));
        assert_eq!(out.meta("msix.device_capability"), Some("webcam"));
        assert_eq!(
            out.meta("msix.extension"),
            Some("windows.startupTask exe=app.exe")
        );
        assert_eq!(out.meta("msix.signature"), Some("none"));
    }

    #[test]
    fn bad_manifests_are_problems() {
        let bytes = crate::zip::tests::build(&[("AppxManifest.xml", b"<Package><unclosed", false)]);
        let out = expand(&bytes, &Limits::default()).unwrap();
        assert!(out.problems.iter().any(|p| p.contains("malformed")));
        let bomb = r#"<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;"><!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;"><!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;"><!ENTITY g "&f;&f;&f;&f;&f;&f;&f;&f;&f;&f;"><!ENTITY h "&g;&g;&g;&g;&g;&g;&g;&g;&g;&g;">]><Package><Properties><DisplayName>&h;</DisplayName></Properties></Package>"#;
        let bytes = crate::zip::tests::build(&[("AppxManifest.xml", bomb.as_bytes(), false)]);
        let _ = expand(&bytes, &Limits::default()).unwrap();
        assert!(expand(b"PK\x03\x04junk", &Limits::default()).is_err());
    }
}
