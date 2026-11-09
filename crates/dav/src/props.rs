//! Nextcloud live properties and permissions.
//!
//! dav-server answers the DAV: properties itself and asks the file system for everything in
//! other namespaces (`GuardedFileSystem::get_prop`). Properties in the ownCloud and Nextcloud
//! namespaces listed in [`live_prop`] are computed from the [`Entry`]; any other name is looked
//! up as a dead property.

use dav_server::fs::DavProp;

use crate::metadata::{Entry, Kind};

/// The ownCloud namespace (`oc:`).
pub const NS_OC: &str = "http://owncloud.org/ns";
/// The Nextcloud namespace (`nc:`).
pub const NS_NC: &str = "http://nextcloud.org/ns";

/// Permission letters as Nextcloud defines them. Sharing does not exist in v1, so `S` and `R`
/// are never reported.
///
/// - `G` readable, `M` mount point,
/// - `D` deletable, `N` renamable, `V` movable,
/// - `W` writable (files), `C` and `K` may create files and folders inside (folders).
pub fn permissions(kind: Kind, writable: bool, mount_root: bool, is_virtual: bool) -> &'static str {
    match (is_virtual, kind, writable, mount_root) {
        (true, ..) => "G",
        (false, Kind::File, true, _) => "GDNVW",
        (false, Kind::File, false, _) => "G",
        (false, Kind::Dir, true, false) => "GDNVCK",
        (false, Kind::Dir, true, true) => "GMCK",
        (false, Kind::Dir, false, false) => "G",
        (false, Kind::Dir, false, true) => "GM",
    }
}

/// Live property names in the ownCloud namespace.
const OC_LIVE: &[&str] = &["fileid", "id", "permissions", "favorite", "size"];
/// Live property names in the Nextcloud namespace.
const NC_LIVE: &[&str] = &["has-preview"];

/// Whether `prop` is one of the live properties computed here.
pub fn is_live(prop: &DavProp) -> bool {
    match prop.namespace.as_deref() {
        Some(NS_OC) => OC_LIVE.contains(&prop.name.as_str()),
        Some(NS_NC) => NC_LIVE.contains(&prop.name.as_str()),
        _ => false,
    }
}

/// Whether PROPPATCH may change `prop` (only `oc:favorite` among the live properties).
pub fn is_settable_live(prop: &DavProp) -> bool {
    prop.namespace.as_deref() == Some(NS_OC) && prop.name == "favorite"
}

/// `oc:id`: the file id zero-padded to eight digits, followed by the instance id.
pub fn oc_id(file_id: i64, instance_id: &str) -> String {
    format!("{file_id:08}{instance_id}")
}

/// The serialized element of a live property, or `None` if the entry does not have it.
pub fn live_prop(prop: &DavProp, entry: &Entry, instance_id: &str) -> Option<Vec<u8>> {
    let (prefix, namespace) = match prop.namespace.as_deref() {
        Some(NS_OC) => ("oc", NS_OC),
        Some(NS_NC) => ("nc", NS_NC),
        _ => return None,
    };
    let value = match (namespace, prop.name.as_str()) {
        (NS_OC, "fileid") => entry.file_id?.to_string(),
        (NS_OC, "id") => oc_id(entry.file_id?, instance_id),
        (NS_OC, "permissions") => entry.permissions.to_owned(),
        (NS_OC, "favorite") => u8::from(entry.favorite).to_string(),
        (NS_OC, "size") => entry.size.to_string(),
        (NS_NC, "has-preview") => "false".to_owned(),
        _ => return None,
    };
    let name = &prop.name;
    Some(
        format!("<{prefix}:{name} xmlns:{prefix}=\"{namespace}\">{value}</{prefix}:{name}>")
            .into_bytes(),
    )
}

/// Parses the value of a PROPPATCH `oc:favorite` element: `1`/`true` sets, `0`/`false` or an
/// empty element clears.
pub fn parse_favorite(prop: &DavProp) -> Option<bool> {
    let text = match &prop.xml {
        Some(xml) => xmltree::Element::parse(xml.as_slice())
            .ok()?
            .get_text()
            .map(|text| text.trim().to_owned())
            .unwrap_or_default(),
        None => String::new(),
    };
    match text.as_str() {
        "1" | "true" => Some(true),
        "" | "0" | "false" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::time::UNIX_EPOCH;

    use gono_core::RelPath;

    use super::*;
    use crate::resolve::Location;

    fn prop(namespace: &str, name: &str, xml: Option<&str>) -> DavProp {
        DavProp {
            name: name.into(),
            prefix: None,
            namespace: Some(namespace.into()),
            xml: xml.map(|xml| xml.as_bytes().to_vec()),
        }
    }

    fn entry(file_id: Option<i64>) -> Entry {
        Entry {
            location: Location::Virtual {
                client: RelPath::root(),
            },
            kind: Kind::File,
            file_id,
            etag: "abc".into(),
            modified: UNIX_EPOCH,
            size: 12,
            favorite: true,
            permissions: "GDNVW",
        }
    }

    #[test]
    fn read_only_permissions_never_offer_writes() {
        for kind in [Kind::File, Kind::Dir] {
            for mount_root in [false, true] {
                let letters = permissions(kind, false, mount_root, false);
                assert!(
                    !letters.contains(['W', 'C', 'K', 'D', 'N', 'V']),
                    "{kind:?} {mount_root}: {letters}"
                );
            }
        }
        assert_eq!(permissions(Kind::File, true, false, false), "GDNVW");
        assert_eq!(permissions(Kind::Dir, true, false, false), "GDNVCK");
        assert!(!permissions(Kind::Dir, true, true, false).contains(['D', 'N', 'V']));
        assert_eq!(permissions(Kind::Dir, true, false, true), "G");
    }

    #[test]
    fn live_props_render_as_elements() {
        let entry_fn = entry;
        let entry = entry_fn(Some(42));
        let render = |namespace, name| {
            live_prop(&prop(namespace, name, None), &entry, "ocabcdef0123")
                .map(|xml| String::from_utf8(xml).unwrap())
        };
        assert_eq!(
            render(NS_OC, "fileid").unwrap(),
            "<oc:fileid xmlns:oc=\"http://owncloud.org/ns\">42</oc:fileid>"
        );
        assert!(
            render(NS_OC, "id")
                .unwrap()
                .contains(">00000042ocabcdef0123<")
        );
        assert!(render(NS_OC, "favorite").unwrap().contains(">1<"));
        assert!(render(NS_OC, "size").unwrap().contains(">12<"));
        assert!(render(NS_NC, "has-preview").unwrap().contains(">false<"));
        assert_eq!(render(NS_OC, "unknown"), None);
        assert_eq!(render("urn:other", "fileid"), None);

        let virtual_entry = entry_fn(None);
        assert_eq!(
            live_prop(&prop(NS_OC, "fileid", None), &virtual_entry, "oc0"),
            None
        );
        assert!(is_live(&prop(NS_OC, "permissions", None)));
        assert!(!is_live(&prop("urn:x", "permissions", None)));
    }

    #[test]
    fn favorite_values_parse() {
        let set = |value: &str| {
            parse_favorite(&prop(
                NS_OC,
                "favorite",
                Some(&format!(
                    "<?xml version=\"1.0\" encoding=\"utf-8\"?><oc:favorite xmlns:oc=\"{NS_OC}\">{value}</oc:favorite>"
                )),
            ))
        };
        assert_eq!(set("1"), Some(true));
        assert_eq!(set(" 0 "), Some(false));
        assert_eq!(set(""), Some(false));
        assert_eq!(set("maybe"), None);
        assert_eq!(parse_favorite(&prop(NS_OC, "favorite", None)), Some(false));
    }
}
