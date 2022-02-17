//! Contains al the basic LDAP types
use oid::ObjectIdentifier;

use is_macro::Is;

use enum_as_inner::EnumAsInner;

#[cfg(feature = "chumsky")]
use chumsky::{prelude::*, text::digits};

#[cfg(feature = "chumsky")]
use itertools::Itertools;

/// represents the object to request from an LDAP server to figure out which
/// features,... it supports
///
/// <https://ldapwiki.com/wiki/RootDSE>
///
/// <https://ldapwiki.com/wiki/LDAP%20Extensions%20and%20Controls%20Listing>
pub struct RootDSE {
    /// version of the LDAP protocol the server supports
    pub supported_ldap_version: String,
    /// LDAP controls the server supports
    ///
    /// <https://ldapwiki.com/wiki/SupportedControl>
    pub supported_controls: Vec<ObjectIdentifier>,
    /// LDAP extensions the server supports
    ///
    /// <https://ldapwiki.com/wiki/SupportedExtension>
    pub supported_extensions: Vec<ObjectIdentifier>,
    /// LDAP features the server supports
    ///
    /// <https://ldapwiki.com/wiki/SupportedFeatures>
    pub supported_features: Vec<ObjectIdentifier>,
    /// SASL mechanisms the server supports for authentication
    ///
    /// <https://ldapwiki.com/wiki/SupportedSASLMechanisms>
    pub supported_sasl_mechanisms: Vec<String>,
    /// the DN of the config context on this server
    ///
    /// this is where the LDAP server configuration lives
    pub config_context: String,
    /// the DNs of naming contexts on this server
    ///
    /// each of these is essentially the root of a tree where the actual data
    /// on the server lives
    ///
    /// <https://ldapwiki.com/wiki/NamingContext>
    pub naming_contexts: Vec<String>,
    /// the DN of the subschema subentry
    ///
    /// this is essentially where the LDAP schema elements this server supports
    /// can be retrieved
    ///
    /// <https://ldapwiki.com/wiki/SubschemaSubentry>
    pub subschema_subentry: String,
}

impl std::fmt::Debug for RootDSE {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.debug_struct("RootDSE")
            .field("supported_ldap_version", &self.supported_ldap_version)
            .field(
                "supported_controls",
                &self
                    .supported_controls
                    .iter()
                    .map(|x| x.into())
                    .collect::<Vec<String>>(),
            )
            .field(
                "supported_extensions",
                &self
                    .supported_extensions
                    .iter()
                    .map(|x| x.into())
                    .collect::<Vec<String>>(),
            )
            .field(
                "supported_features",
                &self
                    .supported_features
                    .iter()
                    .map(|x| x.into())
                    .collect::<Vec<String>>(),
            )
            .field("supported_sasl_mechanisms", &self.supported_sasl_mechanisms)
            .field("config_context", &self.config_context)
            .field("naming_contexts", &self.naming_contexts)
            .field("subschema_subentry", &self.subschema_subentry)
            .finish()
    }
}

/// chumsky parser for [oid::ObjectIdentifier]
#[cfg(feature = "chumsky")]
pub fn oid_parser() -> impl Parser<char, ObjectIdentifier, Error = Simple<char>> {
    digits(10).separated_by(just('.')).try_map(|x, span| {
        x.into_iter()
            .join(".")
            .try_into()
            .map_err(|e| Simple::custom(span, format!("{:?}", e)))
    })
}

/// a key string is a string limited to the characters that are safe to use
/// in a key context, e.g. a relative distinguished name, without encoding
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug, Hash)]
pub struct KeyString(pub String);

impl std::fmt::Display for KeyString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        std::fmt::Display::fmt(&self.0, f)?;
        Ok(())
    }
}

impl KeyString {
    /// this is a quick and dirty helper method to determine if this KeyString
    /// describes one of the standard case insensitive matches
    ///
    /// not perfect but it is useful when trying to figure out how string LDAP
    /// attributes need to be compared
    pub fn describes_case_insensitive_match(&self) -> bool {
        match self {
            KeyString(s) if s == "objectIdentifierMatch" => true,
            KeyString(s) if s == "caseIgnoreMatch" => true,
            KeyString(s) if s == "caseIgnoreListMatch" => true,
            KeyString(s) if s == "caseIgnoreIA5Match" => true,
            KeyString(s) if s == "caseIgnoreListSubstringsMatch" => true,
            KeyString(s) if s == "caseIgnoreSubstringsMatch" => true,
            KeyString(s) if s == "caseIgnoreOrderingMatch" => true,
            KeyString(s) if s == "caseIgnoreIA5SubstringsMatch" => true,
            _ => false,
        }
    }
}

/// parses a [KeyString]
#[cfg(feature = "chumsky")]
pub fn keystring_parser() -> impl Parser<char, KeyString, Error = Simple<char>> {
    filter(|c: &char| c.is_ascii_alphabetic())
        .chain(filter(|c: &char| c.is_ascii_alphanumeric() || *c == '-' || *c == ';').repeated())
        .collect::<String>()
        .map(KeyString)
}

/// parses a [KeyString] in locations where it is single-quoted
#[cfg(feature = "chumsky")]
pub fn quoted_keystring_parser() -> impl Parser<char, KeyString, Error = Simple<char>> {
    keystring_parser().delimited_by('\'', '\'')
}

/// LDAP allows the use of either a keystring or an OID in many locations,
/// e.g. in DNs or in the schema
#[derive(PartialEq, Eq, Clone, Debug, Is, EnumAsInner)]
pub enum KeyStringOrOID {
    /// this represents a [KeyString]
    KeyString(KeyString),
    /// this reprents an [ObjectIdentifier]
    OID(ObjectIdentifier),
}

impl PartialOrd for KeyStringOrOID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (KeyStringOrOID::KeyString(s1), KeyStringOrOID::KeyString(s2)) => s1.partial_cmp(s2),
            (KeyStringOrOID::KeyString(_), KeyStringOrOID::OID(_)) => {
                Some(std::cmp::Ordering::Less)
            }
            (KeyStringOrOID::OID(_), KeyStringOrOID::KeyString(_)) => {
                Some(std::cmp::Ordering::Greater)
            }
            (KeyStringOrOID::OID(oid1), KeyStringOrOID::OID(oid2)) => {
                let s1: String = oid1.into();
                let s2: String = oid2.into();
                s1.partial_cmp(&s2)
            }
        }
    }
}

impl Ord for KeyStringOrOID {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        match (self, other) {
            (KeyStringOrOID::KeyString(s1), KeyStringOrOID::KeyString(s2)) => s1.cmp(s2),
            (KeyStringOrOID::KeyString(_), KeyStringOrOID::OID(_)) => std::cmp::Ordering::Less,
            (KeyStringOrOID::OID(_), KeyStringOrOID::KeyString(_)) => std::cmp::Ordering::Greater,
            (KeyStringOrOID::OID(oid1), KeyStringOrOID::OID(oid2)) => {
                let s1: String = oid1.into();
                let s2: String = oid2.into();
                s1.cmp(&s2)
            }
        }
    }
}

impl std::fmt::Display for KeyStringOrOID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self {
            Self::KeyString(s) => {
                std::fmt::Display::fmt(s, f)?;
                Ok(())
            }
            Self::OID(oid) => {
                let string_oid: String = oid.clone().into();
                std::fmt::Display::fmt(&string_oid, f)?;
                Ok(())
            }
        }
    }
}

/// parses either a [KeyString] or an [ObjectIdentifier]
#[cfg(feature = "chumsky")]
pub fn keystring_or_oid_parser() -> impl Parser<char, KeyStringOrOID, Error = Simple<char>> {
    keystring_parser()
        .map(KeyStringOrOID::KeyString)
        .or(oid_parser().map(KeyStringOrOID::OID))
}

/// in some locations LDAP allows OIDs with an optional length specifier
/// to describe attribute types with a length limit
#[derive(PartialEq, Eq, Clone)]
pub struct OIDWithLength {
    /// the [ObjectIdentifier]
    pub oid: ObjectIdentifier,
    /// the optional maximum length of the value
    pub length: Option<usize>,
}

impl std::fmt::Debug for OIDWithLength {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let string_oid: String = self.oid.clone().into();
        f.debug_struct("OIDWithLength")
            .field("oid", &string_oid)
            .field("length", &self.length)
            .finish()
    }
}

/// a relative distinguished name is one of the components of a distinguished name
/// usually a single pair of a keystring or an OID along with its attribute value
/// but it can also be a plus sign separated string of several such pairs
///
/// <https://ldapwiki.com/wiki/Relative%20Distinguished%20Name>
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RelativeDistinguishedName {
    /// the attributes of the RDN
    pub attributes: Vec<(KeyStringOrOID, Vec<u8>)>,
}

/// parses a series of hex-encoded bytes (always even number of hex digits)
#[cfg(feature = "chumsky")]
pub fn hex_byte_parser() -> impl Parser<char, u8, Error = Simple<char>> {
    filter(|c: &char| c.is_digit(16))
        .repeated()
        .exactly(2)
        .collect::<String>()
        .try_map(|ds, span| {
            hex::decode(ds.as_bytes()).map_err(|e| Simple::custom(span, format!("{:?}", e)))
        })
        .map(|v: Vec<u8>| v.first().unwrap().to_owned())
}

/// parses a hex-encoded binary attribute value in an RDN
#[cfg(feature = "chumsky")]
pub fn rdn_attribute_binary_value_parser() -> impl Parser<char, Vec<u8>, Error = Simple<char>> {
    just('#').ignore_then(hex_byte_parser().repeated())
}

/// parses a plain string attribute value in an RDN
#[cfg(feature = "chumsky")]
pub fn rdn_attribute_string_value_parser() -> impl Parser<char, Vec<u8>, Error = Simple<char>> {
    none_of(",+\"\\<>;")
        .or(just('\\').ignore_then(one_of(" ,+\"\\<>;")))
        .or(just('\\').ignore_then(hex_byte_parser().map(|s| s as char)))
        .repeated()
        .collect::<String>()
        .map(|s| s.as_bytes().to_vec())
}

/// parses either a binary or a plain attribute value in an RDN
#[cfg(feature = "chumsky")]
pub fn rdn_attribute_value_parser() -> impl Parser<char, Vec<u8>, Error = Simple<char>> {
    rdn_attribute_binary_value_parser().or(rdn_attribute_string_value_parser())
}

/// parses a [RelativeDistinguishedName]
#[cfg(feature = "chumsky")]
pub fn rdn_parser() -> impl Parser<char, RelativeDistinguishedName, Error = Simple<char>> {
    keystring_or_oid_parser()
        .then(just('=').ignore_then(rdn_attribute_value_parser()))
        .separated_by(just('+'))
        .at_least(1)
        .map(|attributes| RelativeDistinguishedName { attributes })
}

/// a distinguished name is a unique identifier for an entry within the LDAP tree,
/// it is comprised of a comma-separated ordered list of [RelativeDistinguishedName]
/// components
///
/// <https://ldapwiki.com/wiki/Distinguished%20Names>
#[derive(Debug, PartialEq, Eq)]
pub struct DistinguishedName {
    /// the RDN components of the DN
    pub rdns: Vec<RelativeDistinguishedName>,
}

impl PartialOrd for DistinguishedName {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DistinguishedName {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.rdns
            .iter()
            .rev()
            .zip(other.rdns.iter().rev())
            .map(|(a, b)| a.cmp(b))
            .fold(std::cmp::Ordering::Equal, |acc, e| acc.then(e))
            .then(self.rdns.len().cmp(&other.rdns.len()))
    }
}

/// parses a [DistinguishedName]
#[cfg(feature = "chumsky")]
pub fn dn_parser() -> impl Parser<char, DistinguishedName, Error = Simple<char>> {
    rdn_parser()
        .separated_by(just(','))
        .map(|rdns| DistinguishedName { rdns })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_oid() {
        assert!(oid_parser().parse("1.2.3.4").is_ok());
    }

    #[test]
    fn test_parse_oid_value() {
        assert_eq!(
            oid_parser().parse("1.2.3.4"),
            Ok("1.2.3.4".to_string().try_into().unwrap())
        );
    }

    #[test]
    fn test_dn_parser_empty_dn() {
        assert_eq!(
            dn_parser().parse(""),
            Ok(DistinguishedName { rdns: vec![] })
        )
    }

    #[test]
    fn test_dn_parser_single_rdn_single_string_attribute() {
        assert_eq!(
            dn_parser().parse("cn=Foobar"),
            Ok(DistinguishedName {
                rdns: vec![RelativeDistinguishedName {
                    attributes: vec![(
                        KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                        "Foobar".as_bytes().to_vec()
                    )]
                }]
            })
        )
    }

    #[test]
    fn test_dn_parser_single_rdn_single_string_attribute_with_escaped_comma() {
        assert_eq!(
            dn_parser().parse("cn=Foo\\,bar"),
            Ok(DistinguishedName {
                rdns: vec![RelativeDistinguishedName {
                    attributes: vec![(
                        KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                        "Foo,bar".as_bytes().to_vec()
                    )]
                }]
            })
        )
    }

    #[test]
    fn test_dn_parser_single_rdn_single_binary_attribute() {
        assert_eq!(
            dn_parser().parse("cn=#466f6f626172"),
            Ok(DistinguishedName {
                rdns: vec![RelativeDistinguishedName {
                    attributes: vec![(
                        KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                        "Foobar".as_bytes().to_vec()
                    )]
                }]
            })
        )
    }

    #[test]
    fn test_dn_parser_single_rdn_multiple_string_attributes() {
        assert_eq!(
            dn_parser().parse("cn=Foo\\,bar+uid=foobar"),
            Ok(DistinguishedName {
                rdns: vec![RelativeDistinguishedName {
                    attributes: vec![
                        (
                            KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                            "Foo,bar".as_bytes().to_vec()
                        ),
                        (
                            KeyStringOrOID::KeyString(KeyString("uid".to_string())),
                            "foobar".as_bytes().to_vec()
                        ),
                    ]
                }]
            })
        )
    }

    #[test]
    fn test_dn_parser_multiple_rdns() {
        assert_eq!(
            dn_parser().parse("cn=Foo\\,bar,uid=foobar"),
            Ok(DistinguishedName {
                rdns: vec![
                    RelativeDistinguishedName {
                        attributes: vec![(
                            KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                            "Foo,bar".as_bytes().to_vec()
                        )]
                    },
                    RelativeDistinguishedName {
                        attributes: vec![(
                            KeyStringOrOID::KeyString(KeyString("uid".to_string())),
                            "foobar".as_bytes().to_vec()
                        )]
                    },
                ]
            })
        )
    }

    #[test]
    fn test_dn_cmp() {
        assert_eq!(
            DistinguishedName { rdns: vec![] }.cmp(&DistinguishedName {
                rdns: vec![RelativeDistinguishedName {
                    attributes: vec![(
                        KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                        "Foo,bar".as_bytes().to_vec()
                    )]
                }]
            }),
            std::cmp::Ordering::Less
        )
    }
}
