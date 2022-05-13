//! Contains al the basic LDAP types
use std::{
    collections::{HashMap, HashSet},
    convert::TryFrom,
    hash::{Hash, Hasher},
};

use educe::Educe;
use oid::ObjectIdentifier;

use is_macro::Is;

use enum_as_inner::EnumAsInner;

#[cfg(feature = "chumsky")]
use chumsky::{prelude::*, text::digits};

#[cfg(feature = "chumsky")]
use itertools::Itertools;

#[cfg(feature = "chumsky")]
use ariadne::{Color, Fmt, Label, Report, ReportKind, Source};

#[cfg(feature = "serde")]
use serde::{de::SeqAccess, ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};

#[cfg(feature = "diff")]
use diff::Diff;

/// a wrapped error in case parsing fails to get proper error output
/// the chumsky errors themselves lack Display and std::error::Error
/// implementations
#[cfg(feature = "chumsky")]
#[derive(Debug)]
pub struct ChumskyError {
    /// description of the object we were trying to parse
    pub description: String,
    /// source string for parsing
    pub source: String,
    /// errors encountered during parsing
    pub errors: Vec<chumsky::error::Simple<char>>,
}

#[cfg(feature = "chumsky")]
impl std::fmt::Display for ChumskyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for e in &self.errors {
            let msg = format!(
                "While parsing {}: {}{}, expected {}",
                self.description,
                if e.found().is_some() {
                    "Unexpected token"
                } else {
                    "Unexpected end of input"
                },
                if let Some(label) = e.label() {
                    format!(" while parsing {}", label)
                } else {
                    String::new()
                },
                if e.expected().len() == 0 {
                    "end of input".to_string()
                } else {
                    e.expected()
                        .map(|expected| match expected {
                            Some(expected) => expected.to_string(),
                            None => "end of input".to_string(),
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                },
            );

            let report = Report::build(ReportKind::Error, (), e.span().start)
                .with_code(3)
                .with_message(msg)
                .with_label(
                    Label::new(e.span())
                        .with_message(format!(
                            "Unexpected {}",
                            e.found()
                                .map(|c| format!("token {}", c.fg(Color::Red)))
                                .unwrap_or_else(|| "end of input".to_string())
                        ))
                        .with_color(Color::Red),
                );

            let report = match e.reason() {
                chumsky::error::SimpleReason::Unclosed { span, delimiter } => report.with_label(
                    Label::new(span.clone())
                        .with_message(format!(
                            "Unclosed delimiter {}",
                            delimiter.fg(Color::Yellow)
                        ))
                        .with_color(Color::Yellow),
                ),
                chumsky::error::SimpleReason::Unexpected => report,
                chumsky::error::SimpleReason::Custom(msg) => report.with_label(
                    Label::new(e.span())
                        .with_message(format!("{}", msg.fg(Color::Yellow)))
                        .with_color(Color::Yellow),
                ),
            };

            let mut s: Vec<u8> = Vec::new();
            report
                .finish()
                .write(Source::from(&self.source), &mut s)
                .map_err(|_| <std::fmt::Error as std::default::Default>::default())?;
            let s = std::str::from_utf8(&s).expect("Expected ariadne to generate valid UTF-8");
            write!(f, "{}", s)?;
        }
        Ok(())
    }
}

#[cfg(feature = "chumsky")]
impl std::error::Error for ChumskyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// represents the object to request from an LDAP server to figure out which
/// features,... it supports
///
/// <https://ldapwiki.com/wiki/RootDSE>
///
/// <https://ldapwiki.com/wiki/LDAP%20Extensions%20and%20Controls%20Listing>
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
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

    /// converts the KeyString to lowercase
    pub fn to_lowercase(&self) -> KeyString {
        let KeyString(s) = self;
        KeyString(s.to_lowercase())
    }
}

impl TryFrom<KeyStringOrOID> for KeyString {
    type Error = ();

    fn try_from(value: KeyStringOrOID) -> Result<Self, Self::Error> {
        match value {
            KeyStringOrOID::KeyString(ks) => Ok(ks),
            KeyStringOrOID::OID(_) => Err(()),
        }
    }
}

impl TryFrom<&KeyStringOrOID> for KeyString {
    type Error = ();

    fn try_from(value: &KeyStringOrOID) -> Result<Self, Self::Error> {
        match value {
            KeyStringOrOID::KeyString(ks) => Ok(ks.to_owned()),
            KeyStringOrOID::OID(_) => Err(()),
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

/// hash function for ObjectIdentifier based on string representation
/// since ObjectIdentifier does not implement Hash
pub fn hash_oid<H: Hasher>(s: &ObjectIdentifier, state: &mut H) {
    Hash::hash(&format!("{s:?}"), state);
}

/// LDAP allows the use of either a keystring or an OID in many locations,
/// e.g. in DNs or in the schema
#[derive(Clone, Debug, Is, EnumAsInner, Educe)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[educe(PartialEq, Eq, Hash)]
pub enum KeyStringOrOID {
    /// this represents a [KeyString]
    #[cfg_attr(feature = "serde", serde(rename = "key_string"))]
    KeyString(KeyString),
    /// this reprents an [ObjectIdentifier]
    #[cfg_attr(feature = "serde", serde(rename = "oid"))]
    OID(#[educe(Hash(method = "hash_oid"))] ObjectIdentifier),
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

#[cfg(feature = "chumsky")]
impl TryFrom<&str> for KeyStringOrOID {
    type Error = ChumskyError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        (keystring_or_oid_parser().then_ignore(chumsky::primitive::end()))
            .parse(value)
            .map_err(|e| ChumskyError {
                description: "keystring or OID".to_string(),
                source: value.to_string(),
                errors: e,
            })
    }
}

#[cfg(feature = "chumsky")]
impl TryFrom<String> for KeyStringOrOID {
    type Error = ChumskyError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        (keystring_or_oid_parser().then_ignore(chumsky::primitive::end()))
            .parse(value.to_owned())
            .map_err(|e| ChumskyError {
                description: "keystring or OID".to_string(),
                source: value.to_string(),
                errors: e,
            })
    }
}

#[cfg(feature = "chumsky")]
impl TryFrom<&String> for KeyStringOrOID {
    type Error = ChumskyError;
    fn try_from(value: &String) -> Result<Self, Self::Error> {
        (keystring_or_oid_parser().then_ignore(chumsky::primitive::end()))
            .parse(value.to_owned())
            .map_err(|e| ChumskyError {
                description: "keystring or OID".to_string(),
                source: value.to_string(),
                errors: e,
            })
    }
}

#[cfg(feature = "chumsky")]
impl std::str::FromStr for KeyStringOrOID {
    type Err = ChumskyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        (keystring_or_oid_parser().then_ignore(chumsky::primitive::end()))
            .parse(s.to_owned())
            .map_err(|e| ChumskyError {
                description: "keystring or OID".to_string(),
                source: s.to_string(),
                errors: e,
            })
    }
}

impl From<&KeyStringOrOID> for KeyStringOrOID {
    fn from(value: &KeyStringOrOID) -> Self {
        value.to_owned()
    }
}

impl From<KeyString> for KeyStringOrOID {
    fn from(value: KeyString) -> Self {
        KeyStringOrOID::KeyString(value)
    }
}

impl From<&KeyString> for KeyStringOrOID {
    fn from(value: &KeyString) -> Self {
        KeyStringOrOID::KeyString(value.to_owned())
    }
}

impl From<ObjectIdentifier> for KeyStringOrOID {
    fn from(value: ObjectIdentifier) -> Self {
        KeyStringOrOID::OID(value)
    }
}

impl From<&ObjectIdentifier> for KeyStringOrOID {
    fn from(value: &ObjectIdentifier) -> Self {
        KeyStringOrOID::OID(value.to_owned())
    }
}

impl TryFrom<KeyStringOrOID> for ObjectIdentifier {
    type Error = ();

    fn try_from(value: KeyStringOrOID) -> Result<Self, Self::Error> {
        match value {
            KeyStringOrOID::OID(oid) => Ok(oid),
            KeyStringOrOID::KeyString(_) => Err(()),
        }
    }
}

impl TryFrom<&KeyStringOrOID> for ObjectIdentifier {
    type Error = ();

    fn try_from(value: &KeyStringOrOID) -> Result<Self, Self::Error> {
        match value {
            KeyStringOrOID::OID(oid) => Ok(oid.to_owned()),
            KeyStringOrOID::KeyString(_) => Err(()),
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
#[derive(Clone, Educe)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[educe(PartialEq, Eq, Hash)]
pub struct OIDWithLength {
    /// the [ObjectIdentifier]
    #[educe(Hash(method = "hash_oid"))]
    pub oid: ObjectIdentifier,
    /// the optional maximum length of the value
    pub length: Option<usize>,
}

impl From<OIDWithLength> for ObjectIdentifier {
    fn from(value: OIDWithLength) -> Self {
        value.oid
    }
}

impl From<&OIDWithLength> for ObjectIdentifier {
    fn from(value: &OIDWithLength) -> Self {
        value.oid.to_owned()
    }
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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RelativeDistinguishedName {
    /// the attributes of the RDN
    #[cfg_attr(
        feature = "serde",
        serde(serialize_with = "serialize_rdn", deserialize_with = "deserialize_rdn")
    )]
    pub attributes: Vec<(KeyStringOrOID, Vec<u8>)>,
}

impl std::fmt::Display for RelativeDistinguishedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut first = true;
        for (k, v) in &self.attributes {
            if !first {
                write!(f, "+")?;
            } else {
                first = false;
            }
            write!(f, "{}", k)?;
            write!(f, "=")?;
            if let Ok(s) = std::str::from_utf8(v) {
                write!(f, "{}", s)?;
            } else {
                write!(f, "#{}", hex::encode(v))?;
            }
        }
        Ok(())
    }
}

#[cfg(feature = "chumsky")]
impl TryFrom<&str> for RelativeDistinguishedName {
    type Error = ChumskyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        (rdn_parser().then_ignore(chumsky::primitive::end()))
            .parse(value)
            .map_err(|e| ChumskyError {
                description: "relative distinguished name".to_string(),
                source: value.to_string(),
                errors: e,
            })
    }
}

#[cfg(feature = "chumsky")]
impl TryFrom<String> for RelativeDistinguishedName {
    type Error = ChumskyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        (rdn_parser().then_ignore(chumsky::primitive::end()))
            .parse(value.to_owned())
            .map_err(|e| ChumskyError {
                description: "relative distinguished name".to_string(),
                source: value.to_string(),
                errors: e,
            })
    }
}

#[cfg(feature = "chumsky")]
impl std::str::FromStr for RelativeDistinguishedName {
    type Err = ChumskyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        (rdn_parser().then_ignore(chumsky::primitive::end()))
            .parse(s)
            .map_err(|e| ChumskyError {
                description: "relative distinguished name".to_string(),
                source: s.to_string(),
                errors: e,
            })
    }
}

impl From<RelativeDistinguishedName> for String {
    fn from(rdn: RelativeDistinguishedName) -> Self {
        rdn.to_string()
    }
}

/// serialize RDN attribute values as string if possible
/// falling back to array of numbers of necessary
#[cfg(feature = "serde")]
pub fn serialize_rdn<S>(xs: &[(KeyStringOrOID, Vec<u8>)], s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq = s.serialize_seq(Some(xs.len()))?;
    for e @ (k, v) in xs.iter() {
        if let Ok(s) = std::str::from_utf8(v) {
            seq.serialize_element(&(k, s))?;
        } else {
            seq.serialize_element(e)?;
        }
    }
    seq.end()
}

/// parses an RDN with attribute values being represented either as a string or an array of integers
#[cfg(feature = "serde")]
pub fn deserialize_rdn<'de, D>(d: D) -> Result<Vec<(KeyStringOrOID, Vec<u8>)>, D::Error>
where
    D: Deserializer<'de>,
{
    /// untagged union to allow deserializing attribute values as either string or bytes
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum StringOrBytes {
        /// string attribute value
        String(String),
        /// bytes attribute value
        Bytes(Vec<u8>),
    }

    /// visitor to deserialize RDNs in deserialize_rdn
    struct RDNVisitor;

    impl<'de> serde::de::Visitor<'de> for RDNVisitor {
        type Value = Vec<(KeyStringOrOID, StringOrBytes)>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "an array of tuples of attribute name and attribute value (either a string or a sequence of integers)")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            let mut result = Vec::new();
            while let Some(e) = seq.next_element()? {
                result.push(e);
            }
            Ok(result)
        }
    }

    let parse_result = d.deserialize_seq(RDNVisitor)?;
    let mut results = Vec::new();
    for (ref k, ref v) in parse_result {
        match v {
            StringOrBytes::String(s) => {
                results.push((k.to_owned(), s.as_bytes().to_vec()));
            }
            StringOrBytes::Bytes(b) => results.push((k.to_owned(), b.to_vec())),
        }
    }
    Ok(results)
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
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DistinguishedName {
    /// the RDN components of the DN
    pub rdns: Vec<RelativeDistinguishedName>,
}

impl DistinguishedName {
    /// returns true if this is the empty DN
    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }
    /// returns the DN for the parent object in the LDAP hierarchy unless this is
    /// already the empty DN
    pub fn parent(&self) -> Option<DistinguishedName> {
        if self.is_empty() {
            None
        } else {
            Some(DistinguishedName {
                rdns: self.rdns.iter().skip(1).cloned().collect(),
            })
        }
    }

    /// checks if the current DN is an ancestor (parent, parent of parent,...)
    /// of the given other DN
    ///
    /// it does return false if both DNs are identical
    pub fn is_ancestor_of(&self, other: &DistinguishedName) -> bool {
        let mut it = self.rdns.iter().rev();
        let mut other_it = other.rdns.iter().rev();
        loop {
            let e = it.next();
            let other_e = other_it.next();
            match (e, other_e) {
                (None, None) => {
                    // both DNs are identical
                    return false;
                }
                (Some(_), None) => {
                    // self is longer, can not be an ancestor
                    return false;
                }
                (None, Some(_)) => {
                    // so far we have not gotten a false and self is longer,
                    // so other must be an ancestor
                    return true;
                }
                (Some(e), Some(other_e)) => {
                    if e != other_e {
                        // different RDNs in the same position mean self
                        // can not be an ancestor of other (or vice versa)
                        return false;
                    }
                    // identical RDNs in this position mean we can advance
                    // the loop
                }
            }
        }
    }

    /// add suffix DN to this DN (e.g. the base DN)
    pub fn add_suffix(&self, other: &DistinguishedName) -> DistinguishedName {
        DistinguishedName {
            rdns: vec![self.rdns.to_vec(), other.rdns.to_vec()].concat(),
        }
    }

    /// remove a suffix DN from this DN (e.g. the base DN)
    pub fn strip_suffix(&self, other: &DistinguishedName) -> Option<DistinguishedName> {
        if !other.is_ancestor_of(self) {
            None
        } else {
            let self_len = self.rdns.len();
            let other_len = other.rdns.len();
            Some(DistinguishedName {
                rdns: self.rdns.split_at(self_len - other_len).0.to_vec(),
            })
        }
    }
}

#[cfg(feature = "chumsky")]
impl TryFrom<&str> for DistinguishedName {
    type Error = ChumskyError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        (dn_parser().then_ignore(chumsky::primitive::end()))
            .parse(value)
            .map_err(|e| ChumskyError {
                description: "distinguished name".to_string(),
                source: value.to_string(),
                errors: e,
            })
    }
}

#[cfg(feature = "chumsky")]
impl TryFrom<String> for DistinguishedName {
    type Error = ChumskyError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        (dn_parser().then_ignore(chumsky::primitive::end()))
            .parse(value.to_owned())
            .map_err(|e| ChumskyError {
                description: "distinguished name".to_string(),
                source: value.to_string(),
                errors: e,
            })
    }
}

#[cfg(feature = "chumsky")]
impl std::str::FromStr for DistinguishedName {
    type Err = ChumskyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        (dn_parser().then_ignore(chumsky::primitive::end()))
            .parse(s)
            .map_err(|e| ChumskyError {
                description: "distinguished name".to_string(),
                source: s.to_string(),
                errors: e,
            })
    }
}

impl From<DistinguishedName> for String {
    fn from(dn: DistinguishedName) -> Self {
        dn.to_string()
    }
}

impl std::fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let mut first = true;
        for rdn in &self.rdns {
            if !first {
                write!(f, ",")?;
            } else {
                first = false;
            }
            write!(f, "{}", rdn)?;
        }
        Ok(())
    }
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

/// represents an object in the LDAP tree
/// we would use ldap3::SearchEntry but then we would not be able to derive Diff
/// easily
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "diff", derive(Diff))]
#[cfg_attr(feature = "diff", diff(attr(#[derive(Debug, Serialize, Deserialize)] #[allow(missing_docs)])))]
pub struct LDAPEntry {
    /// the DN of the entry
    pub dn: String,
    /// the textual attributes of the entry
    pub attrs: HashMap<String, Vec<String>>,
    /// the binary attributes of the entry
    pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
}

impl LDAPEntry {
    /// return the combined attributes from attrs and bin_attrs for use in e.g. the [ldap3::Ldap::add] method
    pub fn combined_attrs(&self) -> Vec<(Vec<u8>, HashSet<Vec<u8>>)> {
        let mut result: HashMap<Vec<u8>, HashSet<Vec<u8>>> = HashMap::new();
        for (attr_name, attr_values) in &self.attrs {
            let attr_name = attr_name.as_bytes().to_vec();
            let attr_values = attr_values.iter().map(|x| x.as_bytes().to_vec()).collect();
            if let Some(values) = result.get_mut(&attr_name) {
                values.extend(attr_values);
            } else {
                result.insert(attr_name, attr_values);
            }
        }
        for (attr_name, attr_values) in &self.bin_attrs {
            let attr_name = attr_name.as_bytes().to_vec();
            let attr_values = attr_values.iter().map(|x| x.to_vec()).collect();
            if let Some(values) = result.get_mut(&attr_name) {
                values.extend(attr_values);
            } else {
                result.insert(attr_name, attr_values);
            }
        }
        result.into_iter().collect()
    }
}

#[cfg(feature = "ldap3")]
impl From<ldap3::SearchEntry> for LDAPEntry {
    fn from(entry: ldap3::SearchEntry) -> Self {
        Self {
            dn: entry.dn,
            attrs: entry.attrs,
            bin_attrs: entry.bin_attrs,
        }
    }
}

#[cfg(feature = "ldap3")]
impl From<LDAPEntry> for ldap3::SearchEntry {
    fn from(entry: LDAPEntry) -> Self {
        Self {
            dn: entry.dn,
            attrs: entry.attrs,
            bin_attrs: entry.bin_attrs,
        }
    }
}

/// an operation to perform to turn one LDAP object into another.
/// we purposefully only include operations here that operate without
/// moving the object to a different DN
#[derive(Debug, Clone, EnumAsInner)]
pub enum LDAPOperation {
    /// add a new entry
    Add(LDAPEntry),
    /// delete an existing entry
    Delete {
        /// the DN of the entry to delete
        dn: String,
    },
    /// modify attributes of an existing entry
    Modify {
        /// the DN of the entry to modify
        dn: String,
        /// the modifications to textual attributes to perform
        mods: Vec<ldap3::Mod<String>>,
        /// the modifications to binary attributes to perform
        bin_mods: Vec<ldap3::Mod<Vec<u8>>>,
    },
}

impl LDAPOperation {
    /// Used to order operations so parents are added first and children deleted first
    #[cfg(feature = "chumsky")]
    pub fn operation_apply_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        match (self, other) {
            (
                LDAPOperation::Add(entry1 @ LDAPEntry { .. }),
                LDAPOperation::Add(entry2 @ LDAPEntry { .. }),
            ) => {
                let parsed_dn1: Result<DistinguishedName, _> =
                    dn_parser().parse(entry1.dn.to_owned());
                let parsed_dn2: Result<DistinguishedName, _> =
                    dn_parser().parse(entry2.dn.to_owned());
                if let (Ok(parsed_dn1), Ok(parsed_dn2)) = (parsed_dn1, parsed_dn2) {
                    Some(parsed_dn1.cmp(&parsed_dn2))
                } else {
                    None
                }
            }
            (op1 @ LDAPOperation::Delete { .. }, op2 @ LDAPOperation::Delete { .. }) => {
                let parsed_dn1: Result<DistinguishedName, _> =
                    dn_parser().parse(op1.as_delete().unwrap().to_owned());
                let parsed_dn2: Result<DistinguishedName, _> =
                    dn_parser().parse(op2.as_delete().unwrap().to_owned());
                if let (Ok(parsed_dn1), Ok(parsed_dn2)) = (parsed_dn1, parsed_dn2) {
                    Some(parsed_dn1.cmp(&parsed_dn2))
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use pretty_assertions::assert_eq;

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

    #[test]
    fn test_serialize_json_oid() -> Result<(), Box<dyn std::error::Error>> {
        let oid: ObjectIdentifier = "1.2.3.4".to_string().try_into().unwrap();
        let result = serde_json::to_string(&oid)?;
        assert_eq!(result, "\"1.2.3.4\"".to_string());
        Ok(())
    }

    #[test]
    fn test_deserialize_json_oid() -> Result<(), Box<dyn std::error::Error>> {
        let expected: ObjectIdentifier = "1.2.3.4".to_string().try_into().unwrap();
        let result: ObjectIdentifier = serde_json::from_str("\"1.2.3.4\"")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_serialize_json_keystring() -> Result<(), Box<dyn std::error::Error>> {
        let ks: KeyString = KeyString("foo".to_string());
        let result = serde_json::to_string(&ks)?;
        assert_eq!(result, "\"foo\"".to_string());
        Ok(())
    }

    #[test]
    fn test_deserialize_json_keystring() -> Result<(), Box<dyn std::error::Error>> {
        let expected: KeyString = KeyString("foo".to_string());
        let result: KeyString = serde_json::from_str("\"foo\"")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_serialize_json_keystring_or_oid_keystring() -> Result<(), Box<dyn std::error::Error>> {
        let ks: KeyStringOrOID = KeyStringOrOID::KeyString(KeyString("foo".to_string()));
        let result = serde_json::to_string(&ks)?;
        assert_eq!(result, "{\"key_string\":\"foo\"}".to_string());
        Ok(())
    }

    #[test]
    fn test_deserialize_json_keystring_or_oid_keystring() -> Result<(), Box<dyn std::error::Error>>
    {
        let expected: KeyStringOrOID = KeyStringOrOID::KeyString(KeyString("foo".to_string()));
        let result: KeyStringOrOID = serde_json::from_str("{\"key_string\":\"foo\"}")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_serialize_json_keystring_or_oid_oid() -> Result<(), Box<dyn std::error::Error>> {
        let ks: KeyStringOrOID = KeyStringOrOID::OID("1.2.3.4".to_string().try_into().unwrap());
        let result = serde_json::to_string(&ks)?;
        assert_eq!(result, "{\"oid\":\"1.2.3.4\"}".to_string());
        Ok(())
    }

    #[test]
    fn test_deserialize_json_keystring_or_oid_oid() -> Result<(), Box<dyn std::error::Error>> {
        let expected: KeyStringOrOID =
            KeyStringOrOID::OID("1.2.3.4".to_string().try_into().unwrap());
        let result: KeyStringOrOID = serde_json::from_str("{\"oid\":\"1.2.3.4\"}")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_serialize_json_rdn() -> Result<(), Box<dyn std::error::Error>> {
        let rdn: RelativeDistinguishedName = RelativeDistinguishedName {
            attributes: vec![(
                KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                "Foobar".as_bytes().to_vec(),
            )],
        };
        let result = serde_json::to_string(&rdn)?;
        assert_eq!(
            result,
            "{\"attributes\":[[{\"key_string\":\"cn\"},\"Foobar\"]]}".to_string()
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_json_rdn_string() -> Result<(), Box<dyn std::error::Error>> {
        let expected: RelativeDistinguishedName = RelativeDistinguishedName {
            attributes: vec![(
                KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                "Foobar".as_bytes().to_vec(),
            )],
        };
        let result: RelativeDistinguishedName =
            serde_json::from_str("{\"attributes\":[[{\"key_string\":\"cn\"},\"Foobar\"]]}")?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_deserialize_json_rdn_integers() -> Result<(), Box<dyn std::error::Error>> {
        let expected: RelativeDistinguishedName = RelativeDistinguishedName {
            attributes: vec![(
                KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                "Foobar".as_bytes().to_vec(),
            )],
        };
        let result: RelativeDistinguishedName = serde_json::from_str(
            "{\"attributes\":[[{\"key_string\":\"cn\"},[70, 111, 111, 98, 97, 114]]]}",
        )?;
        assert_eq!(result, expected);
        Ok(())
    }

    #[test]
    fn test_serialize_json_dn() -> Result<(), Box<dyn std::error::Error>> {
        let dn: DistinguishedName = DistinguishedName {
            rdns: vec![RelativeDistinguishedName {
                attributes: vec![
                    (
                        KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                        "Foo,bar".as_bytes().to_vec(),
                    ),
                    (
                        KeyStringOrOID::KeyString(KeyString("uid".to_string())),
                        "foobar".as_bytes().to_vec(),
                    ),
                ],
            }],
        };
        let result = serde_json::to_string(&dn)?;
        assert_eq!(
            result,
            "{\"rdns\":[{\"attributes\":[[{\"key_string\":\"cn\"},\"Foo,bar\"],[{\"key_string\":\"uid\"},\"foobar\"]]}]}".to_string()
        );
        Ok(())
    }

    #[test]
    fn test_deserialize_json_dn() -> Result<(), Box<dyn std::error::Error>> {
        let expected: DistinguishedName = DistinguishedName {
            rdns: vec![RelativeDistinguishedName {
                attributes: vec![
                    (
                        KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                        "Foo,bar".as_bytes().to_vec(),
                    ),
                    (
                        KeyStringOrOID::KeyString(KeyString("uid".to_string())),
                        "foobar".as_bytes().to_vec(),
                    ),
                ],
            }],
        };
        let result : DistinguishedName = serde_json::from_str("{\"rdns\":[{\"attributes\":[[{\"key_string\":\"cn\"},\"Foo,bar\"],[{\"key_string\":\"uid\"},\"foobar\"]]}]}")?;
        assert_eq!(result, expected);
        Ok(())
    }
}
