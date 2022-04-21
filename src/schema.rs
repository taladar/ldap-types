//! Contains all the code related to representing and parsing LDAP schemas
//!
//! LDAP Schema is defined in RFC2252 <https://www.rfc-editor.org/rfc/rfc2252.txt>

#[cfg(feature = "chumsky")]
use chumsky::{prelude::*, text::digits};
use enum_as_inner::EnumAsInner;
use is_macro::Is;
use oid::ObjectIdentifier;

#[cfg(feature = "chumsky")]
use lazy_static::lazy_static;

use crate::basic::{KeyString, KeyStringOrOID, OIDWithLength};

#[cfg(feature = "chumsky")]
use crate::basic::{
    keystring_or_oid_parser, keystring_parser, oid_parser, quoted_keystring_parser,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// stores the parameter values that can appear behind a tag in an LDAP schema entry
#[derive(PartialEq, Eq, Clone, Debug, Is, EnumAsInner)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LDAPSchemaTagValue {
    /// the tag has no value
    Standalone,
    /// the tag has an OID value
    OID(ObjectIdentifier),
    /// the tag has an OID value with an optional length
    OIDWithLength(OIDWithLength),
    /// the tag has a string value
    String(String),
    /// the tag has a key string value
    KeyString(KeyString),
    /// the tag has a quoted key string value
    QuotedKeyString(KeyString),
    /// the tag has a keystring or an OID value
    KeyStringOrOID(KeyStringOrOID),
    /// the tag has a boolean value
    Boolean(bool),
    /// the tag has a value that is a list of quoted key strings
    QuotedKeyStringList(Vec<KeyString>),
    /// the tag has a value that is a list of key strings or OIDs
    KeyStringOrOIDList(Vec<KeyStringOrOID>),
}

/// a single tag in an LDAP schema entry
#[derive(PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LDAPSchemaTag {
    /// the name of the tag
    tag_name: String,
    /// the value of the tag, if any
    tag_value: LDAPSchemaTagValue,
}

/// encodes the expected value type for a schema tag
/// this allows code reuse in the parser
#[cfg(feature = "chumsky")]
#[derive(PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum LDAPSchemaTagType {
    /// the tag is expected to not have a value
    Standalone,
    /// the tag is expected to have an OID value
    OID,
    /// the tag is expected to have an OID value with an optional length
    OIDWithLength,
    /// the tag is expected to have a string value
    String,
    /// the tag is expected to have a key string value
    KeyString,
    /// the tag is expected to have a quoted key string value
    QuotedKeyString,
    /// the tag is expected to have a key string or an OID value
    KeyStringOrOID,
    /// the tag is expected to have a boolean value
    Boolean,
    /// the tag is expected to have a value that is a list of quoted key strings
    QuotedKeyStringList,
    /// the tag is expected to have a value that is a list of keystrings or OIDs
    KeyStringOrOIDList,
}

/// describes an expected tag in an LDAP schema entry
#[cfg(feature = "chumsky")]
#[derive(PartialEq, Eq, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LDAPSchemaTagDescriptor {
    /// the tag name of the expected tag
    pub tag_name: String,
    /// the type of parameter we expect the tag to have
    pub tag_type: LDAPSchemaTagType,
}

/// this parses the LDAP schema tag value that is described by its parameter
#[cfg(feature = "chumsky")]
pub fn ldap_schema_tag_value_parser(
    tag_type: &LDAPSchemaTagType,
) -> impl Parser<char, LDAPSchemaTagValue, Error = Simple<char>> {
    match tag_type {
        LDAPSchemaTagType::Standalone => empty()
            .map(|_| LDAPSchemaTagValue::Standalone)
            .labelled("no value")
            .boxed(),
        LDAPSchemaTagType::OID => oid_parser()
            .map(LDAPSchemaTagValue::OID)
            .labelled("OID")
            .boxed(),
        LDAPSchemaTagType::OIDWithLength => oid_parser()
            .then(
                digits(10)
                    .delimited_by('{', '}')
                    .try_map(|x, span| {
                        x.parse().map_err(|e| {
                            Simple::custom(
                                span,
                                format!("Failed to convert parsed digits to integer: {}", e),
                            )
                        })
                    })
                    .or_not(),
            )
            .map(|(oid, len)| LDAPSchemaTagValue::OIDWithLength(OIDWithLength { oid, length: len }))
            .labelled("OID with optional length")
            .boxed(),
        LDAPSchemaTagType::String => none_of("'")
            .repeated()
            .delimited_by('\'', '\'')
            .collect::<String>()
            .map(LDAPSchemaTagValue::String)
            .labelled("single-quoted string")
            .boxed(),
        LDAPSchemaTagType::KeyString => keystring_parser()
            .map(LDAPSchemaTagValue::KeyString)
            .labelled("keystring")
            .boxed(),
        LDAPSchemaTagType::QuotedKeyString => quoted_keystring_parser()
            .map(LDAPSchemaTagValue::QuotedKeyString)
            .labelled("quoted keystring")
            .boxed(),
        LDAPSchemaTagType::KeyStringOrOID => keystring_or_oid_parser()
            .map(LDAPSchemaTagValue::KeyStringOrOID)
            .labelled("keystring or OID")
            .boxed(),
        LDAPSchemaTagType::Boolean => just("TRUE")
            .to(true)
            .or(just("FALSE").to(false))
            .delimited_by('\'', '\'')
            .map(LDAPSchemaTagValue::Boolean)
            .labelled("single-quoted uppercase boolean")
            .boxed(),
        LDAPSchemaTagType::KeyStringOrOIDList => keystring_or_oid_parser()
            .padded()
            .separated_by(just('$'))
            .delimited_by('(', ')')
            .or(keystring_or_oid_parser().map(|x| vec![x]))
            .map(LDAPSchemaTagValue::KeyStringOrOIDList)
            .labelled("list of keystrings or OIDs separated by $")
            .boxed(),
        LDAPSchemaTagType::QuotedKeyStringList => quoted_keystring_parser()
            .padded()
            .repeated()
            .delimited_by('(', ')')
            .or(quoted_keystring_parser().map(|x| vec![x]))
            .map(LDAPSchemaTagValue::QuotedKeyStringList)
            .labelled("list of quoted keystrings separated by spaces")
            .boxed(),
    }
}

/// this parses an LDAP schema tag described by its parameter
#[cfg(feature = "chumsky")]
pub fn ldap_schema_tag_parser(
    tag_descriptor: &LDAPSchemaTagDescriptor,
) -> impl Parser<char, LDAPSchemaTag, Error = Simple<char>> + '_ {
    just(tag_descriptor.tag_name.to_owned())
        .padded()
        .ignore_then(ldap_schema_tag_value_parser(&tag_descriptor.tag_type).padded())
        .map(move |tag_value| LDAPSchemaTag {
            tag_name: tag_descriptor.tag_name.to_string(),
            tag_value,
        })
}

/// this parses an LDAP schema entry described by its parameter
///
/// the tags can be in any order
///
/// this function only parses the tags, it does not check if required tags
/// exist in the output
#[cfg(feature = "chumsky")]
pub fn ldap_schema_parser(
    tag_descriptors: &[LDAPSchemaTagDescriptor],
) -> impl Parser<char, (ObjectIdentifier, Vec<LDAPSchemaTag>), Error = Simple<char>> + '_ {
    let (first, rest) = tag_descriptors
        .split_first()
        .expect("tag descriptors must have at least one element");
    oid_parser()
        .then(
            rest.iter()
                .fold(ldap_schema_tag_parser(first).boxed(), |p, td| {
                    p.or(ldap_schema_tag_parser(td)).boxed()
                })
                .padded()
                .repeated(),
        )
        .padded()
        .delimited_by('(', ')')
}

/// this is used to extract a required tag's value from the result of [ldap_schema_parser]
#[cfg(feature = "chumsky")]
pub fn required_tag(
    tag_name: &str,
    span: &std::ops::Range<usize>,
    tags: &[LDAPSchemaTag],
) -> Result<LDAPSchemaTagValue, Simple<char>> {
    tags.iter()
        .find(|x| x.tag_name == tag_name)
        .ok_or_else(|| {
            Simple::custom(
                span.clone(),
                format!("No {} tag in parsed LDAP schema tag list", tag_name),
            )
        })
        .map(|x| x.tag_value.to_owned())
}

/// this is used to extract an optional tag's value from the result of [ldap_schema_parser]
#[cfg(feature = "chumsky")]
pub fn optional_tag(tag_name: &str, tags: &[LDAPSchemaTag]) -> Option<LDAPSchemaTagValue> {
    tags.iter()
        .find(|x| x.tag_name == tag_name)
        .map(|x| x.tag_value.to_owned())
}

/// this describes an LDAP syntax schema entry
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LDAPSyntax {
    /// the OID of the syntax
    pub oid: ObjectIdentifier,
    /// the human-readable description of the syntax
    pub desc: String,
    /// does this syntax require binary transfer
    pub x_binary_transfer_required: bool,
    /// is this syntax human-readable
    pub x_not_human_readable: bool,
}

impl std::fmt::Debug for LDAPSyntax {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let string_oid: String = self.oid.clone().into();
        f.debug_struct("LDAPSyntax")
            .field("oid", &string_oid)
            .field("desc", &self.desc)
            .field(
                "x_binary_transfer_required",
                &self.x_binary_transfer_required,
            )
            .field("x_not_human_readable", &self.x_not_human_readable)
            .finish()
    }
}

/// parse an LDAP syntax schema entry
///
/// <https://ldapwiki.com/wiki/LDAPSyntaxes>
#[cfg(feature = "chumsky")]
pub fn ldap_syntax_parser() -> impl Parser<char, LDAPSyntax, Error = Simple<char>> {
    lazy_static! {
        static ref LDAP_SYNTAX_TAGS: Vec<LDAPSchemaTagDescriptor> = vec![
            LDAPSchemaTagDescriptor {
                tag_name: "DESC".to_string(),
                tag_type: LDAPSchemaTagType::String
            },
            LDAPSchemaTagDescriptor {
                tag_name: "X-BINARY-TRANSFER-REQUIRED".to_string(),
                tag_type: LDAPSchemaTagType::Boolean
            },
            LDAPSchemaTagDescriptor {
                tag_name: "X-NOT-HUMAN-READABLE".to_string(),
                tag_type: LDAPSchemaTagType::Boolean
            },
        ];
    }
    ldap_schema_parser(&LDAP_SYNTAX_TAGS).try_map(|(oid, tags), span| {
        Ok(LDAPSyntax {
            oid,
            desc: required_tag("DESC", &span, &tags)?
                .as_string()
                .unwrap()
                .to_string(),
            x_binary_transfer_required: *optional_tag("X-BINARY-TRANSFER-REQUIRED", &tags)
                .unwrap_or(LDAPSchemaTagValue::Boolean(false))
                .as_boolean()
                .unwrap(),
            x_not_human_readable: *optional_tag("X-NOT-HUMAN-READABLE", &tags)
                .unwrap_or(LDAPSchemaTagValue::Boolean(false))
                .as_boolean()
                .unwrap(),
        })
    })
}

/// a matching rule LDAP schema entry
///
/// <https://ldapwiki.com/wiki/MatchingRule>
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MatchingRule {
    /// the matching rule's OID
    pub oid: ObjectIdentifier,
    /// the matching rule's name
    pub name: Vec<KeyString>,
    /// the syntax this matching rule can be used with
    pub syntax: OIDWithLength,
}

impl std::fmt::Debug for MatchingRule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let string_oid: String = self.oid.clone().into();
        f.debug_struct("MatchingRule")
            .field("oid", &string_oid)
            .field("name", &self.name)
            .field("syntax", &self.syntax)
            .finish()
    }
}

/// parse a matching rule LDAP schema entry
#[cfg(feature = "chumsky")]
pub fn matching_rule_parser() -> impl Parser<char, MatchingRule, Error = Simple<char>> {
    lazy_static! {
        static ref MATCHING_RULE_TAGS: Vec<LDAPSchemaTagDescriptor> = vec![
            LDAPSchemaTagDescriptor {
                tag_name: "NAME".to_string(),
                tag_type: LDAPSchemaTagType::QuotedKeyStringList
            },
            LDAPSchemaTagDescriptor {
                tag_name: "SYNTAX".to_string(),
                tag_type: LDAPSchemaTagType::OIDWithLength
            },
        ];
    }
    ldap_schema_parser(&MATCHING_RULE_TAGS).try_map(|(oid, tags), span| {
        Ok(MatchingRule {
            oid,
            name: required_tag("NAME", &span, &tags)?
                .as_quoted_key_string_list()
                .unwrap()
                .to_vec(),
            syntax: required_tag("SYNTAX", &span, &tags)?
                .as_oid_with_length()
                .unwrap()
                .to_owned(),
        })
    })
}

/// parse a matching rule use LDAP schema entry
///
/// <https://ldapwiki.com/wiki/MatchingRuleUse>
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MatchingRuleUse {
    /// the OID of the matching rule this applies to
    pub oid: ObjectIdentifier,
    /// the name of the matching rule
    pub name: Vec<KeyString>,
    /// the attributes this matching rule can be used with
    pub applies: Vec<KeyStringOrOID>,
}

impl std::fmt::Debug for MatchingRuleUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let string_oid: String = self.oid.clone().into();
        f.debug_struct("MatchingRuleUse")
            .field("oid", &string_oid)
            .field("name", &self.name)
            .field("applies", &self.applies)
            .finish()
    }
}

/// parse a matching rule use LDAP schema entry
#[cfg(feature = "chumsky")]
pub fn matching_rule_use_parser() -> impl Parser<char, MatchingRuleUse, Error = Simple<char>> {
    lazy_static! {
        static ref MATCHING_RULE_USE_TAGS: Vec<LDAPSchemaTagDescriptor> = vec![
            LDAPSchemaTagDescriptor {
                tag_name: "NAME".to_string(),
                tag_type: LDAPSchemaTagType::QuotedKeyStringList
            },
            LDAPSchemaTagDescriptor {
                tag_name: "APPLIES".to_string(),
                tag_type: LDAPSchemaTagType::KeyStringOrOIDList
            },
        ];
    }
    ldap_schema_parser(&MATCHING_RULE_USE_TAGS).try_map(|(oid, tags), span| {
        Ok(MatchingRuleUse {
            oid,
            name: required_tag("NAME", &span, &tags)?
                .as_quoted_key_string_list()
                .unwrap()
                .to_vec(),
            applies: required_tag("APPLIES", &span, &tags)?
                .as_key_string_or_oid_list()
                .unwrap()
                .to_vec(),
        })
    })
}

/// an attribute type LDAP schema entry
///
/// <https://ldapwiki.com/wiki/AttributeTypes>
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AttributeType {
    /// the OID of the attribute type
    pub oid: ObjectIdentifier,
    /// the name of the attribute type
    pub name: Vec<KeyString>,
    /// the parent in the inheritance tree
    pub sup: Option<KeyString>,
    /// a human-readable description
    pub desc: Option<String>,
    /// the LDAP syntax of the attribute type
    pub syntax: Option<OIDWithLength>,
    /// is this a single or multi-valued attribute
    pub single_value: bool,
    /// the equality match to use with this attribute type
    pub equality: Option<KeyString>,
    /// the substring match to use with this attribute type
    pub substr: Option<KeyString>,
    /// the ordering to use with this attribute type
    pub ordering: Option<KeyString>,
    /// is user modification of this attribute type allowed
    /// (e.g. often operational attributes are not user modifiable)
    pub no_user_modification: bool,
    /// if this attribute is a
    ///
    /// * user attribute (userApplications)
    /// * an operational attribute (directoryOperation)
    /// * an operational attribute that needs to be replicated (distributedOperation)
    /// * an operational attribute that should not be replicated (dSAOperation)
    pub usage: Option<KeyString>,
    /// is this a collective attribute
    ///
    /// <https://ldapwiki.com/wiki/Collective%20Attribute>
    pub collective: bool,
    /// is this attribute obsolete
    pub obsolete: bool,
    /// is this attribute ordered and if so how
    ///
    /// * values (order among multiple attribute values is preserved)
    /// * siblings (order among entries using this attribute as RDN is preserved)
    ///
    /// <https://tools.ietf.org/html/draft-chu-ldap-xordered-00>
    pub x_ordered: Option<KeyString>,
}

impl std::fmt::Debug for AttributeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let string_oid: String = self.oid.clone().into();
        f.debug_struct("AttributeType")
            .field("oid", &string_oid)
            .field("name", &self.name)
            .field("sup", &self.sup)
            .field("desc", &self.desc)
            .field("syntax", &self.syntax)
            .field("single_value", &self.single_value)
            .field("equality", &self.equality)
            .field("substr", &self.substr)
            .field("ordering", &self.ordering)
            .field("no_user_modification", &self.no_user_modification)
            .field("usage", &self.usage)
            .field("collective", &self.collective)
            .field("obsolete", &self.obsolete)
            .field("x_ordered", &self.x_ordered)
            .finish()
    }
}

/// parser for attribute type LDAP schema entries
#[cfg(feature = "chumsky")]
pub fn attribute_type_parser() -> impl Parser<char, AttributeType, Error = Simple<char>> {
    lazy_static! {
        static ref ATTRIBUTE_TYPE_TAGS: Vec<LDAPSchemaTagDescriptor> = vec![
            LDAPSchemaTagDescriptor {
                tag_name: "NAME".to_string(),
                tag_type: LDAPSchemaTagType::QuotedKeyStringList
            },
            LDAPSchemaTagDescriptor {
                tag_name: "SUP".to_string(),
                tag_type: LDAPSchemaTagType::KeyString
            },
            LDAPSchemaTagDescriptor {
                tag_name: "DESC".to_string(),
                tag_type: LDAPSchemaTagType::String
            },
            LDAPSchemaTagDescriptor {
                tag_name: "SYNTAX".to_string(),
                tag_type: LDAPSchemaTagType::OIDWithLength
            },
            LDAPSchemaTagDescriptor {
                tag_name: "EQUALITY".to_string(),
                tag_type: LDAPSchemaTagType::KeyString
            },
            LDAPSchemaTagDescriptor {
                tag_name: "SUBSTR".to_string(),
                tag_type: LDAPSchemaTagType::KeyString
            },
            LDAPSchemaTagDescriptor {
                tag_name: "ORDERING".to_string(),
                tag_type: LDAPSchemaTagType::KeyString
            },
            LDAPSchemaTagDescriptor {
                tag_name: "SINGLE-VALUE".to_string(),
                tag_type: LDAPSchemaTagType::Standalone
            },
            LDAPSchemaTagDescriptor {
                tag_name: "NO-USER-MODIFICATION".to_string(),
                tag_type: LDAPSchemaTagType::Standalone
            },
            LDAPSchemaTagDescriptor {
                tag_name: "USAGE".to_string(),
                tag_type: LDAPSchemaTagType::KeyString
            },
            LDAPSchemaTagDescriptor {
                tag_name: "COLLECTIVE".to_string(),
                tag_type: LDAPSchemaTagType::Standalone
            },
            LDAPSchemaTagDescriptor {
                tag_name: "OBSOLETE".to_string(),
                tag_type: LDAPSchemaTagType::Standalone
            },
            LDAPSchemaTagDescriptor {
                tag_name: "X-ORDERED".to_string(),
                tag_type: LDAPSchemaTagType::QuotedKeyString
            },
        ];
    }
    ldap_schema_parser(&ATTRIBUTE_TYPE_TAGS).try_map(|(oid, tags), span| {
        Ok(AttributeType {
            oid,
            name: required_tag("NAME", &span, &tags)?
                .as_quoted_key_string_list()
                .unwrap()
                .to_vec(),
            sup: optional_tag("SUP", &tags).map(|s| s.as_key_string().unwrap().to_owned()),
            desc: optional_tag("DESC", &tags).map(|v| v.as_string().unwrap().to_string()),
            syntax: optional_tag("SYNTAX", &tags)
                .map(|v| v.as_oid_with_length().unwrap().to_owned()),
            single_value: optional_tag("SINGLE-VALUE", &tags).is_some(),
            equality: optional_tag("EQUALITY", &tags)
                .map(|s| s.as_key_string().unwrap().to_owned()),
            substr: optional_tag("SUBSTR", &tags).map(|s| s.as_key_string().unwrap().to_owned()),
            ordering: optional_tag("ORDERING", &tags)
                .map(|s| s.as_key_string().unwrap().to_owned()),
            no_user_modification: optional_tag("NO-USER-MODIFICATION", &tags).is_some(),
            usage: optional_tag("USAGE", &tags).map(|s| s.as_key_string().unwrap().to_owned()),
            collective: optional_tag("COLLECTIVE", &tags).is_some(),
            obsolete: optional_tag("OBSOLETE", &tags).is_some(),
            x_ordered: optional_tag("X-ORDERED", &tags)
                .map(|s| s.as_quoted_key_string().unwrap().to_owned()),
        })
    })
}

/// type of LDAP object class
#[derive(PartialEq, Eq, Clone, Debug, Is, EnumAsInner)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ObjectClassType {
    /// this can not be used as an actual object class and is purely used
    /// as a parent for the other types
    Abstract,
    /// this is the main objectclass of an object, other than structural classes
    /// that are ancestors in the inheritance hierarchy only one of these can be used
    /// on any given LDAP object
    Structural,
    /// these are objectclasses that are added on to the main structural object class
    /// of an entry
    Auxiliary,
}

/// an LDAP schema objectclass entry
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ObjectClass {
    /// the OID of the object class
    pub oid: ObjectIdentifier,
    /// the name of the object class
    pub name: Vec<KeyString>,
    /// the parent of the object class
    pub sup: Vec<KeyStringOrOID>,
    /// the human-readable description
    pub desc: Option<String>,
    /// the type of object class
    pub object_class_type: ObjectClassType,
    /// the attributes that must be present on an object with this object class
    pub must: Vec<KeyStringOrOID>,
    /// the attributes that may optionally also be present on an object with this
    /// object class
    pub may: Vec<KeyStringOrOID>,
    /// is this object class obsolete
    pub obsolete: bool,
}

impl std::fmt::Debug for ObjectClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        let string_oid: String = self.oid.clone().into();
        f.debug_struct("ObjectClass")
            .field("oid", &string_oid)
            .field("name", &self.name)
            .field("sup", &self.sup)
            .field("desc", &self.desc)
            .field("object_class_type", &self.object_class_type)
            .field("must", &self.must)
            .field("may", &self.may)
            .field("obsolete", &self.obsolete)
            .finish()
    }
}

/// parses an LDAP schema object class entry
#[cfg(feature = "chumsky")]
pub fn object_class_parser() -> impl Parser<char, ObjectClass, Error = Simple<char>> {
    lazy_static! {
        static ref OBJECT_CLASS_TAGS: Vec<LDAPSchemaTagDescriptor> = vec![
            LDAPSchemaTagDescriptor {
                tag_name: "NAME".to_string(),
                tag_type: LDAPSchemaTagType::QuotedKeyStringList
            },
            LDAPSchemaTagDescriptor {
                tag_name: "SUP".to_string(),
                tag_type: LDAPSchemaTagType::KeyStringOrOIDList
            },
            LDAPSchemaTagDescriptor {
                tag_name: "DESC".to_string(),
                tag_type: LDAPSchemaTagType::String
            },
            LDAPSchemaTagDescriptor {
                tag_name: "ABSTRACT".to_string(),
                tag_type: LDAPSchemaTagType::Standalone
            },
            LDAPSchemaTagDescriptor {
                tag_name: "STRUCTURAL".to_string(),
                tag_type: LDAPSchemaTagType::Standalone
            },
            LDAPSchemaTagDescriptor {
                tag_name: "AUXILIARY".to_string(),
                tag_type: LDAPSchemaTagType::Standalone
            },
            LDAPSchemaTagDescriptor {
                tag_name: "MUST".to_string(),
                tag_type: LDAPSchemaTagType::KeyStringOrOIDList
            },
            LDAPSchemaTagDescriptor {
                tag_name: "MAY".to_string(),
                tag_type: LDAPSchemaTagType::KeyStringOrOIDList
            },
            LDAPSchemaTagDescriptor {
                tag_name: "OBSOLETE".to_string(),
                tag_type: LDAPSchemaTagType::Standalone
            },
        ];
    }
    ldap_schema_parser(&OBJECT_CLASS_TAGS).try_map(|(oid, tags), span| {
        Ok(ObjectClass {
            oid,
            name: required_tag("NAME", &span, &tags)?
                .as_quoted_key_string_list()
                .unwrap()
                .to_vec(),
            sup: optional_tag("SUP", &tags)
                .map(|s| s.as_key_string_or_oid_list().unwrap().to_owned())
                .unwrap_or_default(),
            desc: optional_tag("DESC", &tags).map(|v| v.as_string().unwrap().to_string()),
            object_class_type: optional_tag("ABSTRACT", &tags)
                .map(|_| ObjectClassType::Abstract)
                .or_else(|| optional_tag("STRUCTURAL", &tags).map(|_| ObjectClassType::Structural))
                .or_else(|| optional_tag("AUXILIARY", &tags).map(|_| ObjectClassType::Auxiliary))
                .unwrap_or(ObjectClassType::Structural),
            must: optional_tag("MUST", &tags)
                .map(|v| v.as_key_string_or_oid_list().unwrap().to_vec())
                .unwrap_or_default(),
            may: optional_tag("MAY", &tags)
                .map(|v| v.as_key_string_or_oid_list().unwrap().to_vec())
                .unwrap_or_default(),
            obsolete: optional_tag("OBSOLETE", &tags).is_some(),
        })
    })
}

/// an entire LDAP schema for an LDAP server
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LDAPSchema {
    /// the supported LDAP syntaxes
    pub ldap_syntaxes: Vec<LDAPSyntax>,
    /// the supported LDAP matching rules
    pub matching_rules: Vec<MatchingRule>,
    /// the allowed uses (attributes) for the LDAP matching rules
    pub matching_rule_use: Vec<MatchingRuleUse>,
    /// the supported LDAP attribute types
    pub attribute_types: Vec<AttributeType>,
    /// the supported LDAP object classes
    pub object_classes: Vec<ObjectClass>,
    // these are not implemented by OpenLDAP to the best of my knowledge
    // pub name_forms: Vec<String>,
    // pub dit_content_rules: Vec<String>,
    // pub dit_structure_rules: Vec<String>,
}

impl LDAPSchema {
    /// return the attribute type if it is present in the schema
    #[cfg(feature = "chumsky")]
    pub fn find_attribute_type<'a>(&'a self, id: &str) -> Option<&'a AttributeType> {
        let match_fn: Box<dyn FnMut(&&AttributeType) -> bool> = match oid_parser().parse(id) {
            Ok(oid) => Box::new(move |at: &&AttributeType| (*at).oid == oid),
            Err(_) => {
                Box::new(move |at: &&AttributeType| (*at).name.contains(&KeyString(id.to_string())))
            }
        };
        self.attribute_types.iter().find(match_fn)
    }

    /// apply the given function to the named attribute type
    /// and all its ancestors in the LDAP schema until one
    /// returns Some
    #[cfg(feature = "chumsky")]
    pub fn find_attribute_type_property<'a, R>(
        &'a self,
        id: &str,
        f: fn(&'a AttributeType) -> Option<&'a R>,
    ) -> Option<&'a R> {
        let attribute_type = self.find_attribute_type(id);
        if let Some(attribute_type) = attribute_type {
            if let Some(r) = f(attribute_type) {
                Some(r)
            } else if let Some(KeyString(sup)) = &attribute_type.sup {
                self.find_attribute_type_property(sup, f)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_ldap_syntax() {
        assert!(ldap_syntax_parser().parse("( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )").is_ok());
    }

    #[test]
    fn test_parse_ldap_syntax_value1() {
        assert_eq!(ldap_syntax_parser().parse("( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )"),
            Ok(LDAPSyntax { oid: "1.3.6.1.4.1.1466.115.121.1.8".to_string().try_into().unwrap(),
                         desc: "Certificate".to_string(),
                         x_binary_transfer_required: true,
                         x_not_human_readable: true,
                       }
            ));
    }

    #[test]
    fn test_parse_ldap_syntax_value2() {
        assert_eq!(ldap_syntax_parser().parse("( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-NOT-HUMAN-READABLE 'TRUE' X-BINARY-TRANSFER-REQUIRED 'TRUE' )"),
            Ok(LDAPSyntax { oid: "1.3.6.1.4.1.1466.115.121.1.8".to_string().try_into().unwrap(),
                         desc: "Certificate".to_string(),
                         x_binary_transfer_required: true,
                         x_not_human_readable: true,
                       }
            ));
    }

    #[test]
    fn test_parse_ldap_syntax_value3() {
        assert_eq!(ldap_syntax_parser().parse("( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' )"),
            Ok(LDAPSyntax { oid: "1.3.6.1.4.1.1466.115.121.1.8".to_string().try_into().unwrap(),
                         desc: "Certificate".to_string(),
                         x_binary_transfer_required: true,
                         x_not_human_readable: false,
                       }
            ));
    }

    #[test]
    fn test_parse_ldap_syntax_value4() {
        assert_eq!(
            ldap_syntax_parser().parse(
                "( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-NOT-HUMAN-READABLE 'TRUE' )"
            ),
            Ok(LDAPSyntax {
                oid: "1.3.6.1.4.1.1466.115.121.1.8"
                    .to_string()
                    .try_into()
                    .unwrap(),
                desc: "Certificate".to_string(),
                x_binary_transfer_required: false,
                x_not_human_readable: true,
            })
        );
    }

    #[test]
    fn test_parse_ldap_syntax_value5() {
        assert_eq!(
            ldap_syntax_parser().parse("( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' )"),
            Ok(LDAPSyntax {
                oid: "1.3.6.1.4.1.1466.115.121.1.8"
                    .to_string()
                    .try_into()
                    .unwrap(),
                desc: "Certificate".to_string(),
                x_binary_transfer_required: false,
                x_not_human_readable: false,
            })
        );
    }

    #[test]
    fn test_parse_ldap_syntax_desc_required() {
        assert!(ldap_syntax_parser()
            .parse("( 1.3.6.1.4.1.1466.115.121.1.8 )")
            .is_err());
    }

    #[test]
    fn test_parse_matching_rule() {
        assert!(matching_rule_parser()
            .parse("( 1.3.6.1.1.16.3 NAME 'UUIDOrderingMatch' SYNTAX 1.3.6.1.1.16.1 )")
            .is_ok());
    }

    #[test]
    fn test_parse_matching_rule_value() {
        assert_eq!(
            matching_rule_parser()
                .parse("( 1.3.6.1.1.16.3 NAME 'UUIDOrderingMatch' SYNTAX 1.3.6.1.1.16.1 )"),
            Ok(MatchingRule {
                oid: "1.3.6.1.1.16.3".to_string().try_into().unwrap(),
                name: vec![KeyString("UUIDOrderingMatch".to_string())],
                syntax: OIDWithLength {
                    oid: "1.3.6.1.1.16.1".to_string().try_into().unwrap(),
                    length: None
                },
            })
        );
    }

    #[test]
    fn test_parse_matching_rule_uses() {
        assert!(matching_rule_use_parser().parse("( 2.5.13.11 NAME 'caseIgnoreListMatch' APPLIES ( postalAddress $ registeredAddress $ homePostalAddress ) )").is_ok());
    }

    #[test]
    fn test_parse_matching_rule_uses_value() {
        assert_eq!(matching_rule_use_parser().parse("( 2.5.13.11 NAME 'caseIgnoreListMatch' APPLIES ( postalAddress $ registeredAddress $ homePostalAddress ) )"),
            Ok(MatchingRuleUse { oid: "2.5.13.11".to_string().try_into().unwrap(),
                                 name: vec![KeyString("caseIgnoreListMatch".to_string())],
                                 applies: vec![KeyStringOrOID::KeyString(KeyString("postalAddress".to_string())),
                                               KeyStringOrOID::KeyString(KeyString("registeredAddress".to_string())),
                                               KeyStringOrOID::KeyString(KeyString("homePostalAddress".to_string()))
                                              ],
            })
        );
    }

    #[test]
    fn test_parse_matching_rule_uses_single_applies_value() {
        assert_eq!(
            matching_rule_use_parser()
                .parse("( 2.5.13.11 NAME 'caseIgnoreListMatch' APPLIES postalAddress )"),
            Ok(MatchingRuleUse {
                oid: "2.5.13.11".to_string().try_into().unwrap(),
                name: vec![KeyString("caseIgnoreListMatch".to_string())],
                applies: vec![KeyStringOrOID::KeyString(KeyString(
                    "postalAddress".to_string()
                ))],
            })
        );
    }
}
