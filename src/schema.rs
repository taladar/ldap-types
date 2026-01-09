//! Contains all the code related to representing and parsing LDAP schemas
//!
//! LDAP Schema is defined in RFC2252 <https://www.rfc-editor.org/rfc/rfc2252.txt>

use std::collections::HashSet;

#[cfg(feature = "chumsky")]
use chumsky::{prelude::*, text::digits};
use educe::Educe;
use enum_as_inner::EnumAsInner;
use oid::ObjectIdentifier;

use itertools::Itertools as _;

#[cfg(feature = "chumsky")]
use std::sync::LazyLock;

use crate::basic::{KeyString, KeyStringOrOID, OIDWithLength};

#[cfg(feature = "chumsky")]
use crate::basic::{
    keystring_or_oid_parser, keystring_parser, oid_parser, quoted_keystring_parser,
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// possible tags in the LDAP schema syntax line
#[cfg(feature = "chumsky")]
static LDAP_SYNTAX_TAGS: LazyLock<Vec<LDAPSchemaTagDescriptor>> = LazyLock::new(|| {
    vec![
        LDAPSchemaTagDescriptor {
            tag_name: "DESC".to_string(),
            tag_type: LDAPSchemaTagType::String,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "X-BINARY-TRANSFER-REQUIRED".to_string(),
            tag_type: LDAPSchemaTagType::Boolean,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "X-NOT-HUMAN-READABLE".to_string(),
            tag_type: LDAPSchemaTagType::Boolean,
        },
    ]
});

/// possible tags in the LDAP schema matching rule line
#[cfg(feature = "chumsky")]
static MATCHING_RULE_TAGS: LazyLock<Vec<LDAPSchemaTagDescriptor>> = LazyLock::new(|| {
    vec![
        LDAPSchemaTagDescriptor {
            tag_name: "NAME".to_string(),
            tag_type: LDAPSchemaTagType::QuotedKeyStringList,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "SYNTAX".to_string(),
            tag_type: LDAPSchemaTagType::OIDWithLength,
        },
    ]
});

/// possible tags in the LDAP schema matching rule use line
#[cfg(feature = "chumsky")]
static MATCHING_RULE_USE_TAGS: LazyLock<Vec<LDAPSchemaTagDescriptor>> = LazyLock::new(|| {
    vec![
        LDAPSchemaTagDescriptor {
            tag_name: "NAME".to_string(),
            tag_type: LDAPSchemaTagType::QuotedKeyStringList,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "APPLIES".to_string(),
            tag_type: LDAPSchemaTagType::KeyStringOrOIDList,
        },
    ]
});

/// possible tags in the LDAP schema attribute type line
#[cfg(feature = "chumsky")]
static ATTRIBUTE_TYPE_TAGS: LazyLock<Vec<LDAPSchemaTagDescriptor>> = LazyLock::new(|| {
    vec![
        LDAPSchemaTagDescriptor {
            tag_name: "NAME".to_string(),
            tag_type: LDAPSchemaTagType::QuotedKeyStringList,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "SUP".to_string(),
            tag_type: LDAPSchemaTagType::KeyString,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "DESC".to_string(),
            tag_type: LDAPSchemaTagType::String,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "SYNTAX".to_string(),
            tag_type: LDAPSchemaTagType::OIDWithLength,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "EQUALITY".to_string(),
            tag_type: LDAPSchemaTagType::KeyString,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "SUBSTR".to_string(),
            tag_type: LDAPSchemaTagType::KeyString,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "ORDERING".to_string(),
            tag_type: LDAPSchemaTagType::KeyString,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "SINGLE-VALUE".to_string(),
            tag_type: LDAPSchemaTagType::Standalone,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "NO-USER-MODIFICATION".to_string(),
            tag_type: LDAPSchemaTagType::Standalone,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "USAGE".to_string(),
            tag_type: LDAPSchemaTagType::KeyString,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "COLLECTIVE".to_string(),
            tag_type: LDAPSchemaTagType::Standalone,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "OBSOLETE".to_string(),
            tag_type: LDAPSchemaTagType::Standalone,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "X-ORDERED".to_string(),
            tag_type: LDAPSchemaTagType::QuotedKeyString,
        },
    ]
});

/// possible tags in the LDAP schema object class line
#[cfg(feature = "chumsky")]
static OBJECT_CLASS_TAGS: LazyLock<Vec<LDAPSchemaTagDescriptor>> = LazyLock::new(|| {
    vec![
        LDAPSchemaTagDescriptor {
            tag_name: "NAME".to_string(),
            tag_type: LDAPSchemaTagType::QuotedKeyStringList,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "SUP".to_string(),
            tag_type: LDAPSchemaTagType::KeyStringOrOIDList,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "DESC".to_string(),
            tag_type: LDAPSchemaTagType::String,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "ABSTRACT".to_string(),
            tag_type: LDAPSchemaTagType::Standalone,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "STRUCTURAL".to_string(),
            tag_type: LDAPSchemaTagType::Standalone,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "AUXILIARY".to_string(),
            tag_type: LDAPSchemaTagType::Standalone,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "MUST".to_string(),
            tag_type: LDAPSchemaTagType::KeyStringOrOIDList,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "MAY".to_string(),
            tag_type: LDAPSchemaTagType::KeyStringOrOIDList,
        },
        LDAPSchemaTagDescriptor {
            tag_name: "OBSOLETE".to_string(),
            tag_type: LDAPSchemaTagType::Standalone,
        },
    ]
});

/// all possible tag names in the LDAP schema
#[cfg(feature = "chumsky")]
static ALL_SCHEMA_TAG_NAMES: LazyLock<HashSet<String>> = LazyLock::new(|| {
    let mut tags = HashSet::new();
    for tag in ATTRIBUTE_TYPE_TAGS.iter() {
        tags.insert(tag.tag_name.to_owned());
    }
    for tag in OBJECT_CLASS_TAGS.iter() {
        tags.insert(tag.tag_name.to_owned());
    }
    for tag in LDAP_SYNTAX_TAGS.iter() {
        tags.insert(tag.tag_name.to_owned());
    }
    for tag in MATCHING_RULE_TAGS.iter() {
        tags.insert(tag.tag_name.to_owned());
    }
    for tag in MATCHING_RULE_USE_TAGS.iter() {
        tags.insert(tag.tag_name.to_owned());
    }
    tags
});

/// stores the parameter values that can appear behind a tag in an LDAP schema entry
#[derive(Clone, Debug, EnumAsInner, Educe)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[educe(PartialEq, Eq, Hash)]
pub enum LDAPSchemaTagValue {
    /// the tag has no value
    Standalone,
    /// the tag has an OID value
    OID(#[educe(Hash(method = "crate::basic::hash_oid"))] ObjectIdentifier),
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
#[derive(PartialEq, Eq, Debug, Hash)]
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
#[derive(PartialEq, Eq, Debug, Hash)]
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
#[derive(PartialEq, Eq, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LDAPSchemaTagDescriptor {
    /// the tag name of the expected tag
    pub tag_name: String,
    /// the type of parameter we expect the tag to have
    pub tag_type: LDAPSchemaTagType,
}

/// this parses the LDAP schema tag value that is described by its parameter
#[cfg(feature = "chumsky")]
pub fn ldap_schema_tag_value_parser<'src>(
    tag_type: &LDAPSchemaTagType,
) -> impl Parser<'src, &'src str, LDAPSchemaTagValue, extra::Err<Rich<'src, char>>> {
    match tag_type {
        LDAPSchemaTagType::Standalone => empty()
            .map(|()| LDAPSchemaTagValue::Standalone)
            .labelled("no value")
            .boxed(),
        LDAPSchemaTagType::OID => oid_parser()
            .map(LDAPSchemaTagValue::OID)
            .labelled("OID")
            .boxed(),
        LDAPSchemaTagType::OIDWithLength => oid_parser()
            .then(
                digits(10)
                    .collect::<String>()
                    .delimited_by(just('{'), just('}'))
                    .try_map(|x, span| {
                        x.parse().map_err(|e| {
                            Rich::custom(
                                span,
                                format!("Failed to convert parsed digits to integer: {e}"),
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
            .collect::<String>()
            .delimited_by(just('\''), just('\''))
            .map(LDAPSchemaTagValue::String)
            .labelled("single-quoted string")
            .boxed(),
        LDAPSchemaTagType::KeyString => keystring_parser()
            .try_map(|ks, span| {
                if ALL_SCHEMA_TAG_NAMES.contains(&ks.0) {
                    return Err(Rich::custom(
                        span,
                        format!("'{}' is a reserved tag name and cannot be used as a KeyString value here", ks.0),
                    ));
                }
                Ok(ks)
            })
            .map(LDAPSchemaTagValue::KeyString)
            .labelled("keystring")
            .boxed(),
        LDAPSchemaTagType::QuotedKeyString => quoted_keystring_parser()
            .map(LDAPSchemaTagValue::QuotedKeyString)
            .labelled("quoted keystring")
            .boxed(),
        LDAPSchemaTagType::KeyStringOrOID => keystring_or_oid_parser()
            .try_map(|ksoid, span| {
                if let KeyStringOrOID::KeyString(ks) = &ksoid {
                    if ALL_SCHEMA_TAG_NAMES.contains(&ks.0) {
                        return Err(Rich::custom(
                            span,
                            format!("'{}' is a reserved tag name and cannot be used as a KeyStringOrOID value here", ks.0),
                        ));
                    }
                }
                Ok(ksoid)
            })
            .map(LDAPSchemaTagValue::KeyStringOrOID)
            .labelled("keystring or OID")
            .boxed(),
        LDAPSchemaTagType::Boolean => just("TRUE")
            .to(true)
            .or(just("FALSE").to(false))
            .delimited_by(just('\''), just('\''))
            .map(LDAPSchemaTagValue::Boolean)
            .labelled("single-quoted uppercase boolean")
            .boxed(),
        LDAPSchemaTagType::KeyStringOrOIDList => keystring_or_oid_parser()
            .padded()
            .separated_by(just('$'))
            .collect()
            .delimited_by(just('('), just(')'))
            .or(keystring_or_oid_parser().map(|x| vec![x]))
            .map(LDAPSchemaTagValue::KeyStringOrOIDList)
            .labelled("list of keystrings or OIDs separated by $")
            .boxed(),
        LDAPSchemaTagType::QuotedKeyStringList => quoted_keystring_parser()
            .padded()
            .repeated()
            .collect()
            .delimited_by(just('('), just(')'))
            .or(quoted_keystring_parser().map(|x| vec![x]))
            .map(LDAPSchemaTagValue::QuotedKeyStringList)
            .labelled("list of quoted keystrings separated by spaces")
            .boxed(),
    }
}

/// this parses an LDAP schema tag described by its parameter
#[cfg(feature = "chumsky")]
#[must_use]
pub fn ldap_schema_tag_parser<'src>(
    tag_descriptor: &'src LDAPSchemaTagDescriptor,
) -> impl Parser<'src, &'src str, LDAPSchemaTag, extra::Err<Rich<'src, char>>> + 'src {
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
///
/// # Panics
///
/// This panics when the tag_descriptors parameter is empty
#[cfg(feature = "chumsky")]
#[must_use]
pub fn ldap_schema_parser<'src>(
    tag_descriptors: &'src [LDAPSchemaTagDescriptor],
) -> impl Parser<'src, &'src str, (ObjectIdentifier, Vec<LDAPSchemaTag>), extra::Err<Rich<'src, char>>>
       + 'src {
    #[expect(
        clippy::expect_used,
        reason = "this fails essentially based on the contents of the tag_descriptors parameter only and chumsky offers no good way to return this type of error"
    )]
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
                .repeated()
                .collect(),
        )
        .padded()
        .delimited_by(just('('), just(')'))
}

/// this is used to extract a required tag's value from the result of [ldap_schema_parser]
///
/// # Errors
///
/// returns an error if the required tag was not found in schema tag list
#[cfg(feature = "chumsky")]
pub fn required_tag<'src>(
    tag_name: &str,
    span: &SimpleSpan,
    tags: &[LDAPSchemaTag],
) -> Result<LDAPSchemaTagValue, Rich<'src, char>> {
    tags.iter()
        .find(|x| x.tag_name == tag_name)
        .ok_or_else(|| {
            Rich::custom(
                *span,
                format!("No {tag_name} tag in parsed LDAP schema tag list"),
            )
        })
        .map(|x| x.tag_value.to_owned())
}

/// this is used to extract an optional tag's value from the result of [ldap_schema_parser]
#[cfg(feature = "chumsky")]
#[must_use]
pub fn optional_tag(tag_name: &str, tags: &[LDAPSchemaTag]) -> Option<LDAPSchemaTagValue> {
    tags.iter()
        .find(|x| x.tag_name == tag_name)
        .map(|x| x.tag_value.to_owned())
}

/// this describes an LDAP syntax schema entry
#[derive(Clone, Educe)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[educe(PartialEq, Eq, Hash)]
pub struct LDAPSyntax {
    /// the OID of the syntax
    #[educe(Hash(method = "crate::basic::hash_oid"))]
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
#[must_use]
pub fn ldap_syntax_parser<'src>(
) -> impl Parser<'src, &'src str, LDAPSyntax, extra::Err<Rich<'src, char>>> {
    ldap_schema_parser(&LDAP_SYNTAX_TAGS).try_map(|(oid, tags), span| {
        Ok(LDAPSyntax {
            oid,
            desc: required_tag("DESC", &span, &tags)?
                .as_string()
                .ok_or_else(|| Rich::custom(span, "DESC parameter should be a string"))?
                .to_string(),
            x_binary_transfer_required: *optional_tag("X-BINARY-TRANSFER-REQUIRED", &tags)
                .unwrap_or(LDAPSchemaTagValue::Boolean(false))
                .as_boolean()
                .ok_or_else(|| {
                    Rich::custom(
                        span,
                        "X-BINARY-TRANSFER_REQUIRED parameter should be a boolean",
                    )
                })?,
            x_not_human_readable: *optional_tag("X-NOT-HUMAN-READABLE", &tags)
                .unwrap_or(LDAPSchemaTagValue::Boolean(false))
                .as_boolean()
                .ok_or_else(|| {
                    Rich::custom(span, "X-NOT_HUMAN_READABLE parameter should be a boolean")
                })?,
        })
    })
}

/// a matching rule LDAP schema entry
///
/// <https://ldapwiki.com/wiki/MatchingRule>
#[derive(Clone, Educe)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[educe(PartialEq, Eq, Hash)]
pub struct MatchingRule {
    /// the matching rule's OID
    #[educe(Hash(method = "crate::basic::hash_oid"))]
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
#[must_use]
pub fn matching_rule_parser<'src>(
) -> impl Parser<'src, &'src str, MatchingRule, extra::Err<Rich<'src, char>>> {
    ldap_schema_parser(&MATCHING_RULE_TAGS).try_map(|(oid, tags), span| {
        Ok(MatchingRule {
            oid,
            name: required_tag("NAME", &span, &tags)?
                .as_quoted_key_string_list()
                .ok_or_else(|| {
                    Rich::custom(span, "NAME parameter should be a quoted keystring list")
                })?
                .to_vec(),
            syntax: required_tag("SYNTAX", &span, &tags)?
                .as_oid_with_length()
                .ok_or_else(|| {
                    Rich::custom(
                        span,
                        "SYNTAX parameter should be an OID with an optional length",
                    )
                })?
                .to_owned(),
        })
    })
}

/// parse a matching rule use LDAP schema entry
///
/// <https://ldapwiki.com/wiki/MatchingRuleUse>
#[derive(Clone, Educe)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[educe(PartialEq, Eq, Hash)]
pub struct MatchingRuleUse {
    /// the OID of the matching rule this applies to
    #[educe(Hash(method = "crate::basic::hash_oid"))]
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
#[must_use]
pub fn matching_rule_use_parser<'src>(
) -> impl Parser<'src, &'src str, MatchingRuleUse, extra::Err<Rich<'src, char>>> {
    ldap_schema_parser(&MATCHING_RULE_USE_TAGS).try_map(|(oid, tags), span| {
        Ok(MatchingRuleUse {
            oid,
            name: required_tag("NAME", &span, &tags)?
                .as_quoted_key_string_list()
                .ok_or_else(|| {
                    Rich::custom(span, "NAME parameter should be a quoted keystring list")
                })?
                .to_vec(),
            applies: required_tag("APPLIES", &span, &tags)?
                .as_key_string_or_oid_list()
                .ok_or_else(|| {
                    Rich::custom(span, "APPLIES parameter should be a keystring or OID list")
                })?
                .to_vec(),
        })
    })
}

/// an attribute type LDAP schema entry
///
/// <https://ldapwiki.com/wiki/AttributeTypes>
#[derive(Clone, Educe)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[educe(PartialEq, Eq, Hash)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "this is the LDAP schema, we can not refactor this easily"
)]
pub struct AttributeType {
    /// the OID of the attribute type
    #[educe(Hash(method = "crate::basic::hash_oid"))]
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
#[must_use]
pub fn attribute_type_parser<'src>(
) -> impl Parser<'src, &'src str, AttributeType, extra::Err<Rich<'src, char>>> {
    ldap_schema_parser(&ATTRIBUTE_TYPE_TAGS).try_map(|(oid, tags), span| {
        Ok(AttributeType {
            oid,
            name: required_tag("NAME", &span, &tags)?
                .as_quoted_key_string_list()
                .ok_or_else(|| {
                    Rich::custom(span, "NAME parameter should be a quoted keystring list")
                })?
                .to_vec(),
            sup: optional_tag("SUP", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_key_string()
                        .map(|val| val.to_owned())
                        .ok_or_else(|| Rich::custom(span, "SUP parameter should be a key string"))
                })
                .transpose()?,
            desc: optional_tag("DESC", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_string()
                        .map(|val| val.to_string())
                        .ok_or_else(|| Rich::custom(span, "DESC parameter should be a string"))
                })
                .transpose()?,
            syntax: optional_tag("SYNTAX", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_oid_with_length()
                        .map(|val| val.to_owned())
                        .ok_or_else(|| {
                            Rich::custom(
                                span,
                                "SYNTAX parameter should be an OID with an optional length",
                            )
                        })
                })
                .transpose()?,
            single_value: optional_tag("SINGLE-VALUE", &tags).is_some(),
            equality: optional_tag("EQUALITY", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_key_string()
                        .map(|val| val.to_owned())
                        .ok_or_else(|| {
                            Rich::custom(span, "EQUALITY parameter should be a key string")
                        })
                })
                .transpose()?,
            substr: optional_tag("SUBSTR", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_key_string()
                        .map(|val| val.to_owned())
                        .ok_or_else(|| {
                            Rich::custom(span, "SUBSTR parameter should be a key string")
                        })
                })
                .transpose()?,
            ordering: optional_tag("ORDERING", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_key_string()
                        .map(|val| val.to_owned())
                        .ok_or_else(|| {
                            Rich::custom(span, "ORDERING parameter should be a key string")
                        })
                })
                .transpose()?,
            no_user_modification: optional_tag("NO-USER-MODIFICATION", &tags).is_some(),
            usage: optional_tag("USAGE", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_key_string()
                        .map(|val| val.to_owned())
                        .ok_or_else(|| Rich::custom(span, "USAGE parameter should be a key string"))
                })
                .transpose()?,
            collective: optional_tag("COLLECTIVE", &tags).is_some(),
            obsolete: optional_tag("OBSOLETE", &tags).is_some(),
            x_ordered: optional_tag("X-ORDERED", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_quoted_key_string()
                        .map(|val| val.to_owned())
                        .ok_or_else(|| {
                            Rich::custom(span, "X-ORDERED parameter should be a quoted key string")
                        })
                })
                .transpose()?,
        })
    })
}

/// type of LDAP object class
#[derive(PartialEq, Eq, Clone, Debug, EnumAsInner, Hash)]
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
#[derive(Clone, Educe)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[educe(PartialEq, Eq, Hash)]
pub struct ObjectClass {
    /// the OID of the object class
    #[educe(Hash(method = "crate::basic::hash_oid"))]
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
#[must_use]
pub fn object_class_parser<'src>(
) -> impl Parser<'src, &'src str, ObjectClass, extra::Err<Rich<'src, char>>> {
    ldap_schema_parser(&OBJECT_CLASS_TAGS).try_map(|(oid, tags), span| {
        Ok(ObjectClass {
            oid,
            name: required_tag("NAME", &span, &tags)?
                .as_quoted_key_string_list()
                .ok_or_else(|| {
                    Rich::custom(span, "NAME parameter should be a quoted keystring list")
                })?
                .to_vec(),
            sup: optional_tag("SUP", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_key_string_or_oid_list()
                        .map(|val| val.to_owned())
                        .ok_or_else(|| {
                            Rich::custom(span, "SUP parameter should be a key string or OID list")
                        })
                })
                .transpose()?
                .unwrap_or_default(),
            desc: optional_tag("DESC", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_string()
                        .map(|val| val.to_string())
                        .ok_or_else(|| Rich::custom(span, "DESC parameter should be a string"))
                })
                .transpose()?,
            object_class_type: optional_tag("ABSTRACT", &tags)
                .map(|_| ObjectClassType::Abstract)
                .or_else(|| optional_tag("STRUCTURAL", &tags).map(|_| ObjectClassType::Structural))
                .or_else(|| optional_tag("AUXILIARY", &tags).map(|_| ObjectClassType::Auxiliary))
                .unwrap_or(ObjectClassType::Structural),
            must: optional_tag("MUST", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_key_string_or_oid_list()
                        .map(|val| val.to_owned())
                        .ok_or_else(|| {
                            Rich::custom(span, "MUST parameter should be a key string or OID list")
                        })
                })
                .transpose()?
                .unwrap_or_default(),
            may: optional_tag("MAY", &tags)
                .map(|tag_value| {
                    tag_value
                        .as_key_string_or_oid_list()
                        .map(|val| val.to_owned())
                        .ok_or_else(|| {
                            Rich::custom(span, "MAY parameter should be a key string or OID list")
                        })
                })
                .transpose()?
                .unwrap_or_default(),
            obsolete: optional_tag("OBSOLETE", &tags).is_some(),
        })
    })
}

/// an entire LDAP schema for an LDAP server
#[derive(Debug, Clone, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[expect(
    clippy::module_name_repetitions,
    reason = "without schema it would just be LDAP which is probably not a good name to use anywhere when working with LDAP"
)]
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
    /// returns the set of allowed attributes (either must or may) for an ObjectClass and all of its super-classes
    pub fn allowed_attributes(
        &self,
        id: impl TryInto<KeyStringOrOID>,
    ) -> Option<HashSet<&AttributeType>> {
        if let Some(object_class) = self.find_object_class(id) {
            let mut result = HashSet::new();
            for attribute_name in object_class.must.iter().chain(object_class.may.iter()) {
                if let Some(attribute) = self.find_attribute_type(attribute_name) {
                    result.insert(attribute);
                }
            }
            for sup in &object_class.sup {
                if let Some(allowed_attributes) = self.allowed_attributes(sup) {
                    result.extend(allowed_attributes);
                }
            }
            Some(result)
        } else {
            None
        }
    }

    /// returns the set of required attributes (must) for an ObjectClass and all of its super-classes
    pub fn required_attributes(
        &self,
        id: impl TryInto<KeyStringOrOID>,
    ) -> Option<HashSet<&AttributeType>> {
        if let Some(object_class) = self.find_object_class(id) {
            let mut result = HashSet::new();
            for attribute_name in &object_class.must {
                if let Some(attribute) = self.find_attribute_type(attribute_name) {
                    result.insert(attribute);
                }
            }
            for sup in &object_class.sup {
                if let Some(required_attributes) = self.required_attributes(sup) {
                    result.extend(required_attributes);
                }
            }
            Some(result)
        } else {
            None
        }
    }

    /// return the object class if it is present in the schema
    pub fn find_object_class(&self, id: impl TryInto<KeyStringOrOID>) -> Option<&ObjectClass> {
        let id: Result<KeyStringOrOID, _> = id.try_into();
        match id {
            Ok(id) => {
                let match_fn: Box<dyn FnMut(&&ObjectClass) -> bool> = match id {
                    KeyStringOrOID::OID(oid) => Box::new(move |at: &&ObjectClass| at.oid == oid),
                    KeyStringOrOID::KeyString(s) => Box::new(move |at: &&ObjectClass| {
                        at.name
                            .iter()
                            .map(|n| n.to_lowercase())
                            .contains(&s.to_lowercase())
                    }),
                };
                self.object_classes.iter().find(match_fn)
            }
            Err(_) => None,
        }
    }

    /// apply the given function to the named object class
    /// and all its ancestors in the LDAP schema until one
    /// returns Some
    pub fn find_object_class_property<'a, R>(
        &'a self,
        id: impl TryInto<KeyStringOrOID>,
        f: fn(&'a ObjectClass) -> Option<&'a R>,
    ) -> Option<&'a R> {
        let object_class = self.find_object_class(id);
        if let Some(object_class) = object_class {
            if let Some(r) = f(object_class) {
                Some(r)
            } else {
                let ks_or_oids = &object_class.sup;
                for ks_or_oid in ks_or_oids {
                    if let Some(r) = self.find_object_class_property(ks_or_oid, f) {
                        return Some(r);
                    }
                }
                None
            }
        } else {
            None
        }
    }

    /// return the attribute type if it is present in the schema
    pub fn find_attribute_type(&self, id: impl TryInto<KeyStringOrOID>) -> Option<&AttributeType> {
        let id: Result<KeyStringOrOID, _> = id.try_into();
        match id {
            Ok(id) => {
                let match_fn: Box<dyn FnMut(&&AttributeType) -> bool> = match id {
                    KeyStringOrOID::OID(oid) => Box::new(move |at: &&AttributeType| at.oid == oid),
                    KeyStringOrOID::KeyString(s) => Box::new(move |at: &&AttributeType| {
                        at.name
                            .iter()
                            .map(|n| n.to_lowercase())
                            .contains(&s.to_lowercase())
                    }),
                };
                self.attribute_types.iter().find(match_fn)
            }
            Err(_) => None,
        }
    }

    /// apply the given function to the named attribute type
    /// and all its ancestors in the LDAP schema until one
    /// returns Some
    pub fn find_attribute_type_property<'a, R>(
        &'a self,
        id: impl TryInto<KeyStringOrOID>,
        f: fn(&'a AttributeType) -> Option<&'a R>,
    ) -> Option<&'a R> {
        let attribute_type = self.find_attribute_type(id);
        if let Some(attribute_type) = attribute_type {
            if let Some(r) = f(attribute_type) {
                Some(r)
            } else if let Some(sup @ KeyString(_)) = &attribute_type.sup {
                self.find_attribute_type_property(KeyStringOrOID::KeyString(sup.to_owned()), f)
            } else {
                None
            }
        } else {
            None
        }
    }

    /// return the ldap syntax if it is present in the schema
    #[cfg(feature = "chumsky")]
    pub fn find_ldap_syntax(&self, id: impl TryInto<ObjectIdentifier>) -> Option<&LDAPSyntax> {
        let id: Result<ObjectIdentifier, _> = id.try_into();
        match id {
            Ok(id) => self
                .ldap_syntaxes
                .iter()
                .find(move |ls: &&LDAPSyntax| ls.oid == id),
            Err(_) => None,
        }
    }

    /// return the matching rule if it is present in the schema
    #[cfg(feature = "chumsky")]
    pub fn find_matching_rule(&self, id: impl TryInto<ObjectIdentifier>) -> Option<&MatchingRule> {
        let id: Result<ObjectIdentifier, _> = id.try_into();
        match id {
            Ok(id) => self
                .matching_rules
                .iter()
                .find(move |ls: &&MatchingRule| ls.oid == id),
            Err(_) => None,
        }
    }

    /// return the matching rule use if it is present in the schema
    #[cfg(feature = "chumsky")]
    pub fn find_matching_rule_use(
        &self,
        id: impl TryInto<ObjectIdentifier>,
    ) -> Option<&MatchingRuleUse> {
        let id: Result<ObjectIdentifier, _> = id.try_into();
        match id {
            Ok(id) => self
                .matching_rule_use
                .iter()
                .find(move |ls: &&MatchingRuleUse| ls.oid == id),
            Err(_) => None,
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "In tests it is okay to fail using expect"
)]
mod test {
    #[cfg(feature = "chumsky")]
    use super::*;
    #[cfg(feature = "chumsky")]
    use crate::basic::ChumskyError;

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_ldap_syntax() {
        #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
        ldap_syntax_parser().parse("( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )").into_result().unwrap();
    }

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_ldap_syntax_value1() {
        assert_eq!(ldap_syntax_parser().parse("( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' X-NOT-HUMAN-READABLE 'TRUE' )").into_result(),
            Ok(LDAPSyntax {
                #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                oid: "1.3.6.1.4.1.1466.115.121.1.8".to_string().try_into().unwrap(),
                         desc: "Certificate".to_string(),
                         x_binary_transfer_required: true,
                         x_not_human_readable: true,
                       }
            ));
    }

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_ldap_syntax_value2() {
        assert_eq!(ldap_syntax_parser().parse("( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-NOT-HUMAN-READABLE 'TRUE' X-BINARY-TRANSFER-REQUIRED 'TRUE' )").into_result(),
            Ok(LDAPSyntax {
                #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                oid: "1.3.6.1.4.1.1466.115.121.1.8".to_string().try_into().unwrap(),
                         desc: "Certificate".to_string(),
                         x_binary_transfer_required: true,
                         x_not_human_readable: true,
                       }
            ));
    }

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_ldap_syntax_value3() {
        assert_eq!(ldap_syntax_parser().parse("( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-BINARY-TRANSFER-REQUIRED 'TRUE' )").into_result(),
            Ok(LDAPSyntax {
                #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                oid: "1.3.6.1.4.1.1466.115.121.1.8".to_string().try_into().unwrap(),
                         desc: "Certificate".to_string(),
                         x_binary_transfer_required: true,
                         x_not_human_readable: false,
                       }
            ));
    }

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_ldap_syntax_value4() {
        assert_eq!(
            ldap_syntax_parser().parse(
                "( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' X-NOT-HUMAN-READABLE 'TRUE' )"
            ).into_result(),
            Ok(LDAPSyntax {
                #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
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

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_ldap_syntax_value5() {
        assert_eq!(
            ldap_syntax_parser()
                .parse("( 1.3.6.1.4.1.1466.115.121.1.8 DESC 'Certificate' )")
                .into_result(),
            Ok(LDAPSyntax {
                #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
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

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_ldap_syntax_desc_required() {
        #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
        ldap_syntax_parser()
            .parse("( 1.3.6.1.4.1.1466.115.121.1.8 )")
            .into_result()
            .unwrap_err();
    }

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_matching_rule() {
        #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
        matching_rule_parser()
            .parse("( 1.3.6.1.1.16.3 NAME 'UUIDOrderingMatch' SYNTAX 1.3.6.1.1.16.1 )")
            .into_result()
            .unwrap();
    }

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_matching_rule_value() {
        assert_eq!(
            matching_rule_parser()
                .parse("( 1.3.6.1.1.16.3 NAME 'UUIDOrderingMatch' SYNTAX 1.3.6.1.1.16.1 )")
                .into_result(),
            Ok(MatchingRule {
                #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                oid: "1.3.6.1.1.16.3".to_string().try_into().unwrap(),
                name: vec![KeyString("UUIDOrderingMatch".to_string())],
                syntax: OIDWithLength {
                    #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                    oid: "1.3.6.1.1.16.1".to_string().try_into().unwrap(),
                    length: None
                },
            })
        );
    }

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_matching_rule_uses() {
        #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
        matching_rule_use_parser().parse("( 2.5.13.11 NAME 'caseIgnoreListMatch' APPLIES ( postalAddress $ registeredAddress $ homePostalAddress ) )").into_result().unwrap();
    }

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_matching_rule_uses_value() {
        assert_eq!(matching_rule_use_parser().parse("( 2.5.13.11 NAME 'caseIgnoreListMatch' APPLIES ( postalAddress $ registeredAddress $ homePostalAddress ) )").into_result(),
            Ok(MatchingRuleUse {
                #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                oid: "2.5.13.11".to_string().try_into().unwrap(),
                                 name: vec![KeyString("caseIgnoreListMatch".to_string())],
                                 applies: vec![KeyStringOrOID::KeyString(KeyString("postalAddress".to_string())),
                                               KeyStringOrOID::KeyString(KeyString("registeredAddress".to_string())),
                                               KeyStringOrOID::KeyString(KeyString("homePostalAddress".to_string()))
                                              ],
            })
        );
    }

    #[cfg(feature = "chumsky")]
    #[test]
    fn test_parse_matching_rule_uses_single_applies_value() {
        assert_eq!(
            matching_rule_use_parser()
                .parse("( 2.5.13.11 NAME 'caseIgnoreListMatch' APPLIES postalAddress )")
                .into_result(),
            Ok(MatchingRuleUse {
                #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                oid: "2.5.13.11".to_string().try_into().unwrap(),
                name: vec![KeyString("caseIgnoreListMatch".to_string())],
                applies: vec![KeyStringOrOID::KeyString(KeyString(
                    "postalAddress".to_string()
                ))],
            })
        );
    }

    mod attribute_type_parser_tests {
        use super::*;

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_sup_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.sup.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_sup_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' SUP 'invalid value with spaces' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_sup_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' SUP DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_sup_correct() {
            let schema_str = "( 1.2.3 NAME 'test' SUP someKeyString DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(attr_type.sup, Some(KeyString("someKeyString".to_string())));
        }

        // Test cases for 'DESC'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_desc_missing() {
            let schema_str = "( 1.2.3 NAME 'test' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.desc.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_desc_wrong_type() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC unquoted String SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected single-quoted string"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected single-quoted string'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_desc_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' DESC SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected single-quoted string"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected single-quoted string'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_desc_correct() {
            let schema_str = "( 1.2.3 NAME 'test' DESC 'Some description' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(attr_type.desc, Some("Some description".to_string()));
        }

        // Test cases for 'SYNTAX'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_syntax_missing() {
            let schema_str = "( 1.2.3 NAME 'test' DESC 'Test Attribute' )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.syntax.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_syntax_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' SYNTAX 'not an OID' DESC 'Test Attribute' )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected OID with optional length"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected OID with optional length'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_syntax_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' SYNTAX DESC 'Test Attribute' )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected OID with optional length"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected OID with optional length'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_syntax_correct_with_length() {
            let schema_str = "( 1.2.3 NAME 'test' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{255} DESC 'Test Attribute' )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.syntax,
                Some(OIDWithLength {
                    #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                    oid: "1.3.6.1.4.1.1466.115.121.1.15"
                        .to_string()
                        .try_into()
                        .unwrap(),
                    length: Some(255)
                })
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_syntax_correct_without_length() {
            let schema_str =
                "( 1.2.3 NAME 'test' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Test Attribute' )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.syntax,
                Some(OIDWithLength {
                    #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                    oid: "1.3.6.1.4.1.1466.115.121.1.15"
                        .to_string()
                        .try_into()
                        .unwrap(),
                    length: None
                })
            );
        }

        // Test cases for 'SINGLE-VALUE'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_single_value_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(!attr_type.single_value);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_single_value_present() {
            let schema_str = "( 1.2.3 NAME 'test' SINGLE-VALUE DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.single_value);
        }

        // Test cases for 'EQUALITY'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_equality_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.equality.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_equality_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' EQUALITY 'invalid equality with spaces' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_equality_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' EQUALITY DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_equality_correct() {
            let schema_str = "( 1.2.3 NAME 'test' EQUALITY caseIgnoreMatch DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.equality,
                Some(KeyString("caseIgnoreMatch".to_string()))
            );
        }

        // Test cases for 'SUBSTR'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_substr_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.substr.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_substr_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' SUBSTR 'invalid substr with spaces' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_substr_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' SUBSTR DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_substr_correct() {
            let schema_str = "( 1.2.3 NAME 'test' SUBSTR caseIgnoreSubstringsMatch DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.substr,
                Some(KeyString("caseIgnoreSubstringsMatch".to_string()))
            );
        }

        // Test cases for 'ORDERING'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_ordering_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.ordering.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_ordering_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' ORDERING 'invalid ordering with spaces' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_ordering_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' ORDERING DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_ordering_correct() {
            let schema_str = "( 1.2.3 NAME 'test' ORDERING caseIgnoreOrderingMatch DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.ordering,
                Some(KeyString("caseIgnoreOrderingMatch".to_string()))
            );
        }

        // Test cases for 'NO-USER-MODIFICATION'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_no_user_modification_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(!attr_type.no_user_modification);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_no_user_modification_present() {
            let schema_str = "( 1.2.3 NAME 'test' NO-USER-MODIFICATION DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.no_user_modification);
        }

        // Test cases for 'USAGE'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_usage_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.usage.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_usage_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' USAGE 'invalid usage with spaces' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_usage_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' USAGE DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_usage_correct() {
            let schema_str = "( 1.2.3 NAME 'test' USAGE userApplications DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.usage,
                Some(KeyString("userApplications".to_string()))
            );
        }

        // Test cases for 'COLLECTIVE'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_collective_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(!attr_type.collective);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_collective_present() {
            let schema_str = "( 1.2.3 NAME 'test' COLLECTIVE DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.collective);
        }

        // Test cases for 'OBSOLETE'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_obsolete_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(!attr_type.obsolete);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_obsolete_present() {
            let schema_str = "( 1.2.3 NAME 'test' OBSOLETE DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.obsolete);
        }

        // Test cases for 'X-ORDERED'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_x_ordered_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.x_ordered.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_x_ordered_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' X-ORDERED unquotedString DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected quoted keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected quoted keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_x_ordered_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' X-ORDERED DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected quoted keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected quoted keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_x_ordered_correct() {
            let schema_str = "( 1.2.3 NAME 'test' X-ORDERED 'values' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(attr_type.x_ordered, Some(KeyString("values".to_string())));
        }
    }

    mod object_class_parser_tests {
        use super::*;

        // Test cases for 'SUP'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_sup_missing() {
            let schema_str = "( 1.2.3 NAME 'testOC' MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(object_class.sup.is_empty());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_sup_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'testOC' SUP 'invalid value with spaces' MUST attr1 )";
            let result = object_class_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "object class".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected list of keystrings or OIDs separated by $"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected list of keystrings or OIDs separated by $'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_sup_missing_param() {
            let schema_str = "( 1.2.3 NAME 'testOC' SUP MUST attr1 )";
            let result = object_class_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "object class".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected 'N', 'S', 'D', 'A', 'M', 'O', ')'"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected 'N', 'S', 'D', 'A', 'M', 'O', ')''",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_sup_correct_single() {
            let schema_str = "( 1.2.3 NAME 'testOC' SUP top MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                object_class.sup,
                vec![KeyStringOrOID::KeyString(KeyString("top".to_string()))]
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_sup_correct_list() {
            let schema_str = "( 1.2.3 NAME 'testOC' SUP ( top $ person ) MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                object_class.sup,
                vec![
                    KeyStringOrOID::KeyString(KeyString("top".to_string())),
                    KeyStringOrOID::KeyString(KeyString("person".to_string()))
                ]
            );
        }

        // Test cases for 'DESC'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_desc_missing() {
            let schema_str = "( 1.2.3 NAME 'testOC' MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(object_class.desc.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_desc_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'testOC' DESC unquoted String MUST attr1 )";
            let result = object_class_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "object class".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected single-quoted string"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected single-quoted string'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_desc_missing_param() {
            let schema_str = "( 1.2.3 NAME 'testOC' DESC MUST attr1 )";
            let result = object_class_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "object class".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected single-quoted string"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected single-quoted string'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_desc_correct() {
            let schema_str = "( 1.2.3 NAME 'testOC' DESC 'Some description' MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(object_class.desc, Some("Some description".to_string()));
        }

        // Test cases for 'object_class_type' (ABSTRACT, STRUCTURAL, AUXILIARY)
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_type_abstract_present() {
            let schema_str = "( 1.2.3 NAME 'testOC' ABSTRACT MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(object_class.object_class_type, ObjectClassType::Abstract);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_type_structural_present() {
            let schema_str = "( 1.2.3 NAME 'testOC' STRUCTURAL MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(object_class.object_class_type, ObjectClassType::Structural);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_type_auxiliary_present() {
            let schema_str = "( 1.2.3 NAME 'testOC' AUXILIARY MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(object_class.object_class_type, ObjectClassType::Auxiliary);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_type_default_structural() {
            let schema_str = "( 1.2.3 NAME 'testOC' MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(object_class.object_class_type, ObjectClassType::Structural);
        }

        // Test for multiple type tags - parser should pick the first encountered.
        // In OBJECT_CLASS_TAGS, ABSTRACT is before STRUCTURAL and AUXILIARY.
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_type_multiple_tags_abstract_first() {
            let schema_str = "( 1.2.3 NAME 'testOC' ABSTRACT STRUCTURAL MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(object_class.object_class_type, ObjectClassType::Abstract);
        }

        // Test for multiple type tags - if STRUCTURAL is encountered first.
        // This scenario might not be easily parsable with current ldap_schema_parser due to fixed order in OBJECT_CLASS_TAGS.
        // But if it were possible to define `STRUCTURAL` before `ABSTRACT`, this test would be relevant.
        // For now, let's assume the parser handles input as defined in OBJECT_CLASS_TAGS.
        // This test case is more about understanding parsing behavior rather than "error" of multiple tags.
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_type_multiple_tags_structural_first_if_possible() {
            // Note: Due to fixed order of OBJECT_CLASS_TAGS, ABSTRACT is always parsed before STRUCTURAL.
            // This test is conceptual unless OBJECT_CLASS_TAGS order can be dynamic or input order matters for tag parsing in ldap_schema_parser.
            // Based on `object_class_parser`'s `or_else` chain, the first one found wins.
            // The actual input string for parsing doesn't necessarily enforce order, but the `ldap_schema_parser` picks based on its internal `fold` order.
            // The `fold` processes tags in the order they appear in `tag_descriptors`.
            // So if STRUCTURAL appears before ABSTRACT in the input string, the ldap_schema_parser should still pick ABSTRACT if it's listed earlier in OBJECT_CLASS_TAGS.
            // Let's create an input where STRUCTURAL comes first to see if the `or_else` chain correctly picks based on tag definition order.
            // However, the `ldap_schema_parser` gets a list of tags and can find them in any order in the input. The `or_else` in the `object_class_parser` logic will then apply a preference.

            // The OBJECT_CLASS_TAGS is defined as:
            // ABSTRACT, STRUCTURAL, AUXILIARY
            // So, ABSTRACT will always be checked first by `object_class_type` logic if present.
            // If the input string has STRUCTURAL before ABSTRACT, but ABSTRACT is still found by `ldap_schema_parser` as one of the `tags`,
            // then `optional_tag("ABSTRACT", &tags)` will return Some, and the `or_else` chain will stop there.

            // So a test where STRUCTURAL is *picked* over ABSTRACT when both are present in the *input* string,
            // would require STRUCTURAL to be defined earlier in OBJECT_CLASS_TAGS or a different parsing strategy.
            // For now, we'll confirm that if STRUCTURAL is the only one, it's picked.
            // The previous `test_object_class_type_structural_present` already covers this.

            // Re-evaluating `test_object_class_type_multiple_tags_abstract_first`, if `STRUCTURAL` were to appear before `ABSTRACT` in `OBJECT_CLASS_TAGS`,
            // this test would be crucial. For now, given the fixed tag order, I will test the documented behavior.

            let schema_str = "( 1.2.3 NAME 'testOC' STRUCTURAL ABSTRACT MUST attr1 )"; // STRUCTURAL appears first in input
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            // Due to `OBJECT_CLASS_TAGS` definition order and `or_else` chain, ABSTRACT takes precedence if both are present in the `tags` list.
            assert_eq!(object_class.object_class_type, ObjectClassType::Abstract);
        }

        // Test cases for 'MUST'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_must_missing() {
            let schema_str = "( 1.2.3 NAME 'testOC' MAY attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(object_class.must.is_empty());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_must_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'testOC' MUST 'invalid value with spaces' MAY attr1 )";
            let result = object_class_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "object class".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected list of keystrings or OIDs separated by $"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected list of keystrings or OIDs separated by $'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_must_missing_param() {
            let schema_str = "( 1.2.3 NAME 'testOC' MUST MAY attr1 )";
            let result = object_class_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "object class".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected 'N', 'S', 'D', 'A', 'M', 'O', ')'"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected 'N', 'S', 'D', 'A', 'M', 'O', ')''",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_must_correct_single() {
            let schema_str = "( 1.2.3 NAME 'testOC' MUST cn MAY attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                object_class.must,
                vec![KeyStringOrOID::KeyString(KeyString("cn".to_string()))]
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_must_correct_list() {
            let schema_str = "( 1.2.3 NAME 'testOC' MUST ( cn $ sn ) MAY attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                object_class.must,
                vec![
                    KeyStringOrOID::KeyString(KeyString("cn".to_string())),
                    KeyStringOrOID::KeyString(KeyString("sn".to_string()))
                ]
            );
        }

        // Test cases for 'MAY'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_may_missing() {
            let schema_str = "( 1.2.3 NAME 'testOC' MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(object_class.may.is_empty());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_may_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'testOC' MAY 'invalid value with spaces' MUST attr1 )";
            let result = object_class_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "object class".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected list of keystrings or OIDs separated by $"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected list of keystrings or OIDs separated by $'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_may_missing_param() {
            let schema_str = "( 1.2.3 NAME 'testOC' MAY MUST attr1 )";
            let result = object_class_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "object class".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected 'N', 'S', 'D', 'A', 'M', 'O', ')'"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected 'N', 'S', 'D', 'A', 'M', 'O', ')''",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_may_correct_single() {
            let schema_str = "( 1.2.3 NAME 'testOC' MAY description MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                object_class.may,
                vec![KeyStringOrOID::KeyString(KeyString(
                    "description".to_string()
                ))]
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_may_correct_list() {
            let schema_str = "( 1.2.3 NAME 'testOC' MAY ( description $ seeAlso ) MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                object_class.may,
                vec![
                    KeyStringOrOID::KeyString(KeyString("description".to_string())),
                    KeyStringOrOID::KeyString(KeyString("seeAlso".to_string()))
                ]
            );
        }

        // Test cases for 'OBSOLETE'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_obsolete_missing() {
            let schema_str = "( 1.2.3 NAME 'testOC' MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(!object_class.obsolete);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_object_class_obsolete_present() {
            let schema_str = "( 1.2.3 NAME 'testOC' OBSOLETE MUST attr1 )";
            let object_class = object_class_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(object_class.obsolete);
        }

        // Test cases for 'DESC'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_desc_missing() {
            let schema_str = "( 1.2.3 NAME 'test' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.desc.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_desc_wrong_type() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC unquoted String SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected single-quoted string"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected single-quoted string'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_desc_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' DESC SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected single-quoted string"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected single-quoted string'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_desc_correct() {
            let schema_str = "( 1.2.3 NAME 'test' DESC 'Some description' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(attr_type.desc, Some("Some description".to_string()));
        }

        // Test cases for 'SYNTAX'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_syntax_missing() {
            let schema_str = "( 1.2.3 NAME 'test' DESC 'Test Attribute' )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.syntax.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_syntax_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' SYNTAX 'not an OID' DESC 'Test Attribute' )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected OID with optional length"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected OID with optional length'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_syntax_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' SYNTAX DESC 'Test Attribute' )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected OID with optional length"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected OID with optional length'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_syntax_correct_with_length() {
            let schema_str = "( 1.2.3 NAME 'test' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{255} DESC 'Test Attribute' )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.syntax,
                Some(OIDWithLength {
                    #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                    oid: "1.3.6.1.4.1.1466.115.121.1.15"
                        .to_string()
                        .try_into()
                        .unwrap(),
                    length: Some(255)
                })
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_syntax_correct_without_length() {
            let schema_str =
                "( 1.2.3 NAME 'test' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Test Attribute' )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.syntax,
                Some(OIDWithLength {
                    #[expect(clippy::unwrap_used, reason = "just a literal parse in a test")]
                    oid: "1.3.6.1.4.1.1466.115.121.1.15"
                        .to_string()
                        .try_into()
                        .unwrap(),
                    length: None
                })
            );
        }

        // Test cases for 'SINGLE-VALUE'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_single_value_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(!attr_type.single_value);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_single_value_present() {
            let schema_str = "( 1.2.3 NAME 'test' SINGLE-VALUE DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.single_value);
        }

        // Test cases for 'EQUALITY'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_equality_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.equality.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_equality_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' EQUALITY 'invalid equality with spaces' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_equality_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' EQUALITY DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_equality_correct() {
            let schema_str = "( 1.2.3 NAME 'test' EQUALITY caseIgnoreMatch DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.equality,
                Some(KeyString("caseIgnoreMatch".to_string()))
            );
        }

        // Test cases for 'SUBSTR'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_substr_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.substr.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_substr_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' SUBSTR 'invalid substr with spaces' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_substr_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' SUBSTR DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_substr_correct() {
            let schema_str = "( 1.2.3 NAME 'test' SUBSTR caseIgnoreSubstringsMatch DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.substr,
                Some(KeyString("caseIgnoreSubstringsMatch".to_string()))
            );
        }

        // Test cases for 'ORDERING'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_ordering_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.ordering.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_ordering_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' ORDERING 'invalid ordering with spaces' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_ordering_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' ORDERING DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_ordering_correct() {
            let schema_str = "( 1.2.3 NAME 'test' ORDERING caseIgnoreOrderingMatch DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.ordering,
                Some(KeyString("caseIgnoreOrderingMatch".to_string()))
            );
        }

        // Test cases for 'NO-USER-MODIFICATION'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_no_user_modification_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(!attr_type.no_user_modification);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_no_user_modification_present() {
            let schema_str = "( 1.2.3 NAME 'test' NO-USER-MODIFICATION DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.no_user_modification);
        }

        // Test cases for 'USAGE'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_usage_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.usage.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_usage_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' USAGE 'invalid usage with spaces' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_usage_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' USAGE DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected end of input while parsing [], expected keystring"),
                "Error string '{err_string}' does not contain 'Unexpected end of input while parsing [], expected keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_usage_correct() {
            let schema_str = "( 1.2.3 NAME 'test' USAGE userApplications DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(
                attr_type.usage,
                Some(KeyString("userApplications".to_string()))
            );
        }

        // Test cases for 'COLLECTIVE'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_collective_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(!attr_type.collective);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_collective_present() {
            let schema_str = "( 1.2.3 NAME 'test' COLLECTIVE DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.collective);
        }

        // Test cases for 'OBSOLETE'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_obsolete_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(!attr_type.obsolete);
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_obsolete_present() {
            let schema_str = "( 1.2.3 NAME 'test' OBSOLETE DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.obsolete);
        }

        // Test cases for 'X-ORDERED'
        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_x_ordered_missing() {
            let schema_str =
                "( 1.2.3 NAME 'test' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert!(attr_type.x_ordered.is_none());
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_x_ordered_wrong_type() {
            let schema_str = "( 1.2.3 NAME 'test' X-ORDERED unquotedString DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected quoted keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected quoted keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_x_ordered_missing_param() {
            let schema_str = "( 1.2.3 NAME 'test' X-ORDERED DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let result = attribute_type_parser().parse(schema_str).into_result();
            #[expect(clippy::unwrap_used, reason = "intentional for assertion")]
            let err = result.unwrap_err();
            let err_string = format!(
                "{}",
                ChumskyError {
                    description: "attribute type".to_string(),
                    source: schema_str.to_string(),
                    errors: err.into_iter().map(|e| e.into_owned()).collect(),
                }
            );
            assert!(
                err_string.contains("Unexpected token while parsing [], expected quoted keystring"),
                "Error string '{err_string}' does not contain 'Unexpected token while parsing [], expected quoted keystring'",
            );
        }

        #[cfg(feature = "chumsky")]
        #[test]
        fn test_attribute_type_x_ordered_correct() {
            let schema_str = "( 1.2.3 NAME 'test' X-ORDERED 'values' DESC 'Test Attribute' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )";
            let attr_type = attribute_type_parser()
                .parse(schema_str)
                .into_result()
                .expect("Parsing failed");
            assert_eq!(attr_type.x_ordered, Some(KeyString("values".to_string())));
        }
    }
}
