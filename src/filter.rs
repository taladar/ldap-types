//! Contains all the code related to representing and parsing LDAP search filters

#[cfg(feature = "chumsky")]
use chumsky::prelude::*;

#[cfg(feature = "chumsky")]
use lazy_static::lazy_static;
#[cfg(feature = "chumsky")]
use oid::ObjectIdentifier;

#[cfg(feature = "chumsky")]
use crate::basic::keystring_or_oid_parser;
use crate::basic::KeyStringOrOID;
#[cfg(feature = "chumsky")]
use crate::basic::OIDWithLength;
#[cfg(feature = "chumsky")]
use crate::schema::LDAPSchema;

/// represents an LDAP search filter
///
/// this crate does not support extended matches at this time
///
/// <https://datatracker.ietf.org/doc/html/rfc2254#section-4>
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LDAPSearchFilter {
    /// a boolean and operation applied to all the sub-filters
    And(Vec<LDAPSearchFilter>),
    /// a boolean or operation applied to all the sub-filters
    Or(Vec<LDAPSearchFilter>),
    /// a boolean not operation applied to the sub-filter
    Not(Box<LDAPSearchFilter>),
    /// an equality match on the given attribute name and value
    Equal {
        /// attribute name or OID
        attribute_name: KeyStringOrOID,
        /// attribute value
        attribute_value: String,
    },
    /// an approximate match on the given attribute name and value
    ///
    /// <https://ldapwiki.com/wiki/ApproxMatch>
    Approx {
        /// attribute name or OID
        attribute_name: KeyStringOrOID,
        /// attribute value
        attribute_value: String,
    },
    /// a greater or equal match on the given attribute name and value
    Greater {
        /// attribute name or OID
        attribute_name: KeyStringOrOID,
        /// attribute value
        attribute_value: String,
    },
    /// a less or equal match on the given attribute name and value
    Less {
        /// attribute name or OID
        attribute_name: KeyStringOrOID,
        /// attribute value
        attribute_value: String,
    },
    /// checks for presence of the given attribute
    Present {
        /// attribute name or OID
        attribute_name: KeyStringOrOID,
    },
    /// a substring match on the given attribute name and value
    Substring {
        /// attribute name or OID
        attribute_name: KeyStringOrOID,
        /// attribute value
        attribute_value: String,
    },
}

impl LDAPSearchFilter {
    /// using the schema this method transforms the base DN of all DN-valued attributes
    /// from the source_base_dn to the destination_base_dn
    ///
    /// this is useful e.g. when comparing LDAP objects from different directories
    /// with different namingContext values
    #[cfg(feature = "chumsky")]
    pub fn transform_base_dns(
        &self,
        source_base_dn: &str,
        destination_base_dn: &str,
        source_ldap_schema: &LDAPSchema,
    ) -> Self {
        lazy_static! {
            static ref DN_SYNTAX_OID: OIDWithLength = OIDWithLength {
                oid: ObjectIdentifier::try_from("1.3.6.1.4.1.1466.115.121.1.12").unwrap(),
                length: None
            };
        }
        match self {
            Self::And(filters) => Self::And(
                filters
                    .iter()
                    .map(|f| {
                        f.transform_base_dns(
                            source_base_dn,
                            destination_base_dn,
                            source_ldap_schema,
                        )
                    })
                    .collect(),
            ),
            Self::Or(filters) => Self::Or(
                filters
                    .iter()
                    .map(|f| {
                        f.transform_base_dns(
                            source_base_dn,
                            destination_base_dn,
                            source_ldap_schema,
                        )
                    })
                    .collect(),
            ),
            Self::Not(filter) => Self::Not(Box::new(filter.transform_base_dns(
                source_base_dn,
                destination_base_dn,
                source_ldap_schema,
            ))),
            Self::Equal {
                attribute_name,
                attribute_value,
            } => {
                if let Some(syntax) = source_ldap_schema
                    .find_attribute_type_property(&attribute_name.to_string(), |at| {
                        at.syntax.as_ref()
                    })
                {
                    if DN_SYNTAX_OID.eq(syntax) {
                        Self::Equal {
                            attribute_name: attribute_name.clone(),
                            attribute_value: attribute_value
                                .replace(source_base_dn, destination_base_dn),
                        }
                    } else {
                        (*self).clone()
                    }
                } else {
                    (*self).clone()
                }
            }
            Self::Approx {
                attribute_name,
                attribute_value,
            } => {
                if let Some(syntax) = source_ldap_schema
                    .find_attribute_type_property(&attribute_name.to_string(), |at| {
                        at.syntax.as_ref()
                    })
                {
                    if DN_SYNTAX_OID.eq(syntax) {
                        Self::Approx {
                            attribute_name: attribute_name.clone(),
                            attribute_value: attribute_value
                                .replace(source_base_dn, destination_base_dn),
                        }
                    } else {
                        (*self).clone()
                    }
                } else {
                    (*self).clone()
                }
            }
            Self::Greater {
                attribute_name,
                attribute_value,
            } => {
                if let Some(syntax) = source_ldap_schema
                    .find_attribute_type_property(&attribute_name.to_string(), |at| {
                        at.syntax.as_ref()
                    })
                {
                    if DN_SYNTAX_OID.eq(syntax) {
                        Self::Greater {
                            attribute_name: attribute_name.clone(),
                            attribute_value: attribute_value
                                .replace(source_base_dn, destination_base_dn),
                        }
                    } else {
                        (*self).clone()
                    }
                } else {
                    (*self).clone()
                }
            }
            Self::Less {
                attribute_name,
                attribute_value,
            } => {
                if let Some(syntax) = source_ldap_schema
                    .find_attribute_type_property(&attribute_name.to_string(), |at| {
                        at.syntax.as_ref()
                    })
                {
                    if DN_SYNTAX_OID.eq(syntax) {
                        Self::Less {
                            attribute_name: attribute_name.clone(),
                            attribute_value: attribute_value
                                .replace(source_base_dn, destination_base_dn),
                        }
                    } else {
                        (*self).clone()
                    }
                } else {
                    (*self).clone()
                }
            }
            Self::Present { attribute_name } => Self::Present {
                attribute_name: attribute_name.clone(),
            },
            Self::Substring {
                attribute_name,
                attribute_value,
            } => {
                if let Some(syntax) = source_ldap_schema
                    .find_attribute_type_property(&attribute_name.to_string(), |at| {
                        at.syntax.as_ref()
                    })
                {
                    if DN_SYNTAX_OID.eq(syntax) {
                        Self::Substring {
                            attribute_name: attribute_name.clone(),
                            attribute_value: attribute_value
                                .replace(source_base_dn, destination_base_dn),
                        }
                    } else {
                        (*self).clone()
                    }
                } else {
                    (*self).clone()
                }
            }
        }
    }
}

impl std::fmt::Display for LDAPSearchFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match &self {
            Self::And(filters) => {
                write!(f, "(&")?;
                for filter in filters {
                    std::fmt::Display::fmt(&filter, f)?;
                }
                write!(f, ")")?;
                Ok(())
            }
            Self::Or(filters) => {
                write!(f, "(|")?;
                for filter in filters {
                    std::fmt::Display::fmt(&filter, f)?;
                }
                write!(f, ")")?;
                Ok(())
            }
            Self::Not(filter) => {
                write!(f, "(!")?;
                std::fmt::Display::fmt(&filter, f)?;
                write!(f, ")")?;
                Ok(())
            }
            Self::Equal {
                attribute_name,
                attribute_value,
            } => {
                write!(f, "(")?;
                std::fmt::Display::fmt(&attribute_name, f)?;
                write!(f, "=")?;
                std::fmt::Display::fmt(&attribute_value, f)?;
                write!(f, ")")?;
                Ok(())
            }
            Self::Approx {
                attribute_name,
                attribute_value,
            } => {
                write!(f, "(")?;
                std::fmt::Display::fmt(&attribute_name, f)?;
                write!(f, "=~")?;
                std::fmt::Display::fmt(&attribute_value, f)?;
                write!(f, ")")?;
                Ok(())
            }
            Self::Greater {
                attribute_name,
                attribute_value,
            } => {
                write!(f, "(")?;
                std::fmt::Display::fmt(&attribute_name, f)?;
                write!(f, ">=")?;
                std::fmt::Display::fmt(&attribute_value, f)?;
                write!(f, ")")?;
                Ok(())
            }
            Self::Less {
                attribute_name,
                attribute_value,
            } => {
                write!(f, "(")?;
                std::fmt::Display::fmt(&attribute_name, f)?;
                write!(f, "<=")?;
                std::fmt::Display::fmt(&attribute_value, f)?;
                write!(f, ")")?;
                Ok(())
            }
            Self::Present { attribute_name } => {
                write!(f, "(")?;
                std::fmt::Display::fmt(&attribute_name, f)?;
                write!(f, "=*)")?;
                Ok(())
            }
            Self::Substring {
                attribute_name,
                attribute_value,
            } => {
                write!(f, "(")?;
                std::fmt::Display::fmt(&attribute_name, f)?;
                write!(f, "=")?;
                std::fmt::Display::fmt(&attribute_value, f)?;
                write!(f, ")")?;
                Ok(())
            }
        }
    }
}

/// parses an equality match in an LDAP filter expression
#[cfg(feature = "chumsky")]
pub fn search_equal_parser() -> impl Parser<char, LDAPSearchFilter, Error = Simple<char>> {
    keystring_or_oid_parser()
        .then(just('=').ignore_then(none_of(")*").repeated().collect::<String>()))
        .map(
            |(attribute_name, attribute_value)| LDAPSearchFilter::Equal {
                attribute_name,
                attribute_value,
            },
        )
        .labelled("search filter EQUAL expression")
        .boxed()
}

/// parses an approximate match in an LDAP filter expression
#[cfg(feature = "chumsky")]
pub fn search_approx_parser() -> impl Parser<char, LDAPSearchFilter, Error = Simple<char>> {
    keystring_or_oid_parser()
        .then(just("=~").ignore_then(none_of(')').repeated().collect::<String>()))
        .map(
            |(attribute_name, attribute_value)| LDAPSearchFilter::Approx {
                attribute_name,
                attribute_value,
            },
        )
        .labelled("search filter APPROX expression")
        .boxed()
}

/// parses a greater or equal match in an LDAP filter expression
#[cfg(feature = "chumsky")]
pub fn search_greater_parser() -> impl Parser<char, LDAPSearchFilter, Error = Simple<char>> {
    keystring_or_oid_parser()
        .then(just(">=").ignore_then(none_of(')').repeated().collect::<String>()))
        .map(
            |(attribute_name, attribute_value)| LDAPSearchFilter::Greater {
                attribute_name,
                attribute_value,
            },
        )
        .labelled("search filter GREATER expression")
        .boxed()
}

/// parses a less or equal match in an LDAP filter expression
#[cfg(feature = "chumsky")]
pub fn search_less_parser() -> impl Parser<char, LDAPSearchFilter, Error = Simple<char>> {
    keystring_or_oid_parser()
        .then(just("<=").ignore_then(none_of(')').repeated().collect::<String>()))
        .map(|(attribute_name, attribute_value)| LDAPSearchFilter::Less {
            attribute_name,
            attribute_value,
        })
        .labelled("search filter LESS expression")
        .boxed()
}

/// parses a present match in an LDAP filter expression
#[cfg(feature = "chumsky")]
pub fn search_present_parser() -> impl Parser<char, LDAPSearchFilter, Error = Simple<char>> {
    keystring_or_oid_parser()
        .then_ignore(just("=*"))
        .map(|attribute_name| LDAPSearchFilter::Present { attribute_name })
        .labelled("search filter PRESENT expression")
        .boxed()
}

/// parses a substring match in an LDAP filter expression
#[cfg(feature = "chumsky")]
pub fn search_substring_parser() -> impl Parser<char, LDAPSearchFilter, Error = Simple<char>> {
    keystring_or_oid_parser()
        .then(just('=').ignore_then(none_of(')').repeated().collect::<String>()))
        .map(
            |(attribute_name, attribute_value)| LDAPSearchFilter::Substring {
                attribute_name,
                attribute_value,
            },
        )
        .labelled("search filter SUBSTRING expression")
        .boxed()
}

/// parses an LDAP search filter expression
#[cfg(feature = "chumsky")]
pub fn search_filter_parser() -> impl Parser<char, LDAPSearchFilter, Error = Simple<char>> {
    recursive::<_, _, _, _, _>(|inner| {
        choice::<_, Simple<char>>((
            just('&')
                .ignore_then(inner.clone().repeated().at_least(1))
                .delimited_by('(', ')')
                .map(LDAPSearchFilter::And)
                .labelled("search filter AND expression"),
            just('|')
                .ignore_then(inner.clone().repeated().at_least(1))
                .delimited_by('(', ')')
                .map(LDAPSearchFilter::Or)
                .labelled("search filter OR expression"),
            just('!')
                .ignore_then(inner.clone())
                .delimited_by('(', ')')
                .map(|f| LDAPSearchFilter::Not(Box::new(f)))
                .labelled("search filter NOT expression"),
            search_equal_parser().delimited_by('(', ')'),
            search_approx_parser().delimited_by('(', ')'),
            search_greater_parser().delimited_by('(', ')'),
            search_less_parser().delimited_by('(', ')'),
            search_present_parser().delimited_by('(', ')'),
            search_substring_parser().delimited_by('(', ')'),
        ))
        .boxed()
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::basic::KeyString;

    #[test]
    fn test_equal_filter_parser() {
        assert_eq!(
            search_filter_parser().parse("(host=foo.bar.baz)".to_string()),
            Ok(LDAPSearchFilter::Equal {
                attribute_name: KeyStringOrOID::KeyString(KeyString("host".to_string())),
                attribute_value: "foo.bar.baz".to_string()
            })
        );
    }

    #[test]
    fn test_and_filter_parser() {
        assert_eq!(
            search_filter_parser().parse("(&(host=foo.bar.baz)(port>=35))".to_string()),
            Ok(LDAPSearchFilter::And(vec![
                LDAPSearchFilter::Equal {
                    attribute_name: KeyStringOrOID::KeyString(KeyString("host".to_string())),
                    attribute_value: "foo.bar.baz".to_string(),
                },
                LDAPSearchFilter::Greater {
                    attribute_name: KeyStringOrOID::KeyString(KeyString("port".to_string())),
                    attribute_value: "35".to_string(),
                },
            ]))
        );
    }

    #[test]
    fn test_substring_filter_parser() {
        assert_eq!(
            search_filter_parser().parse("(uid=m*)".to_string()),
            Ok(LDAPSearchFilter::Substring {
                attribute_name: KeyStringOrOID::KeyString(KeyString("uid".to_string())),
                attribute_value: "m*".to_string(),
            })
        );
    }

    #[test]
    fn test_present_filter_parser() {
        assert_eq!(
            search_filter_parser().parse("(objectClass=*)".to_string()),
            Ok(LDAPSearchFilter::Present {
                attribute_name: KeyStringOrOID::KeyString(KeyString("objectClass".to_string())),
            })
        );
    }

    #[test]
    fn test_filter_parser_roundtrip() {
        let s = "(&(host=foo.bar.baz)(port>=35))".to_string();
        assert_eq!(
            search_filter_parser()
                .parse(s.clone())
                .expect("unexpected Err in roundtrip test")
                .to_string(),
            s
        );
    }
}
