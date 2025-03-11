//! Types and traits related to the conversion of LDAP types to Rust types

/// represents the representation for a type that could be returned by a search
/// query, zero, one or multiple Strings and zero, one or
/// multiple binary values (Vec<u8>)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdapAttributeResultValues {
    /// the String result values
    pub string_values: Vec<String>,
    /// the binary result values
    pub binary_values: Vec<Vec<u8>>,
}

/// adds a method to ldap3::SearchEntry to extract the LdapResultValue
/// for a given attribute
#[cfg(feature = "ldap3")]
pub trait SearchEntryExt {
    /// extracts the results for a given attribute
    fn attribute_results(&self, attribute_name: &str) -> LdapAttributeResultValues;
}

#[cfg(feature = "ldap3")]
impl SearchEntryExt for ldap3::SearchEntry {
    fn attribute_results(&self, attribute_name: &str) -> LdapAttributeResultValues {
        let string_values = self.attrs.get(attribute_name);
        let binary_values = self.bin_attrs.get(attribute_name);
        LdapAttributeResultValues {
            string_values: string_values.map_or(Vec::new(), |v| v.to_vec()),
            binary_values: binary_values.map_or(Vec::new(), |v| v.to_vec()),
        }
    }
}

/// a primitive result that can be converted from an Ldap type that is returned
/// as a String
pub trait FromStringLdapType {
    /// the type of error when the conversion fails
    type Error;

    /// parse this type from a String returned by an LDAP search
    ///
    /// # Errors
    ///
    /// fails if the type could not be parsed
    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

impl FromStringLdapType for String {
    type Error = std::convert::Infallible;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(value)
    }
}

/// error that occurs when a conversion encounters a value that it can not
/// convert
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnexpectedStringValue {
    /// name of the type we couldn't convert the value to
    conversion_target_name: String,
    /// value that was encountered and could not be converted
    unexpected_value: String,
}

impl std::fmt::Display for UnexpectedStringValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Unexpected value in conversion to {}: {}",
            self.conversion_target_name, self.unexpected_value
        )
    }
}

impl FromStringLdapType for bool {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        match std::ops::Deref::deref(&value) {
            "TRUE" => Ok(true),
            "FALSE" => Ok(false),
            v => Err(UnexpectedStringValue {
                conversion_target_name: "bool".to_string(),
                unexpected_value: v.to_owned(),
            }),
        }
    }
}

impl FromStringLdapType for u8 {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "u8".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for i8 {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "i8".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for u16 {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "u16".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for i16 {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "i16".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for u32 {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "u32".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for i32 {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "i32".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for u64 {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "u64".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for i64 {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "i64".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for u128 {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "u128".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for i128 {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "i128".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for usize {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "usize".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for isize {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "isize".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for crate::basic::DistinguishedName {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as std::str::FromStr>::from_str(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "DistinguishedName".to_string(),
            unexpected_value: value,
        })
    }
}

impl FromStringLdapType for oid::ObjectIdentifier {
    type Error = UnexpectedStringValue;

    fn parse(value: String) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        <Self as TryFrom<&str>>::try_from(&value).map_err(|_| UnexpectedStringValue {
            conversion_target_name: "ObjectIdentifier".to_string(),
            unexpected_value: value,
        })
    }
}

/// a type that can be parsed from an Ldap type (on the level where
/// optional/required and single/multi-value matter as opposed to the primitives
/// above)
pub trait FromLdapType {
    /// the type of error when the conversion fails
    type Error;

    /// parse this type from the LDAP representation returned
    /// by a search query
    ///
    /// # Errors
    ///
    /// fails if the type could not be parsed or if the number or type
    /// (string/binary) does not match what is expected
    fn parse(values: LdapAttributeResultValues) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// represents the errors that can occur when decoding a Vec of types with a
/// FromStringLdapType implementation
#[derive(Debug, Clone)]
pub enum VecOfFromStringLdapTypeError<E> {
    /// since types implementing FromStringLdapType can not handle binary values
    /// this reprents the error when the input contains binary values
    LdapShouldNotReturnBinaryResult,
    /// represents an error converting one of the primitive values
    PrimitiveValueConversionError(E),
}

impl<E> std::fmt::Display for VecOfFromStringLdapTypeError<E>
where
    E: std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VecOfFromStringLdapTypeError::LdapShouldNotReturnBinaryResult => {
                write!(f, "encountered binary values in input when converting a Vec of a type that only supports String inputs")
            }
            VecOfFromStringLdapTypeError::PrimitiveValueConversionError(err) => {
                write!(
                    f,
                    "encountered error converting a primitive value from String: {}",
                    err
                )
            }
        }
    }
}

impl<E> std::error::Error for VecOfFromStringLdapTypeError<E> where E: std::error::Error {}

impl<T> FromLdapType for Vec<T>
where
    T: FromStringLdapType,
{
    type Error = VecOfFromStringLdapTypeError<<T as FromStringLdapType>::Error>;

    fn parse(values: LdapAttributeResultValues) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        if !values.binary_values.is_empty() {
            return Err(VecOfFromStringLdapTypeError::LdapShouldNotReturnBinaryResult);
        }
        Ok(values
            .string_values
            .into_iter()
            .map(|v| <T as FromStringLdapType>::parse(v))
            .collect::<Result<Vec<T>, <T as FromStringLdapType>::Error>>()
            .map_err(VecOfFromStringLdapTypeError::PrimitiveValueConversionError)?)
    }
}

/// represents the errors that can occur when decoding an Option of types with a
/// FromStringLdapType implementation
#[derive(Debug, Clone)]
pub enum OptionOfFromStringLdapTypeError<E> {
    /// since types implementing FromStringLdapType can not handle binary values
    /// this reprents the error when the input contains binary values
    LdapShouldNotReturnBinaryResult,
    /// since Option types can only hold 0 or 1 results there should not be more
    /// than one String input value
    LdapShouldNotReturnMultipleResults,
    /// represents an error converting one of the primitive values
    PrimitiveValueConversionError(E),
}

impl<E> std::fmt::Display for OptionOfFromStringLdapTypeError<E>
where
    E: std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptionOfFromStringLdapTypeError::LdapShouldNotReturnBinaryResult => {
                write!(f, "encountered binary values in input when converting an Option of a type that only supports String inputs")
            }
            OptionOfFromStringLdapTypeError::LdapShouldNotReturnMultipleResults => {
                write!(f, "encountered multiple string values in input when converting an Option of a type that only supports String inputs")
            }
            OptionOfFromStringLdapTypeError::PrimitiveValueConversionError(err) => {
                write!(
                    f,
                    "encountered error converting a primitive value from String: {}",
                    err
                )
            }
        }
    }
}

impl<E> std::error::Error for OptionOfFromStringLdapTypeError<E> where E: std::error::Error {}

impl<T> FromLdapType for Option<T>
where
    T: FromStringLdapType,
{
    type Error = OptionOfFromStringLdapTypeError<<T as FromStringLdapType>::Error>;

    fn parse(values: LdapAttributeResultValues) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        if !values.binary_values.is_empty() {
            return Err(OptionOfFromStringLdapTypeError::LdapShouldNotReturnBinaryResult);
        }
        if values.string_values.len() > 1 {
            return Err(OptionOfFromStringLdapTypeError::LdapShouldNotReturnMultipleResults);
        }
        if let Some(value) = values.string_values.first() {
            Ok(Some(
                <T as FromStringLdapType>::parse(value.to_owned())
                    .map_err(OptionOfFromStringLdapTypeError::PrimitiveValueConversionError)?,
            ))
        } else {
            Ok(None)
        }
    }
}

/// represents the errors that can occur when decoding a required value of
/// types with a FromStringLdapType implementation
#[derive(Debug, Clone)]
pub enum RequiredFromStringLdapTypeError<E> {
    /// since types implementing FromStringLdapType can not handle binary values
    /// this reprents the error when the input contains binary values
    LdapShouldNotReturnBinaryResult,
    /// since primitive types can only hold exactly one result there should
    /// be exactly one String input value
    LdapShouldReturnExactlyOneResult,
    /// represents an error converting one of the primitive values
    PrimitiveValueConversionError(E),
}

impl<E> std::fmt::Display for RequiredFromStringLdapTypeError<E>
where
    E: std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequiredFromStringLdapTypeError::LdapShouldNotReturnBinaryResult => {
                write!(f, "encountered binary values in input when converting a required value of a type that only supports String inputs")
            }
            RequiredFromStringLdapTypeError::LdapShouldReturnExactlyOneResult => {
                write!(f, "encountered zero or multiple string values in input when converting a required value of a type that only supports String inputs")
            }
            RequiredFromStringLdapTypeError::PrimitiveValueConversionError(err) => {
                write!(
                    f,
                    "encountered error converting a primitive value from String: {}",
                    err
                )
            }
        }
    }
}

impl<T> FromLdapType for T
where
    T: FromStringLdapType,
{
    type Error = RequiredFromStringLdapTypeError<<T as FromStringLdapType>::Error>;

    fn parse(values: LdapAttributeResultValues) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        if !values.binary_values.is_empty() {
            return Err(RequiredFromStringLdapTypeError::LdapShouldNotReturnBinaryResult);
        }
        if values.string_values.len() != 1 {
            return Err(RequiredFromStringLdapTypeError::LdapShouldReturnExactlyOneResult);
        }
        if let Some(value) = values.string_values.first() {
            Ok(<T as FromStringLdapType>::parse(value.to_owned())
                .map_err(RequiredFromStringLdapTypeError::PrimitiveValueConversionError)?)
        } else {
            return Err(RequiredFromStringLdapTypeError::LdapShouldReturnExactlyOneResult);
        }
    }
}
