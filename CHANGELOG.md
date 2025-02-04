## 0.4.7

update dependencies

## 0.4.6

update dependencies

## 0.4.5

update dependencies

## 0.4.4

update dependencies

## 0.4.3

update dependencies

## 0.4.2

update dependencies

## 0.4.1

update dependencies, including some incompatible updates

## 0.4.0

update dependencies, including some incompatible updates
sort dependencies in Cargo.toml with cargo sort
update deny.toml to new format

## 0.3.0

update dependencies, including some incompatible updates

## 0.2.3

fix SPDX license expression
update dependencies to get rid of unmaintained indirect ones

## 0.2.2

add proper error display for chumsky parser errors via ariadne
add function to return combined attributes from an LDAPEntry as required by add operation

## 0.2.1

add FromStr instances for KeyStringOrOID, RelativeDistinguishedName and DistinguishedName

## 0.2.0

update ldap3 dependency to 0.10.5 or above (earlier 0.10 have a bug with SASL external auth)

## 0.1.3

fix parser tests
add various trait implementations to DN and RND types
add LDAPEntry, LDAPOperation types

## 0.1.2

add From/TryFrom instances
add more functions to find values in the LDAPSchema
change functions to find values in the LDAPSchema to work on anything with an impl TryFrom<KeyStringOrOID>
add Hash instances
add functions to return required and allowed attributes for a given objectClass

## 0.1.1

add serde support

## 0.1.0

Initial Release
