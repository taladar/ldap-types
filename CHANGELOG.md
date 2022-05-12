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
