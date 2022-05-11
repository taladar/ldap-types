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
