# ldap-types

Implements the basic LDAP types so they can be used in other crates

## Features

### chumsky

Include the chumsky parser dependency and related crates to generate parsers
for DNs, RDNs, filters, schemas,...

### serde

Include serde support for serialization and deserialization of some of the types

### diff

Pull in the diff-struct dependency to allow diffing of LDAP entries

### ldap3

Pull in some basic types from ldap3 to generate From instances for LDAP entries
and for the LDAPOperation type which models essentially LDIF modifications
apart from renames (all the operations that can be applied to an entry that
do not change its DN), used in my ldap-utils and ultimately
sync-ldap-subtrees crates
