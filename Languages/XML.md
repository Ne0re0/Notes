# eXtensible Markup Language
- Used for storing and transporting data
- Both human and machine readable so it doesn't require any conversion

## Starter
- Every XML document mostly starts with what is known as XML Prolog.
- Every XML document must contain a `ROOT` element, if not, wrong syntaxe
- Case sensitive

```xml
<?xml version="1.0" encoding="UTF-8"?>
```

## Example
```xml
<?xml version="1.0" encoding="UTF-8"?>
<mail>
   <to>falcon</to>
   <from>feast</from>
   <subject>About XXE</subject>
   <text>Teach about XXE</text>
</mail>
```

| Tag | Utility |
| ---- | ---- |
| mail | Root element |
| to / from / subject / text | Child elements / mail parameters |

- Like HTML we can use attributes in XML too. The syntax for having attributes is also very similar to HTML. For example:

```xml
<text category = "message">You need to learn about XXE</text>
```

In the above example category is the attribute name and message is the attribute value.

