
GraphQL is an API structure, like REST, but with some differences.

All the data can be retrieved by specifying all the attributs we want in the request.


# Introspection

If Introspection is enabled, then we can dump the structure of the API such as attributs and parameters

```
?query={__schema{types{name,fields{name}}}}
```


# Requests

```URL
?query={theParameter(SomeID:4){attributeOne,AttributeTwo}}
```


# Resources

https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql