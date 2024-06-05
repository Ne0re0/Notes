
# Filters

- `nfs`

# Statements

| Call                                     | Description of Call                                         | Reply             | Description of Reply                           |
|------------------------------------------|-------------------------------------------------------------|-------------------|------------------------------------------------|
| EXCHANGE_ID                              | Initialize an exchange ID                                   | EXCHANGE_ID       | Reply with the exchange ID                     |
| CREATE_SESSION                           | Create a session                                            | CREATE_SESSION    | Reply with session details                     |
| RECLAIM_COMPLETE                         | Indicate completion of resource reclamation                 | RECLAIM_COMPLETE  | Confirm the completion of reclamation          |
| SECINFO_NO_NAME                          | Obtain security information without a name                  | SECINFO_NO_NAME   | Provide security information                   |
| PUTROOTFH \| GETATTR                     | Set root file handle and get attributes                     | PUTROOTFH \| GETATTR | Return the file attributes                     |
| GETATTR FH : 0xSOME_HEX                  | Get attributes of the file handle 0xSOME_HEX                | GETATTR           | Return file attributes                         |
| LOOKUP DC : 0xSOME_HEX/folder_or_filename| Lookup directory component 0xSOME_HEX/folder_or_filename    | LOOKUP            | Return lookup results                          |
| ACCESS FH : 0xSOME_HEX                   | Check access permissions for file handle 0xSOME_HEX         | ACCESS            | Return access permissions                      |
| READDIR : 0xSOME_HEX                     | Read the directory entries for handle 0xSOME_HEX            | READDIR           | Return directory entries                       |
| OPEN DH : 0xSOME_HEX                     | Open directory handle 0xSOME_HEX                            | OPEN StateID      | Return the state ID for the open directory     |
| READ StateID 0xSOME_HEX offset: integer len: integer | Read data using state ID 0xSOME_HEX from a specified offset and length | READ             | Return the read data                           |

# Data Exfiltration

1. Find a READ request with the file handle you want to extract (the hex value e.g. 0x758596)
2. Then find the READ packets containing the file or a part of the file (e.g. `[PSH,ACK] Seq=... Ack=... TSecr=...`)
3. Develop and copy the data to a file

![](../images/Pasted%20image%2020240530082646.png)

4. `cat file.hex | unhex > output`
5. `file output`