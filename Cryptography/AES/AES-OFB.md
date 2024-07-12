
# **Requirements**

- Key
- Initialization vector
	- It should be completely random, otherwise it is trivial to retrieve the key stream

# **How it works**

1. The key and the initialization vector are combined to provide a `key stream` that is the same length as the clear text message.
2. Then, the clear text message is xored with the key stream
3. You have to store the IV somewhere so it can be retrieved

# Same key and IV

- If neither the key nor the IV is randomized, then, the keystream will always be the same for every cyphertext.

**Knowing a cleartext and its cipher**
- By xoring a cleartext with its cipher, you can partially retrieve the key stream (`len(cleartext)`)
- You are now able to encrypt and decrypt *n* bytes.


