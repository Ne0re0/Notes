## Polybius cipher
- Monoalphabetic cipher
#### English square
- i and j are merged

|  | 1 | 2 | 3 | 4 | 5 |
| :--- | :--- | ---- | ---- | ---- | ---- |
| 1 | a | b | c | d | e |
| 2 | f | g | h | **i**/j | k |
| 3 | l | m | n | o | p |
| 4 | s | r | s | t | u |
| 5 | v | w | x | y | z |

#### French square
- v and w are merged

|  | 1 | 2 | 3 | 4 | 5 |
| :--- | :--- | ---- | ---- | ---- | ---- |
| 1 | a | b | c | d | e |
| 2 | f | g | h | i | j |
| 3 | k | l | m | n | o |
| 4 | p | q | r | s | t |
| 5 | u | **v**/w | x | y | z |

## Usage
Each character can be represented as 2 digits, for example, e is 15 and z is 55

## Upgrade with password
We can add a password to the table, example with `DIFFICILE` 
- All we have to do is remove letters that appear twice or more in the password and write it to the table
- Since the password is not made of 25 characters, we have to complete the table with letters that do not appear in the password, sorted in alphabetical order

|  | 1 | 2 | 3 | 4 | 5 |
| :--- | :--- | ---- | ---- | ---- | ---- |
| **1** | ***d*** | ***i*** | ***f*** | ***c*** | ***l*** |
| **2** | ***e*** | a | b | g | h |
| **3** | j | k | m | n | o |
| **4** | p | q | r | s | t |
| **5** | u | **v**/w | x | y | z |
## Variations 

### Bifid cipher

#### Usage
- The message is divided into segments of size `n`.
- For each character, its coordinates in the table are determined.
- Two arrays are created: one with the `first values` (i.e., the y-coordinate) and another with the `second values` (i.e., the x-coordinate).
- Once the segment is complete, the two arrays are merged, and for each pair of values, the character at the corresponding coordinates is returned.

## Python implementation

```python
class Polybe :
    
    def __init__(self,key,language = "FR") : 
        self.key = key
        self.language = language
        self.table = self.create_table()

            
    def create_table(self) :
        alphabet = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
        table = [[""]*5 for k in range(5)]
        stripped_key = []

        for char in list(self.key.upper()) : 
            if char not in stripped_key and char in alphabet: 
                stripped_key += [char]

        if self.language == 'FR' : 
            alphabet.remove('W') 
            stripped_key = ['V' if element == 'W' else element for element in stripped_key]
        elif self.language == 'EN' : 
            alphabet.remove("J")
            stripped_key = ['I' if element == 'J' else element for element in stripped_key]

        for char in stripped_key : 
            alphabet.remove(char)

        for k in range(len(table)) : 
            for i in range(len(table[k])) : 
                key_char_index = 5*k+i
                if (key_char_index < len(stripped_key)) :
                    table[k][i] = stripped_key[5*k+i]
                else : 
                    table[k][i] = alphabet.pop(0)

        return table 

    def __str__(self) : 
        string = f"Polybe : {self.key}\n"
        for line in self.table : 
            string += f"{line}\n"
        return string
    
    def encrypt(self, message) : 
        cipher = ""
        for message_char in message.upper() : 
            if message_char == " " : 
                cipher += " "
            else : 
                found = False
                for y,line in enumerate(self.table) : 
                    if not found : 
                        for x, table_char in enumerate(line) : 
                            if table_char == message_char : 
                                cipher += f"{y+1}{x+1}"
                                found = True
                                break
                if not found : 
                    print(f"Error while encrypting {message_char}, not in table. Adding it to cipher with no change")
                    cipher += message_char
        return cipher
    
    def decrypt(self,cipher) : 
        i = 0
        message = ""
        while i < len(cipher) : 
            if not cipher[i].isdigit() : 
                message += cipher[i]
                i += 1
            else : 
                x = int(cipher[i]) - 1
                y = int(cipher[i+1]) - 1
                message += self.table[x][y]
                i += 2
        return message

if __name__ == '__main__' : 
    polybe = Polybe("BLAISE PASCALE",'FR')
    message = "L'homme est un ange déchu qui se souvient du ciel"
    cipher = polybe.encrypt(message)
    print(cipher)
    decrypted = polybe.decrypt(cipher)
    print(decrypted)

```