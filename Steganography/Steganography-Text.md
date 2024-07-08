
# Base 64/32/URL-Safe Padding 

**Works the same with base 32 but with four `=`**
**Works the same with base64 URL-Safe but `+` are replaced by `-` and `/` by `_` and there is no `=` sign**

- In ASCII, a char is coded on 8 bits
- In base64, a char is coded on 6 bits
- b64 charset : english alphabet lowercase and uppercase, `+`, `/`

**Encoding protocol**
- Convert each ASCII string to its 8-bit representation
- Concatenation of the three 8-bit strings
- Regroup the 24 bits in groups of 6-bit strings
- Replace each 6-bit group with its equivalent in base64

**Decoding protocol**
- Convert each base64 char to its binary representation
- Remove the last 2 bits for `=` in the base64
	- it means that the last 4 bytes are removed if `==` is present
	- **This is where steganography appears because the value of those last bites are ignored**
- Regroup in 8 bits string
- Convert to ASCII

**When Encoding :**

| Length of the input | Binary                                             | Input | Output | Utility                |
| ------------------- | -------------------------------------------------- | ----- | ------ | ---------------------- |
| 3n                  | ![](../images/Pasted%20image%2020240623135927.png) | ABC   | QUJD   | Can not carry anything |
| 3n + 1              | ![](../images/Pasted%20image%2020240623135654.png) | A     | QQ==   | Can carry 4 bits       |
| 3n + 2              | ![](../images/Pasted%20image%2020240623135716.png) | AB    | QUI=   | Can carry 2 bits       |
Since the last bits cannot form a whole 6-bit string, the Base64 encoding adds **padding** until they reach the appropriate length. And for representation purposes, each “00” padding is represented by an “=” sign, to instruct the decoder how many bits should be discarded from the end of the string.

Well, look again at that padding! Base64 decoders proceed by discarding the last 2 or 4 bits of the string when necessary. **So the content of those bytes does not matter and can be used for steganography**


```python
import base64

base64_table = {
    0b000000: 'A', 0b000001: 'B', 0b000010: 'C', 0b000011: 'D',
    0b000100: 'E', 0b000101: 'F', 0b000110: 'G', 0b000111: 'H',
    0b001000: 'I', 0b001001: 'J', 0b001010: 'K', 0b001011: 'L',
    0b001100: 'M', 0b001101: 'N', 0b001110: 'O', 0b001111: 'P',
    0b010000: 'Q', 0b010001: 'R', 0b010010: 'S', 0b010011: 'T',
    0b010100: 'U', 0b010101: 'V', 0b010110: 'W', 0b010111: 'X',
    0b011000: 'Y', 0b011001: 'Z', 0b011010: 'a', 0b011011: 'b',
    0b011100: 'c', 0b011101: 'd', 0b011110: 'e', 0b011111: 'f',
    0b100000: 'g', 0b100001: 'h', 0b100010: 'i', 0b100011: 'j',
    0b100100: 'k', 0b100101: 'l', 0b100110: 'm', 0b100111: 'n',
    0b101000: 'o', 0b101001: 'p', 0b101010: 'q', 0b101011: 'r',
    0b101100: 's', 0b101101: 't', 0b101110: 'u', 0b101111: 'v',
    0b110000: 'w', 0b110001: 'x', 0b110010: 'y', 0b110011: 'z',
    0b110100: '0', 0b110101: '1', 0b110110: '2', 0b110111: '3',
    0b111000: '4', 0b111001: '5', 0b111010: '6', 0b111011: '7',
    0b111100: '8', 0b111101: '9', 0b111110: '+', 0b111111: '/'
}

base64_reverse_table = {
    'A': 0b000000, 'B': 0b000001, 'C': 0b000010, 'D': 0b000011,
    'E': 0b000100, 'F': 0b000101, 'G': 0b000110, 'H': 0b000111,
    'I': 0b001000, 'J': 0b001001, 'K': 0b001010, 'L': 0b001011,
    'M': 0b001100, 'N': 0b001101, 'O': 0b001110, 'P': 0b001111,
    'Q': 0b010000, 'R': 0b010001, 'S': 0b010010, 'T': 0b010011,
    'U': 0b010100, 'V': 0b010101, 'W': 0b010110, 'X': 0b010111,
    'Y': 0b011000, 'Z': 0b011001, 'a': 0b011010, 'b': 0b011011,
    'c': 0b011100, 'd': 0b011101, 'e': 0b011110, 'f': 0b011111,
    'g': 0b100000, 'h': 0b100001, 'i': 0b100010, 'j': 0b100011,
    'k': 0b100100, 'l': 0b100101, 'm': 0b100110, 'n': 0b100111,
    'o': 0b101000, 'p': 0b101001, 'q': 0b101010, 'r': 0b101011,
    's': 0b101100, 't': 0b101101, 'u': 0b101110, 'v': 0b101111,
    'w': 0b110000, 'x': 0b110001, 'y': 0b110010, 'z': 0b110011,
    '0': 0b110100, '1': 0b110101, '2': 0b110110, '3': 0b110111,
    '4': 0b111000, '5': 0b111001, '6': 0b111010, '7': 0b111011,
    '8': 0b111100, '9': 0b111101, '+': 0b111110, '/': 0b111111
}

def replace_last_4_bits(base64_str, replacement_4_bits):
    last_char = base64_str[-3]
    last_char_first_two_bits = base64_reverse_table[last_char] & 0b110000
    new_last_char = base64_table[last_char_first_two_bits + replacement_4_bits]
    modified_base64_str = base64_str[:-3] + new_last_char + base64_str[-2:]
    return modified_base64_str

def replace_last_2_bits(base64_str, replacement_2_bits):
    last_char = base64_str[-3]
    last_char_first_two_bits = base64_reverse_table[last_char] & 0b111100
    new_last_char = base64_table[last_char_first_two_bits + replacement_2_bits]
    modified_base64_str = base64_str[:-3] + new_last_char + base64_str[-2:]
    return modified_base64_str

original_base64_str = "YmxhaA==" # blah
replacement_4_bits = 0b1010      # 10 in decimal
print(replace_last_4_bits(original_base64_str, replacement_4_bits))
# Normal output : YmxhaA==
# Stego  output : YmxhaK==
# But decoding returns : blah in both cases
```


# Sources

- https://excellium-services.com/2022/04/27/base64-padding-steganography/