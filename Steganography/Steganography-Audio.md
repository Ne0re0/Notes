
# Least Significant Bit

### Python
**Encode LSB**

```python
# We will use wave package available in native Python installation to read and write .wav audio file
import wave
# read wave audio file
song = wave.open("song.wav", mode='rb')
# Read frames and convert to byte array
frame_bytes = bytearray(list(song.readframes(song.getnframes())))

# The "secret" text message
string='Peter Parker is the Spiderman!'
# Append dummy data to fill out rest of the bytes. Receiver shall detect and remove these characters.
string = string + int((len(frame_bytes)-(len(string)*8*8))/8) *'#'
# Convert text to bit array
bits = list(map(int, ''.join([bin(ord(i)).lstrip('0b').rjust(8,'0') for i in string])))

# Replace LSB of each byte of the audio data by one bit from the text bit array
for i, bit in enumerate(bits):
    frame_bytes[i] = (frame_bytes[i] & 254) | bit
# Get the modified bytes
frame_modified = bytes(frame_bytes)

# Write bytes to a new wave audio file
with wave.open('song_embedded.wav', 'wb') as fd:
    fd.setparams(song.getparams())
    fd.writeframes(frame_modified)
song.close()
```

**Decode LSB**
```python
# Use wave package (native to Python) for reading the received audio file
import wave
song = wave.open("monster.wav", mode='rb')
# Convert audio to byte array
frame_bytes = bytearray(list(song.readframes(song.getnframes())))

# Extract the LSB of each byte
extracted = [frame_bytes[i] & 1 for i in range(len(frame_bytes))]
# Convert byte array back to string
string = "".join(chr(int("".join(map(str,extracted[i:i+8])),2)) for i in range(0,len(extracted),8))
# Cut off at the filler characters
decoded = string.split("###")[0]

# Print the extracted text
print(decoded)
song.close()       
```

### WavSteg

- The LSB technique can be used on certain audio files.
- [WavSteg](https://github.com/ragibson/Steganography#WavSteg) tool allows you to perform this manipulation on WAV files.

```bash
stegolsb wavsteg -r -i file.wav -o output.txt -n 1 -b 1000
```


| Tag | Meaning                                      |
| --- | -------------------------------------------- |
| -b  | byte number to discover                      |
| -h  | hide files                                   |
| -r  | recover files                                |
| -n  | lsb count (how many LSBs to use) [default:2] |
| -i  | input file                                   |


# DeepSound

- Used to hide data (files) in sound files (.wav, .mp3, ...)
- Windows only
- Hidden data can be encrypted using AES-256
- Can recover hidden data from a stego file


# DTMF

- Dual Tone Multi Frequencies are the tones we can hear when we dial a number on our phones
- Special encoding methods can be used, such as [DTMF Code](https://en.wikipedia.org/wiki/Dual-tone_multi-frequency_signaling) formerly used in telephony

```
Import sound file to http://dialabc.com/sound/detect/
Needs to be WAV, RIFF, PCM, or Sun/NeXt
```

- https://github.com/ribt/dtmf-decoder


# SSTV

- Slow Scan Television
- Method for picture transmission used by amateur radio operators to transmit and receive images.
- [QSSTV](https://doc.ubuntu-fr.org/qsstv)

### QSSTV

```bash
apt-get install qsstv
```

- https://ourcodeworld.com/articles/read/956/how-to-convert-decode-a-slow-scan-television-transmissions-sstv-audio-file-to-images-using-qsstv-in-ubuntu-18-04

### Python (Encoding only)

https://github.com/dnet/pySSTV

```bash
pip install pysstv
```

**Encode**
```bash
python -m pysstv /path/to/image.jpg /path/to/audio.wav
```

### SSTV (decoding)

https://github.com/colaclanth/sstv

```
sstv -d audio.wav -o result.png
```

# Wav file size edit

Just like PNG files, some sound files embed their theoretical sizes in their headers. This is particularly the case for [WAV files](https://fr.wikipedia.org/wiki/Waveform_Audio_File_Format#En-t%C3%AAte_de_fichier_WAV) whose DataSize block can be decreased or increased using a hex editor.

- You have to use hexeditor to edit the four bytes after the bloc the statement `data`
- Warning : **Little Endian encoding**

![](images/Pasted%20image%2020240611171253.png)


# Song tools

- Hiddenwave

# Using Infrasongs / Ultrasongs

