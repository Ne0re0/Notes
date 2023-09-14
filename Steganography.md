***Par HackingIsland - https://www.youtube.com/channel/UCaqcHDqE0DuqoaoVwJQa7vQ/videos***

 
Méthodologie pour résoudre les challenges de stéganographie :  
La stéganographie est l'art de la dissimulation : son objet est de faire passer inaperçu un message dans un autre message.  
 
# Méthodologie principale :
- analyse visuelle
- file
- exiftool
- strings
- binwalk / foremost / scalpel
- Steghide
- Stegcracker (Steghide bruteforcer)
- analyse manuelle
- stegsolve
- steganabra
- PNG Chunks :
    - TweakPNG
    - pngcheck -vtp7 myImage.png
- tineye / Reverse image search
zsteg
- Thumbnail exif
__
 
## Outils classiques :
- stegsolve
- steganabra
- steghide / stegcracker
 
### Outils moins courants :
- stegseek
- OpenStego
- Stegpy
- Outguess
- jphide
- jpgx
- zsteg
- stegoveritas
 
## Ainsi que des techniques forensic :
- file
- exif
- exiftool
- strings
- foremost
- binwalk
 
## Audio :
- Audacity
- MixW
- MMSSTV / RX SSTV
- Wavsteg (extraire LSB)
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile
- Deepsound (Comme steghide pour l'audio)
 
## Vidéos :
- vlc
- ffmpg
- Veracrypt
 
## Texte :
- Twitter Secrets Messages
- Snow
- Base64 padding

## Outils en ligne :
Equivalent stegsolve online :  
https://stegonline.georgeom.net/upload  
https://aperisolve.fr/  
 
## ELA (Error Level Analysis) - Analyse de compression (typique du JPEG)
https://fotoforensics.com/  
 
## FFT Analysis (Fast Fourier Transform) :  
http://bigwww.epfl.ch/demo/ip/demos/FFT/  
https://ejectamenta.com/imaging-experiments/fourifier/
