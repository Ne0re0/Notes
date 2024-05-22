***From HackingIsland*** - https://www.youtube.com/channel/UCaqcHDqE0DuqoaoVwJQa7vQ/videos
 
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
- 
## Common tools :
- stegsolve
- steganabra
- steghide / stegcracker
 
### Rare tools :
- stegseek
- OpenStego
- Stegpy
- Outguess
- jphide
- jpgx
- zsteg
- stegoveritas
 
## Forensic technics :
- file
- exif
- exiftool
- strings
- foremost
- binwalk
 
## Songs :
- Audacity
- MixW
- MMSSTV / RX SSTV
- Wavsteg (extraire LSB)
python3 WavSteg.py -r -b 1 -s soundfile -o outputfile
- Deepsound (Comme steghide pour l'audio)
 
## Footages :
- vlc
- ffmpg
- Veracrypt
 
## Texts :
- Twitter Secrets Messages
- Snow
- Base64 padding

# APNG

**Animated Portable Network Graphics** (**APNG**) is a [file format](https://en.wikipedia.org/wiki/File_format "File format") which extends the [Portable Network Graphics](https://en.wikipedia.org/wiki/Portable_Network_Graphics "Portable Network Graphics") (PNG) specification to permit [animated](https://en.wikipedia.org/wiki/Computer_animation "Computer animation") images that work similarly to animated [GIF](https://en.wikipedia.org/wiki/Graphics_Interchange_Format "Graphics Interchange Format") files, while supporting 24 or 48-bit images and [full alpha transparency](https://en.wikipedia.org/wiki/Alpha_compositing "Alpha compositing") not available for GIFs. It also retains [backward compatibility](https://en.wikipedia.org/wiki/Backward_compatibility "Backward compatibility") with non-animated PNG files.

***Technics :***
- Separate frames

https://ezgif.com/apng-maker

## Onlines tools :
- https://stegonline.georgeom.net/upload  
- https://aperisolve.fr/  
 
## ELA (Error Level Analysis) - Analyse de compression (JPEG typical)
- https://fotoforensics.com/  
 
## FFT Analysis (Fast Fourier Transform) :  
- http://bigwww.epfl.ch/demo/ip/demos/FFT/  
- https://ejectamenta.com/imaging-experiments/fourifier/
