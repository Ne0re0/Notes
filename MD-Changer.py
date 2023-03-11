#!/bin/python
"""     
        Asks to append every file with a .md file and remove blank spaces
        Do not changes directories 
        Asks every .txt to be converted to .md

        Example :
        Test => Test.md
        Very Hard Test => Very-Hard-Test.md
        Very Hard Test.txt => Very-Hard-Test.md

"""

if __name__ == '__main__' :
    import os

    x = os.system("ls -l > /tmp/tmp")
    with open('/tmp/tmp') as tmp :
        for index,file in enumerate(tmp) :
            if index >= 1 :
                rights = file[:11]
                indexWord = len(file.split(" "))-1
                file = file.split(" ")
                while True :
                    try :
                        file.remove("")
                    except :
                        break

                file[-1] = file[-1][:-1]
                newName = ""
                if len(file) > 9 :
                    newName = file[-1]
                    for i in range(len(file) -2 ,7, -1) :
                        file[-1] = file[i] +' '+ file[-1]
                        newName = file[i] + '-' + newName
                file = file[-1]
                if newName == "" :
                    newName = file
                
                if newName.split(".")[-1] in ["txt"] :
                    newName = newName[:-4]
                    print(newName)
                
                if rights[0] != 'd' and file != 'MD-Changer.py' and file != 'tmp' and file[-3:] != ".md":
                        if input(f"mv '{file}' {newName}.md || Are you sure ? (y/n) :").upper() == 'Y' :
                            os.system(f"mv '{file}' {newName}.md")