# Powershell Basics (cmdlets)
(All cmdlet are designed the same way : Verb-Noun)
## Help
```powershell
Get-Help commandName 
```
Add the ```-examples``` shows examples

## List/search commands 
```powershell
Get-Command pattern-*
```
***Exemple :***  
```powershell
Get-Command New*
```
## Cat a file
```powershell
Get-Content file.txt
```
## List properties and methods from a cmdlet
```powershell
Get-Member commandName
```
## List current directory
```powershell
Get-ChildItem
```
## Find equivalent
```powershell
Get-ChildItem -Recurse -Filter *.txt 
```

## Create new objects (Select only certain columns = properties)
```powershell
Select-Object -property Column1, Column2
```
***Example :***  
```powershell
Get-ChilItem | Select-Object -Property Name, Mode
```
- first - gets the first x object
- last - gets the last x object
- unique - shows the unique objects
- skip - skips x objects

## Filtering 
```powershell
Where-Object -Property propertyName -operator value
```
***operator possibilities :***   
- -eq : means equivalent  
- -Contains : means include
- -GT : means greater than  
[Other operators](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/where-object?view=powershell-7.3&viewFallbackFrom=powershell-6)  
***Example :***  
```powershell
Get-ChildItem | Where-Object -Name -eq Desktop
```

## Sort items
```powershell
Sort-Object
```

## Count items
```powershell
Get-Command | Where-Object -Property CommandType -eq cmdlet | measure
```
## Other tips
`|` (pipelines) are used the same way as Unix and allows redirection from an output to another command.  
A major difference is that pipelines give entire objects instead of text only in Unix.  


