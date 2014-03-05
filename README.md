Encrypt and decrypt with PHP:

$aes = new SLemesPCrypt();
echo $aes->decrypt($aes->encrypt("Prueba de encriptado en PHP"));


Encrypt and decrypt with JavaScript:

var secret = new SLemesPCrypt();
secret.decrypt(secret.encrypt("Prueba de encriptado en JavaScript"));


Encrypt PHP and Decrypt JavaScript:

  PHP side
    $aes = new SLemesPCrypt();
    $fafafa = $aes->encrypt("Prueba de encriptado de PHP a JavaScript");

  JavaScript side
    var secret = new SLemesPCrypt();
    var decrypted = secret.decrypt("<?php echo $fafafa; ?>");


Encrypt JavaSCript and Decrypt PHP

  JavaScript side
    var secret = new SLemesPCrypt();
    var encrypted = secret.encrypt("Prueba de encriptado de JavaScript a PHP");
    window.open( "prueba2.php?name=" + encrypted);

  PHP side
    $aes = new SLemesPCrypt();
    echo $aes->decrypt($_GET['name']);

