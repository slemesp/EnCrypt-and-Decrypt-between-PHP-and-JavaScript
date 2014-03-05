<?php
echo "<br>***************PHP*****************";

class SLemesPCrypt {
    /*
     * Deben ser identicas
     */
    private $key = "secret password";

    private function getRandomBytes($length = 8) {
        if (function_exists("openssl_random_pseudo_bytes")) {
            $bytes = base64_encode(openssl_random_pseudo_bytes($length, $strong));
            if ($strong == TRUE) {
                return substr($bytes, 0, $length);
            }
        }
//fallback to mt_rand if php < 5.3 or no openssl available 
        $characters = "0123456789";
        $characters .= "abcdef";
        $charactersLength = strlen($characters) - 1;
        $bytes = "";
//select some random characters 
        for ($i = 0; $i < $length; $i++) {
            $bytes .= $characters[mt_rand(0, $charactersLength)];
        }
        return $bytes;
    }

    public function encrypt($data) {
        $iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_CBC);
        $iv = mcrypt_create_iv($iv_size, MCRYPT_DEV_RANDOM);
        $salt = $this->getRandomBytes(8);

        $key = $this->PBKDF2($this->key, $salt, 1, 32);
        $encrypted = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_CBC, $iv);
        $json = array("iv" => base64_encode($iv),
            "s" => base64_encode($salt),
            "ct" => base64_encode($encrypted)
        );
        return base64_encode(json_encode($json));
    }

    public function decrypt($data) {
        $json = json_decode(base64_decode($data), true);
        if ($json == null || $json == false)
            return "Invalid format!";
        $key = $this->PBKDF2($this->key, base64_decode($json["s"]), 1, 32);
        $decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, base64_decode($json["ct"]), MCRYPT_MODE_CBC, base64_decode($json["iv"]));
        return $decrypted;
    }

    private function PBKDF2($p, $s, $c, $dkl, $algo = "sha1") {

        /**
         * PHP PBKDF2 Implementation. 
         * 
         * For more information see: http://www.ietf.org/rfc/rfc2898.txt 
         * 
         * @param string $p password 
         * @param string $s salt 
         * @param integer $c iteration count (use 1000 or higher) 
         * @param integer $dkl derived key length 
         * @param string $algo hash algorithm 
         * @return string derived key of correct length 
         */
        $kb = ceil($dkl / strlen(hash($algo, null, true)));
        $dk = "";
        for ($block = 1; $block <= $kb; ++$block) {
            $ib = $b = hash_hmac($algo, $s . pack("N", $block), $p, true);
            for ($i = 1; $i < $c; ++$i)
                $ib ^= ($b = hash_hmac($algo, $b, $p, true));
            $dk.= $ib;
        }
        return substr($dk, 0, $dkl);
    }

}

$aes = new SLemesPCrypt();

echo "<br>Encriptado y Desencriptado con PHP: " . $aes->decrypt($aes->encrypt("Prueba de encriptado en PHP"));
echo "<br>***************PHP JAVASCRIPT*****************";
$fafafa = $aes->encrypt("Prueba de encriptado de PHP a JavaScript");
echo "<br>Encriptado con PHP: " . $fafafa;
?>


<script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/aes.js"></script> 
<script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/rollups/pbkdf2.js"></script>
<script src="http://crypto-js.googlecode.com/svn/tags/3.1.2/build/components/pad-zeropadding.js"></script> 

<script type="text/javascript">
            
            function SLemesPCrypt() {
            this.key = 'secret password';
                    this.JsonFormatter = {
                    stringify: function(cipherParams) {
// create json object with ciphertext
                    var jsonObj = {
                    ct: cipherParams.ciphertext.toString(CryptoJS.enc.Base64)
                    };
// optionally add iv and salt
                            if (cipherParams.iv) {
                    jsonObj.iv = cipherParams.iv.toString(CryptoJS.enc.Base64)
                    }
                    if (cipherParams.salt) {
                    jsonObj.s = cipherParams.salt.toString(CryptoJS.enc.Base64)
                    }
// stringify json object
                    return JSON.stringify(jsonObj);
                    },
                            parse: function(jsonStr) {
// parse json string
                            var jsonObj = JSON.parse(jsonStr);
// extract ciphertext from json object, and create cipher params object
                                    var cipherParams = CryptoJS.lib.CipherParams.create({
                                    ciphertext: CryptoJS.enc.Base64.parse(jsonObj.ct)
                                    });
// optionally extract iv and salt
                                    if (jsonObj.iv) {
                            cipherParams.iv = CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(jsonObj.iv).toString())
                            }
                            if (jsonObj.s) {
                            cipherParams.salt = CryptoJS.enc.Hex.parse(CryptoJS.enc.Base64.parse(jsonObj.s).toString())

                            }
                            return cipherParams;
                            }
                    };
                    this.encrypt = function(data) {
                        var iv = CryptoJS.lib.WordArray.random(128 / 8);
                            var salt = CryptoJS.lib.WordArray.random(32 / 8);
                            key = CryptoJS.PBKDF2(this.key, salt, {keySize: 256 / 32, iterations: 1});
                            var encrypted = CryptoJS.AES.encrypt(data, key, {padding: CryptoJS.pad.ZeroPadding, format: this.JsonFormatter, iv: iv});
                            encrypted = this.JsonFormatter.parse("{\"ct\":\"" + encrypted.ciphertext.toString(CryptoJS.enc.Base64) + "\",\"iv\":\"" + encrypted.iv.toString(CryptoJS.enc.Base64) + "\",\"s\":\"" + salt.toString(CryptoJS.enc.Base64) + "\"}");
                            return btoa(this.JsonFormatter.stringify(encrypted));
                    };
                    this.decrypt = function(data) {
                            var encrypted = this.JsonFormatter.parse(atob(data));
                            var salt = CryptoJS.enc.Hex.parse(encrypted.salt.toString());
                            var key = CryptoJS.PBKDF2(this.key, salt, {keySize: 256 / 32, iterations: 1});
                            var decrypted = CryptoJS.AES.decrypt(encrypted, key, {padding: CryptoJS.pad.ZeroPadding, format: this.JsonFormatter, iv: CryptoJS.enc.Hex.parse(encrypted.iv.toString())});
                            return decrypted.toString(CryptoJS.enc.Utf8);
                    };

            }
      
     try {

    var secret = new SLemesPCrypt();
            var decrypted = secret.decrypt("<?php echo $fafafa; ?>");
            document.write("<br>Desencriptado en JS: " + decrypted);
            document.write("<br>***************JAVASCRIPT*****************");
            document.write("<br>Encriptado y Desencriptado en JS: " + secret.decrypt(secret.encrypt("Prueba de encriptado en JavaScript")));
            document.write("<br>***************JAVASCRIPT PHP*****************");
            var encrypted = secret.encrypt("Prueba de encriptado de JavaScript a PHP");
            document.write("<br>Encriptado en JS: " + encrypted);

/*
 * You need create a prueba2.php file with this php code
 * $aes = new YASCloudCrypt();
 * echo "<br>Desencriptado con PHP: " . $aes->decrypt($_GET['name']);
 */
            window.open( "prueba2.php?name=" + encrypted); 

    } catch (e) {
    document.write("<br>ERROR: " + e);
    }

</script>
