<?php
class SLemesPCrypt {

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
echo "<br>Desencriptado con PHP: " . $aes->decrypt($_GET['name']);
?>
