<?php

if (PHP_VERSION_ID < 70200) {
	throw new \LogicException('Milo\Crypto requires PHP 7.2 or newer.');
}

require __DIR__ . '/Crypto/Crypt.php';
require __DIR__ . '/Crypto/Strict.php';
require __DIR__ . '/Crypto/CryptException.php';
require __DIR__ . '/Crypto/SodiumSymmetricCrypt.php';
require __DIR__ . '/Crypto/SodiumAsymmetricCrypt.php';
