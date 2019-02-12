<?php

declare(strict_types=1);

namespace Milo\Crypto;


/**
 * @author  Miloslav Hůla (https://github.com/milo)
 */
interface Crypt
{
	/**
	 * @param  string $message  Plain text message to be encrypted.
	 * @return string  Encrypted message in base64 encoding.
	 * @throws CryptException
	 */
	public function encrypt(string $message): string;


	/**
	 * @param  string $message  Encrypted message in base64 encoding.
	 * @return string  Decrypted plain text message.
	 * @throws CryptException
	 */
	public function decrypt(string $message): string;
}
