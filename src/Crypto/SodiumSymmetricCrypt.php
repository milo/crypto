<?php

declare(strict_types=1);

namespace Milo\Crypto;


/**
 * @author  Miloslav Hůla (https://github.com/milo)
 */
final class SodiumSymmetricCrypt implements Crypt
{
	private const NONCE_LENGTH = \SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;

	/** @var string */
	private $secretKey;


	public function __construct(string $secretHex)
	{
		if (!\extension_loaded('sodium')) {
			throw new \LogicException('PHP extension sodium is missing.');
		}

		try {
			$this->secretKey = \sodium_hex2bin($secretHex);
		} catch (\SodiumException $e) {
			throw new CryptException('Cannot load secret key.', 0, $e);
		}
	}


	public function __debugInfo(): array
	{
		return [];
	}


	public function encrypt(string $message): string
	{
		try {
			$nonce = \random_bytes(self::NONCE_LENGTH);

			$ciphered = \sodium_crypto_secretbox(
				$message,
				$nonce,
				$this->secretKey
			);

		} catch (\SodiumException $e) {
			\sodium_memzero($nonce);
			throw new CryptException('Message encryption failed.', 0, $e);

		} finally {
			\sodium_memzero($message);
		}

		return \base64_encode($nonce . $ciphered);
	}


	public function decrypt(string $ciphered): string
	{
		if (\strlen($ciphered) < self::NONCE_LENGTH) {
			throw new CryptException('Message is too short.');
		}

		try {
			$binary = \base64_decode($ciphered);

			$message = \sodium_crypto_secretbox_open(
				\substr($binary, self::NONCE_LENGTH),
				\substr($binary, 0, self::NONCE_LENGTH),
				$this->secretKey
			);

			if ($message === false) {
				throw new CryptException('Message cannot be decrypted.');
			}

		} catch (\SodiumException $e) {
			throw new CryptException('Message decryption failed.', 0, $e);
		}

		return $message;
	}
}
