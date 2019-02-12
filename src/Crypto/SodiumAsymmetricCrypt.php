<?php

declare(strict_types=1);

namespace Milo\Crypto;


/**
 * @author  Miloslav Hůla (https://github.com/milo)
 */
final class SodiumAsymmetricCrypt implements Crypt
{
	private const NONCE_LENGTH = \SODIUM_CRYPTO_BOX_NONCEBYTES;

	/** @var string */
	private $secretKey;

	/** @var string */
	private $publicKey;


	public function __construct(string $secretHex, string $publicHex)
	{
		if (!\extension_loaded('sodium')) {
			throw new \LogicException('PHP extension sodium is missing.');
		}

		try {
			$this->secretKey = \sodium_hex2bin($secretHex);
		} catch (\SodiumException $e) {
			throw new CryptException('Cannot load secret key.', 0, $e);
		}

		try {
			$this->publicKey = \sodium_hex2bin($publicHex);
		} catch (\SodiumException $e) {
			throw new CryptException('Cannot load public key.', 0, $e);
		}
	}


	public function __debugInfo(): array
	{
		return [];
	}


	public function encrypt(string $message): string
	{
		try {
			$keyPair = \sodium_crypto_box_keypair_from_secretkey_and_publickey(
				$this->secretKey,
				$this->publicKey
			);

			$nonce = \random_bytes(self::NONCE_LENGTH);

			$ciphered = \sodium_crypto_box(
				$message,
				$nonce,
				$keyPair
			);

		} catch (\SodiumException $e) {
			isset($nonce) && \is_string($nonce) && \sodium_memzero($nonce);
			throw new CryptException('Message encryption failed.', 0, $e);

		} finally {
			\sodium_memzero($message);
			isset($keyPair) && \is_string($keyPair) && \sodium_memzero($keyPair);
		}

		return \base64_encode($nonce . $ciphered);
	}


	public function decrypt(string $ciphered): string
	{
		if (\strlen($ciphered) < self::NONCE_LENGTH) {
			throw new CryptException('Message is too short.');
		}

		try {
			$keyPair = \sodium_crypto_box_keypair_from_secretkey_and_publickey(
				$this->secretKey,
				$this->publicKey
			);

			$binary = \base64_decode($ciphered);

			$message = \sodium_crypto_box_open(
				\substr($binary, self::NONCE_LENGTH),
				\substr($binary, 0, self::NONCE_LENGTH),
				$keyPair
			);

			if ($message === false) {
				throw new CryptException('Message cannot be decrypted.');
			}

		} catch (\SodiumException $e) {
			throw new CryptException('Message decryption failed.', 0, $e);

		} finally {
			isset($keyPair) && \is_string($keyPair) && \sodium_memzero($keyPair);
		}

		return $message;
	}
}
