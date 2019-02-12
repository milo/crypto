<?php

declare(strict_types=1);

namespace Milo\Crypto;


/**
 * Object access sanitization. Stolen from Nette Framework (https://nette.org/)
 */
trait Strict
{
	public function & __get($name)
	{
		throw new \LogicException("Reading undeclared member " . get_class($this) . "::$$name.");
	}


	public function __set($name, $value)
	{
		throw new \LogicException("Setting undeclared member " . get_class($this) . "::$$name.");
	}
}
