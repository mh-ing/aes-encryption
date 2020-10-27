<?php
/**
 * File AesEncrypter.php
 */

namespace Tebru\AesEncryption;

use Tebru;
use Tebru\AesEncryption\Enum\AesEnum;
use Tebru\AesEncryption\Exception\IvSizeMismatchException;
use Tebru\AesEncryption\Exception\MacHashMismatchException;
use Tebru\AesEncryption\Strategy\AesEncryptionStrategy;
use Tebru\AesEncryption\Strategy\OpenSslStrategy;

/**
 * Class AesEncrypter
 *
 * @author Nate Brunette <n@tebru.net>
 */
class AesEncrypter
{
    const STRATEGY_OPENSSL = 'openssl';

    /**
     * @var AesEncryptionStrategy
     */
    private $strategy;

    /**
     * Constructor
     *
     * @param string $key The secret key
     * @param string $method
     * @param AesEncryptionStrategy $strategy
     */
    public function __construct($key, $method = AesEnum::METHOD_256)
    {
        $this->strategy = new OpenSslStrategy($key, $method);
    }

    /**
     * Encrypts any data using mac-then-encrypt method
     *
     * @param mixed $data
     * @return string
     */
    public function encrypt($data, $serialized = true)
    {
        $serializedData = $serialized ? serialize($data) : $data;
        $iv = $this->strategy->createIv();
        $encrypted = $this->strategy->encryptData($serializedData, $iv);
        $mac = $this->strategy->getMac($encrypted);
        $encoded = $this->strategy->encodeData($encrypted, $mac, $iv);

        return $encoded;
    }

    /**
     * Decrypts data encrypted through encrypt() method
     *
     * @param string $data
     * @return mixed
     * @throws IvSizeMismatchException If the IV length has been altered
     * @throws MacHashMismatchException If the data has been altered
     */
    public function decrypt($data, $serialized = true)
    {
        // if this is not an encrypted string
        if (false === strpos($data, '|')) {
            return $data;
        }

        list($encryptedData, $mac, $iv) = $this->strategy->decodeData($data);

        if ($mac !== $this->strategy->getMac($encryptedData)){
            throw new MacHashMismatchException('MAC hashes do not match');
        }

        if (strlen($iv) !== $this->strategy->getIvSize()){
            throw new IvSizeMismatchException('IV size does not match expectation');
        }

        $serializedData = $this->strategy->decryptData($encryptedData, $iv);

        return $serialized ? unserialize($serializedData) : $serializedData;
    }
}
