<?php

/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

namespace OCSP\Certificate;

use Exception;
use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Maps\Name;
use phpseclib3\File\X509;
use OCSP\Exceptions\OcspCertificateException;
use OCSP\Util\AsnUtil;
use OCSP\Util\HashAlgorithm;

class CertificateLoader
{
    /**
     * Loads the certificate from file path and returns the certificate
     *
     * @param string $pathToFile Full path to the certificate file
     * @return X509 Loaded certificate
     * @throws OcspCertificateException when the certificate decoding or parse fails
     */
    public static function fromFile(string $pathToFile): X509
    {
        if (!is_readable($pathToFile) || !is_file($pathToFile)) {
            throw new OcspCertificateException("Certificate file not found or not readable: $pathToFile");
        }
        $fileContent = file_get_contents($pathToFile);
        if ($fileContent === false) {
            throw new OcspCertificateException("Failed to read certificate file: $pathToFile");
        }

        return CertificateLoader::fromString($fileContent);
    }

    /**
     * Loads the certificate from string and returns the certificate
     *
     * @param string $certString Certificate as string
     * @return X509 Loaded certificate
     * @throws OcspCertificateException Thrown when the certificate decoding or parse fails
     */
    public static function fromString(string $certString): X509
    {
        $certificate = new X509();
        $loaded = false;
        try {
            $loaded = $certificate->loadX509($certString);
        } catch (Exception) {
        }
        if (!$loaded) {
            throw new OcspCertificateException("Certificate decoding from Base64 or parsing failed");
        }
        return $certificate;
    }

    public static function getIssuerCertificateUrl(X509 $certificate): string
    {
        $url = "";
        $opts = $certificate->getExtension("id-pe-authorityInfoAccess");
        foreach ($opts as $opt) {
            if ($opt["accessMethod"] == "id-ad-caIssuers") {
                $url = $opt["accessLocation"]["uniformResourceIdentifier"];
                break;
            }
        }
        return $url;
    }

    public static function getOcspResponderUrl(X509 $certificate): string
    {
        $url = "";
        $opts = $certificate->getExtension("id-pe-authorityInfoAccess");
        foreach ($opts as $opt) {
            if ($opt["accessMethod"] == "id-ad-ocsp") {
                $url = $opt["accessLocation"]["uniformResourceIdentifier"];
                break;
            }
        }
        return $url;
    }

    /**
     * Generates certificate ID with subject and issuer certificates
     *
     * @param X509 $certificate Subject certificate
     * @param X509 $issuerCertificate Issuer certificate
     * @param HashAlgorithm $hashAlgorithm The hash algorithm to use for the issuer name and key hashes
     * @return mixed[] Certificate ID array
     * @throws OcspCertificateException Thrown when the subject or issuer certificates don't have required data
     */
    public static function generateCertificateId(
        X509 $certificate,
        X509 $issuerCertificate,
        HashAlgorithm $hashAlgorithm = HashAlgorithm::SHA256
    ): array {
        AsnUtil::loadOIDs();

        // try to get serial number
        $serialNumber = $certificate->getCurrentCert()["tbsCertificate"]["serialNumber"] ?? null;
        if ($serialNumber === null) {
            throw new OcspCertificateException("Serial number of subject certificate does not exist");
        }
        $serialNumber = clone $serialNumber;

        // try to get issuer name and compute hash
        $issuerName = $issuerCertificate->getCurrentCert()["tbsCertificate"]["subject"] ?? null;
        if ($issuerName === null) {
            throw new OcspCertificateException("Subject of issuer certificate does not exist");
        }
        $issuerNameHash = hash(
            algo: $hashAlgorithm->value,
            data: ASN1::encodeDER($issuerName, Name::MAP),
            binary: true
        );

        // try to get issuer public key and compute hash
        $issuerKey = $issuerCertificate->getCurrentCert()["tbsCertificate"]["subjectPublicKeyInfo"]["subjectPublicKey"]
            ?? null;
        if ($issuerKey === null) {
            throw new OcspCertificateException("Public key of issuer certificate does not exist");
        }
        $issuerKeyHash = hash(
            algo: $hashAlgorithm->value,
            data: AsnUtil::extractKeyData($issuerKey),
            binary: true
        );

        return [
            "hashAlgorithm" => [
                "algorithm" => Asn1::getOID("id-" . $hashAlgorithm->value),
            ],
            "issuerNameHash" => $issuerNameHash,
            "issuerKeyHash" => $issuerKeyHash,
            "serialNumber" => $serialNumber,
        ];
    }
}
