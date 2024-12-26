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

namespace web_eid\ocsp_php\certificate;

use Exception;
use phpseclib3\File\X509;
use web_eid\ocsp_php\exceptions\OcspCertificateException;

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
}
