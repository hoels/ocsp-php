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

use PHPUnit\Framework\TestCase;
use web_eid\ocsp_php\exceptions\OcspCertificateException;

class CertificateLoaderTest extends TestCase
{
    public function testWhenCertificateLoaderFromFileSuccess(): void
    {
        $certificate = CertificateLoader::fromFile(__DIR__ . '/../_resources/revoked.crt');

        $issuerCertificateUrl = CertificateLoader::getIssuerCertificateUrl($certificate);
        $ocspResponderUrl = CertificateLoader::getOcspResponderUrl($certificate);

        $this->assertEquals(
            "318601422914101149693420017798940712227677",
            $certificate->getCurrentCert()['tbsCertificate']['serialNumber']
        );
        $this->assertEquals("http://cert.int-x3.letsencrypt.org/", $issuerCertificateUrl);
        $this->assertEquals("http://ocsp.int-x3.letsencrypt.org", $ocspResponderUrl);
    }

    public function testWhenCertificateLoaderFromStringSuccess(): void
    {
        $certData = file_get_contents(__DIR__ . '/../_resources/revoked.crt');
        $certificate = CertificateLoader::fromString($certData);
        $this->assertEquals(
            "318601422914101149693420017798940712227677",
            $certificate->getCurrentCert()['tbsCertificate']['serialNumber']
        );
    }

    public function testWhenCertificateFileDoNotExistThrows(): void
    {
        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage(
            'Certificate file not found or not readable: ' . __DIR__ . '/../_resources/somecert.crt'
        );

        CertificateLoader::fromFile(__DIR__ . '/../_resources/somecert.crt');
    }

    public function testWhenCertificateIsInvalidThrows(): void
    {
        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage('Certificate decoding from Base64 or parsing failed');

        CertificateLoader::fromFile(__DIR__ . '/../_resources/invalid.crt');
    }

    public function testWhenCertificateStringIsNotValidThrows(): void
    {
        $this->expectException(OcspCertificateException::class);
        $this->expectExceptionMessage('Certificate decoding from Base64 or parsing failed');

        CertificateLoader::fromString("certsource");
    }
}
