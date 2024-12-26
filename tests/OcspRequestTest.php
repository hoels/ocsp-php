<?php

/*
 * Copyright (c) 2022-2024 Estonian Information System Authority
 * Copyright (c) 2024 Kai Hölscher
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

namespace OCSP\Tests;

use OCSP\OcspRequest;
use OCSP\Util\AsnUtil;
use phpseclib3\File\ASN1;
use PHPUnit\Framework\TestCase;
use ReflectionObject;

class OcspRequestTest extends TestCase
{
    public function testSuccessWhenAddingCertificateId(): void
    {
        $request = new OcspRequest();
        $request->addCertificateId([1]);

        $requestReflector = new ReflectionObject($request);

        $this->assertEquals([
            "tbsRequest" => [
                "version" => "v1",
                "requestList" => [
                    [
                        "reqCert" => [1]
                    ]
                ],
            ],
        ], $requestReflector->getProperty("ocspRequest")->getValue($request));
    }

    public function testWhenAddNonceExtensionSuccess(): void
    {
        $request = new OcspRequest();
        $request->addNonceExtension("nonce");

        $requestReflector = new ReflectionObject($request);

        $this->assertEquals([
            "tbsRequest" => [
                "version" => "v1",
                "requestExtensions" => [
                    [
                        "extnId" => AsnUtil::ID_PKIX_OCSP_NONCE,
                        "critical" => false,
                        "extnValue" => ASN1::encodeDER("nonce", ["type" => ASN1::TYPE_OCTET_STRING]),
                    ]
                ]
            ],
        ], $requestReflector->getProperty("ocspRequest")->getValue($request));
    }

    public function testWhenGetNonceExtensionSuccess(): void
    {
        $request = new OcspRequest();
        $request->addNonceExtension("nonce");

        $this->assertEquals("nonce", $request->getNonceExtension());
    }
}
