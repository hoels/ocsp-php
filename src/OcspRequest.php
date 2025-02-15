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

namespace OCSP;

use phpseclib3\File\ASN1;
use OCSP\Maps\OcspRequestMap;
use OCSP\Util\AsnUtil;

class OcspRequest
{
    const CONTENT_TYPE = "application/ocsp-request";

    private array $ocspRequest;

    public function __construct()
    {
        AsnUtil::loadOIDs();

        $this->ocspRequest = [
            "tbsRequest" => [
                "version" => "v1",
            ],
        ];
    }

    public function addCertificateId(array $certificateId): void
    {
        $this->ocspRequest["tbsRequest"]["requestList"][]["reqCert"] = $certificateId;
    }

    public function addNonceExtension(string $nonce): void
    {
        $this->ocspRequest["tbsRequest"]["requestExtensions"][] = [
            "extnId" => AsnUtil::ID_PKIX_OCSP_NONCE,
            "critical" => false,
            "extnValue" => ASN1::encodeDER($nonce, ['type' => ASN1::TYPE_OCTET_STRING]),
        ];
    }

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public function getNonceExtension(): ?string
    {
        return AsnUtil::decodeNonceExtension($this->ocspRequest["tbsRequest"]["requestExtensions"] ?? []);
    }

    public function getEncodeDer(): string
    {
        return ASN1::encodeDER($this->ocspRequest, OcspRequestMap::MAP);
    }
}
