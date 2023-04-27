<?php

/*
 * Copyright (c) 2022-2023 Estonian Information System Authority
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

declare(strict_types=1);

namespace web_eid\ocsp_php;

use phpseclib3\File\ASN1;
use web_eid\ocsp_php\maps\OcspRequestMap;
use web_eid\ocsp_php\util\AsnUtil;

class OcspRequest
{
    private array $ocspRequest = [];

    public function __construct()
    {
        AsnUtil::loadOIDs();

        $this->ocspRequest = [
            "tbsRequest" => [
                "version" => "v1",
                "requestList" => [],
                "requestExtensions" => [],
            ],
        ];
    }

    public function addCertificateId(array $certificateId): void
    {
        $request = [
            "reqCert" => $certificateId,
        ];
        $this->ocspRequest["tbsRequest"]["requestList"][] = $request;
    }

    public function addNonceExtension(string $nonce): void
    {
        $nonceExtension = [
            "extnId" => AsnUtil::ID_PKIX_OCSP_NONCE,
            "critical" => false,
            "extnValue" => $nonce,
        ];
        $this->ocspRequest["tbsRequest"][
            "requestExtensions"
        ][] = $nonceExtension;
    }

    /**
     * @copyright 2022 Petr Muzikant pmuzikant@email.cz
     */
    public function getNonceExtension(): string
    {
        return current(
            array_filter(
                $this->ocspRequest["tbsRequest"]["requestExtensions"],
                function ($extension) {
                    return AsnUtil::ID_PKIX_OCSP_NONCE == $extension["extnId"];
                }
            )
        )["extnValue"];
    }

    public function getEncodeDer(): string
    {
        return ASN1::encodeDER($this->ocspRequest, OcspRequestMap::MAP);
    }
}
