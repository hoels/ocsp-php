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
use UnexpectedValueException;
use OCSP\Exceptions\OcspCertificateException;
use OCSP\Exceptions\OcspResponseDecodeException;
use OCSP\Exceptions\OcspVerifyFailedException;
use OCSP\Maps\OcspBasicResponseMap;
use OCSP\Maps\OcspResponseMap;

class OcspResponse
{
    const CONTENT_TYPE = "application/ocsp-response";
    /** Response type for a basic OCSP responder */
    const ID_PKIX_OCSP_BASIC_STRING = "id-pkix-ocsp-basic";

    private array $ocspResponse;
    private string $revokeReason = "";

    /**
     * @throws OcspResponseDecodeException
     */
    public function __construct(string $encodedBER)
    {
        $decoded = self::getDecoded($encodedBER);

        $this->ocspResponse = ASN1::asn1map($decoded[0], OcspResponseMap::MAP, [
            "response" => function ($encoded) {
                return ASN1::asn1map(
                    self::getDecoded($encoded)[0],
                    OcspBasicResponseMap::MAP
                );
            },
        ]);
    }

    public function getBasicResponse(): OcspBasicResponse
    {
        if ($this->ocspResponse["responseBytes"]["responseType"] !== self::ID_PKIX_OCSP_BASIC_STRING) {
            throw new UnexpectedValueException(
                'responseType is not "' . self::ID_PKIX_OCSP_BASIC_STRING . '" but is "' .
                $this->ocspResponse["responseBytes"]["responseType"] . '"'
            );
        }

        if (!$this->ocspResponse["responseBytes"]["response"]) {
            throw new UnexpectedValueException(
                "Could not decode OcspResponse->responseBytes->response"
            );
        }

        return new OcspBasicResponse(
            $this->ocspResponse["responseBytes"]["response"]
        );
    }

    public function getStatus(): string
    {
        return $this->ocspResponse["responseStatus"];
    }

    public function getRevokeReason(): string
    {
        return $this->revokeReason;
    }

    /**
     * @throws OcspVerifyFailedException
     */
    public function isRevoked(): ?bool
    {
        $basicResponse = $this->getBasicResponse();
        $this->validateResponse($basicResponse);

        if (isset($basicResponse->getResponses()[0]["certStatus"]["good"])) {
            return false;
        }

        if (isset($basicResponse->getResponses()[0]["certStatus"]["revoked"])) {
            $revokedStatus = $basicResponse->getResponses()[0]["certStatus"]["revoked"];
            // Check revoke reason
            if (isset($revokedStatus["revokedReason"])) {
                $this->revokeReason = $revokedStatus["revokedReason"];
            }
            return true;
        }

        return null;
    }

    /**
     * @throws OcspCertificateException|OcspVerifyFailedException
     */
    public function validateSignature(): void
    {
        $basicResponse = $this->getBasicResponse();
        $this->validateResponse($basicResponse);

        $responderCert = $basicResponse->getCertificates()[0];
        // get public key from responder certificate in order to verify signature on response
        $publicKey = $responderCert
            ->getPublicKey()
            ->withHash($basicResponse->getSignatureAlgorithm());
        // verify response data
        $encodedTbsResponseData = $basicResponse->getEncodedResponseData();
        $signature = $basicResponse->getSignature();

        if (!$publicKey->verify($encodedTbsResponseData, $signature)) {
            throw new OcspVerifyFailedException(
                "OCSP response signature is not valid"
            );
        }
    }

    /**
     * @throws OcspVerifyFailedException
     */
    public function validateCertificateId(array $requestCertificateId): void
    {
        $basicResponse = $this->getBasicResponse();
        if ($requestCertificateId != $basicResponse->getCertID()) {
            throw new OcspVerifyFailedException(
                "OCSP responded with certificate ID that differs from the requested ID"
            );
        }
    }

    /**
     * @throws OcspVerifyFailedException
     */
    private function validateResponse(OcspBasicResponse $basicResponse): void
    {
        // Must be one response
        if (count($basicResponse->getResponses()) != 1) {
            throw new OcspVerifyFailedException(
                "OCSP response must contain one response, received " . count($basicResponse->getResponses())
                . " responses instead"
            );
        }

        // At least on cert must exist in responder
        if (count($basicResponse->getCertificates()) < 1) {
            throw new OcspVerifyFailedException(
                "OCSP response must contain the responder certificate, but none was provided"
            );
        }
    }

    /**
     * @throws OcspResponseDecodeException
     */
    private static function getDecoded(string $encodedBER): array
    {
        $decoded = ASN1::decodeBER($encodedBER);
        if (!is_array($decoded)) {
            throw new OcspResponseDecodeException();
        }
        return $decoded;
    }
}
