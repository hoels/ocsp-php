# OCSP PHP

ocsp-php is a library for checking if certificates are revoked by using Online Certificate Status Protocol (OCSP),
entirely written in PHP.

Note that this library does not include any HTTP client. You can use any client of your choice, e.g. Curl or GuzzleHTTP.

## Installation

#### Requirements

- PHP 8.1+
- Composer

### Composer
```shell
composer require hoels/app-store-server-library-php
```

## Loading the certificates

By using `CertificateLoader`, you can load certificates from a file or string.

```php
// Loading certificate from file
$certificate = CertificateLoader::fromFile("/path/to/cert.crt");

// Loading certificate from string
$certificate = CertificateLoader::fromString("-----BEGIN CERTIFICATE-----MIIEAzCCA...-----END CERTIFICATE-----");
```

## Getting the issuer certificate from certificate

The certificate usually contains a URL where you can find certificate of the certificate issuer.

You can use this code to extract this URL from the certificate.

```php
$certificate = CertificateLoader::fromFile("/path/to/cert.crt");
$issuerCertificateUrl = CertificateLoader::getIssuerCertificateUrl($certificate);
```

`$issuerCertificateUrl` will contain the URL where the issuer certificate can be downloaded. When it is an empty string,
that means the issuer certificate URL is not included in the SSL certificate.

## Getting the OCSP responder URL

To check if a SSL Certificate is valid, you need to know the OCSP URL, that is provided by the authority that issued the
certificate. This URL can be called to check if the certificate has been revoked.

This URL may be included in the SSL Certificate itself.

You can use this code to extract the OCSP responder URL from the SSL Certificate.

```php
$certificate = CertificateLoader::fromFile("/path/to/cert.crt");
$ocspResponderUrl = CertificateLoader::getOcspResponderUrl($certificate);
```
When it is an empty string, that means the OCSP responder URL is not included in the SSL Certificate.

## Checking the revocation status of an SSL Certificate

Once you have the SSL Certificate, the issuer certificate, and the OCSP responder URL, you can check whether the SSL
certificate has been revoked or is still valid.

```php
$subjectCert = CertificateLoader::fromFile("/path/to/subject.crt");
$issuerCert = CertificateLoader::fromFile("/path/to/issuer.crt");

// Create the certificateId
$certificateId = CertificateLoader::generateCertificateId($subjectCert, $issuerCert);

// Build request body
$requestBody = new OcspRequest();
$requestBody->addCertificateId($certificateId);

// Add nonce extension when the nonce feature is enabled,
// otherwise skip this line
$requestBody->addNonceExtension(random_bytes(8));

// Send request to OCSP responder URL
$curl = curl_init();
curl_setopt($curl, CURLOPT_URL, $ocspResponderUrl);
curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
curl_setopt($curl, CURLOPT_POST, true);
curl_setopt($curl, CURLOPT_HTTPHEADER, ["Content-Type: " . Ocsp::OCSP_REQUEST_MEDIATYPE]);
curl_setopt($curl, CURLOPT_POSTFIELDS, $requestBody->getEncodeDer());
$result = curl_exec($curl);
$info = curl_getinfo($curl);
if ($info["http_code"] !== 200) {
    throw new RuntimeException("HTTP status is not 200");
}

// Check the response content type
if ($info["content_type"] != Ocsp::OCSP_RESPONSE_MEDIATYPE) {
    throw new RuntimeException("Content-Type header of the response is wrong");
}

// Decode the raw response from the OCSP Responder
$response = new OcspResponse($result);

// Validate response certificateId
$response->validateCertificateId($certificateId);

// Validate response signature
$response->validateSignature();

// Validate nonce when the nonce feature is enabled,
$basicResponse = $response->getBasicResponse();
if ($requestBody->getNonceExtension() != $basicResponse->getNonceExtension()) {
    throw new RuntimeException("OCSP request nonce and response nonce do not match");
}
```

`$response` contains instance of the `OCSP\OcspResponse` class:

* `$response->isRevoked() === false` when the certificate is not revoked
* `$response->isRevoked() === true` when the certificate is revoked (to get revoke reason, call
  `$response->getRevokeReason()`)
* when `$response->isRevoked()` returns `null`, then the certificate revoke status is unknown

To get more detailed information from the response you can use:

```php
$response->getStatus();
$basicResponse = $response->getBasicResponse();
```

Following methods can be called with `$basicResponse`:

* `$basicResponse->getResponses()` - returns array of the responses
* `$basicResponse->getCertificates()` - returns array of X.509 certificates (phpseclib3\File\X509)
* `$basicResponse->getSignature()` - returns signature
* `$basicResponse->getProducedAt()` - returns DateTime object
* `$basicResponse->getThisUpdate()` - returns DateTime object
* `$basicResponse->getNextUpdate()` - returns DateTime object (is `null` when `nextUpdate` field does not exist)
* `$basicResponse->getSignatureAlgorithm()` - returns signature algorithm as string (throws exception, when signature algorithm is not implemented)
* `$basicResponse->getNonceExtension()` - returns nonce (when value is `null` then nonce extension does not exist in response)
* `$basicResponse->getCertID()` - returns response certificateID

To get the full response for debugging or logging purposes, use `$response->getResponse()`
