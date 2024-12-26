<?php

namespace OCSP\Util;

enum HashAlgorithm: string
{
    case SHA1 = "sha1";
    case SHA256 = "sha256";
}
