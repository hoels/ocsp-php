<?php

/*
 * Copyright (c) 2020-2021 Estonian Information System Authority
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

namespace web_eid\ocsp_php\maps;

use phpseclib3\File\ASN1;

abstract class OcspResponseMap
{
    public const MAP = [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
            'responseStatus' => [
                'type' => ASN1::TYPE_ENUMERATED,
                'mapping' => [
                    0 => 'successful',
                    1 => 'malformedRequest',
                    2 => 'internalError',
                    3 => 'tryLater',
                    5 => 'sigRequired',
                    6 => 'unauthorized',
                ],
            ],
            'responseBytes' => [
                'constant' => 0,
                'explicit' => true,
                'optional' => true,
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => array(
                    'responseType' => array('type' => ASN1::TYPE_OBJECT_IDENTIFIER),
                    'response' => array('type' => ASN1::TYPE_OCTET_STRING),
                ),
            ],
        ],
    ];

}