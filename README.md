# MAYO-sage

![MAYO-sage workflow](https://github.com/PQCMayo/MAYO-sage/actions/workflows/python-app.yml/badge.svg)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

This is the sage implementation of our MAYO scheme. Learn about it on our [website](https://pqmayo.org/).

*Warning*: This code is a research prototype. Do not use it in production.

## Requirements

In order to natively build, run, test and benchmark the library, you will need the following:

```
  Make
  Python3 >= 3.9.7
  pycryptodomex (please, install this version to avoid bugs with pycrypto.
                 Install it on sage by running 'sage --pip install pycryptodomex')
  Sage
```

## Building and running

In order to run, you can type:

```
   make run (pure sage version)
```

## Testing

In order to test the library, run:

```
   make test
```

## Testing against the KAT

In order to test the KAT of the library, run:

```
   make kat-test
```

## Vectors

To generate the vectors, run:

```
   make vectors
```
