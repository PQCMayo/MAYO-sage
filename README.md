# MAYO-sage

This is the sage implementation of our MAYO scheme. Learn about it on our [website](https://pqmayo.org/).

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

In order to run, you can either type:

```
   make run (pure sage version)
   make run-python (python/sage version)
```

## Testing

In order to test the library, run:

```
   make test
```

## Vectors

To generate the vectors, run:

```
   make vectors
```
