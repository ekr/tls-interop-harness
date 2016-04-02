# tls-interop-harness

Very rough instructions:

- Download and build OpenSSL source (https://www.openssl.org/) to ```$(OPENSSL_ROOT)```
- Download and build NSS (https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_Sources_Building_Testing) to ```$(NSS_ROOT)```
  - Run the NSS tests to populate a cert database ```cd tests; NSS_TESTS=ssl_gtests NSS_CYCLES=standard ./all.sh```. This will make something in ```$(NSS_ROOT)/test-results/<something>/ssl_gtests```. Call that ```$(NSS_CERT_DIR)```

Then run:
~~~
python tls-interop.py --openssldir=$(OPENSSL_ROOT) --nssdir=$(NSS_ROOT) --nss_cert_dir=$(NSS_CERT_DIR)
~~~

