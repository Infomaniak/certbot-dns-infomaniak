certbot-dns-infomaniak
======================

Infomaniak DNS Authenticator plugin for certbot

This plugin enables usage of Infomaniak public API to complete``dns-01`` challenges.

Issue a token
-------------

At your Infomaniak manager dashboard, to to the API section and generate a token
with "Domain" scope

https://manager.infomaniak.com/v3/infomaniak-api

Then, export this token as an environment variable:

::

   export INFOMANIAK_API_TOKEN=xxx

Installation
------------

::

    pip install certbot-dns-infomaniak

Usage
-----

::

.. code-block:: bash

   export INFOMANIAK_API_TOKEN=xxx
   certbot certonly \
   --authenticator certbot-dns-infomaniak:dns-infomaniak \
   --server https://acme-staging-v02.api.letsencrypt.org/directory \
   --agree-tos \
   --rsa-key-size 4096 \
   -d 'death.star'

Acknowledgments
---------------

Based on certbot-dns-ispconfig plugin at https://github.com/m42e/certbot-dns-ispconfig/
