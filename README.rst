certbot-dns-infomaniak
======================

Infomaniak_ DNS Authenticator plugin for certbot_

This plugin enables usage of Infomaniak public API to complete ``dns-01`` challenges.

.. _Infomaniak: https://www.infomaniak.com/
.. _certbot: https://certbot.eff.org/

Issue a token
-------------

At your Infomaniak manager dashboard_, to to the API section and generate a token
with "Domain" scope

.. _dashboard: https://manager.infomaniak.com/v3/infomaniak-api

Then, export this token as an environment variable:

::

    export INFOMANIAK_API_TOKEN=xxx

Installation
------------

::

    pip install certbot-dns-infomaniak

Usage
-----

.. code-block:: bash

   export INFOMANIAK_API_TOKEN=xxx
   certbot certonly \
     --authenticator certbot-dns-infomaniak:dns-infomaniak \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     -d 'death.star'

If certbot requires elevated rights, the following command must be used instead:

.. code-block:: bash

   export INFOMANIAK_API_TOKEN=xxx
   sudo --preserve-env=INFOMANIAK_API_TOKEN certbot certonly \
     --authenticator certbot-dns-infomaniak:dns-infomaniak \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     -d 'death.star'

Automatic renewal
-----------------

By default, certbot installs a service that periodically renews its
certificates automatically. In order to do this, the command must know the API
key, otherwise it will fail silently.

In order to enable automatic renewal for your wildcard certificates, you will
need to edit ``/lib/systemd/system/certbot.service``. In there, add the
following line in ``Service``, with <YOUR_API_TOKEN> replaced with your actual
token:

::

   Environment="INFOMANIAK_API_TOKEN=<YOUR_API_TOKEN>"

Acknowledgments
---------------

Based on certbot-dns-ispconfig plugin at https://github.com/m42e/certbot-dns-ispconfig/
