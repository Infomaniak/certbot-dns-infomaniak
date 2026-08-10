certbot-dns-infomaniak
======================

Infomaniak_ DNS Authenticator plugin for certbot_

This plugin enables usage of Infomaniak public API to complete ``dns-01`` challenges.

.. _Infomaniak: https://www.infomaniak.com/
.. _certbot: https://certbot.eff.org/

Issue a token
-------------

At your Infomaniak manager dashboard_, go to the API section and generate a token
with ``dns:read`` and ``dns:write`` scopes.

.. _dashboard: https://manager.infomaniak.com/v3/ng/profile/user/token/list


Installation
------------

.. code-block:: bash

    pip install certbot-dns-infomaniak

Usage
-----

Via environment variable
^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

   export INFOMANIAK_API_TOKEN=xxx
   certbot certonly \
     --authenticator dns-infomaniak \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     -d 'death.star'

If certbot requires elevated rights, the following command must be used instead:

.. code-block:: bash

   export INFOMANIAK_API_TOKEN=xxx
   sudo --preserve-env=INFOMANIAK_API_TOKEN certbot certonly \
     --authenticator dns-infomaniak \
     --server https://acme-v02.api.letsencrypt.org/directory \
     --agree-tos \
     --rsa-key-size 4096 \
     -d 'death.star'

Via INI file
^^^^^^^^^^^^

Certbot will emit a warning if it detects that the credentials file can be
accessed by other users on your system. The warning reads "Unsafe permissions
on credentials configuration file", followed by the path to the credentials
file. This warning will be emitted each time Certbot uses the credentials file,
including for renewal, and cannot be silenced except by addressing the issue
(e.g., by using a command like ``chmod 600`` to restrict access to the file).

===================================  ==========================================
``--authenticator dns-infomaniak``   select the authenticator plugin (Required)
``--dns-infomaniak-credentials``     Infomaniak Token credentials
                                     INI file. (Required)
===================================  ==========================================

An example ``credentials.ini`` file:

.. code-block:: ini

   dns_infomaniak_token = XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


To start using DNS authentication for Infomaniak, pass the following arguments on certbot's command line:


.. code-block:: bash

  certbot certonly \
    --authenticator dns-infomaniak \
    --dns-infomaniak-credentials <path to file> \
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

.. code-block:: bash

   Environment="INFOMANIAK_API_TOKEN=<YOUR_API_TOKEN>"

Local Development
-----------------

Usage of `uv`_ to manage virtual environments and dependencies as defined in ``pyproject.toml`` is strongly recommended.

.. _uv: https://docs.astral.sh/uv/

Simply run ``uv sync`` to automatically create or update the ``.venv``. Usual activation is not required as all tools can simply be run within the project's environment through ``uv run...``, (eg. ``uv run ruff check``, ``uv run pytest``), eliminating the need for manual requirements management.

Acknowledgments
---------------

Based on certbot-dns-ispconfig plugin at https://github.com/m42e/certbot-dns-ispconfig/
