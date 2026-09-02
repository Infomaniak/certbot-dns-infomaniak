Traefik with Let's Encrypt (certbot-dns-infomaniak)
===================================================

Example setup for a Traefik v3 reverse proxy with wildcard certificates from
Let's Encrypt, using the `certbot-dns-infomaniak`_ plugin for DNS-01 challenges.

.. _certbot-dns-infomaniak: https://github.com/ootwch/certbot-dns-infomaniak

What it does
------------

- **reverse-proxy** (Traefik v3) — TLS termination on ports 80/443, HTTP→HTTPS redirect
- **homepage** — Dashboard (gethomepage/homepage) served at your domain
- **create_or_renew_certificate** — Obtains and renews wildcard certs via Infomaniak DNS API (manual run)

Prerequisites
-------------

- Docker and Docker Compose
- Domain with DNS at Infomaniak
- Infomaniak API token with Domain scope

Setup
-----

1. Clone or download this directory.

2. Create credentials and config:

.. code-block:: bash

 cp infomaniak_credentials.ini.example infomaniak_credentials.ini
 cp .env.example .env

3. Edit the files:

   - ``infomaniak_credentials.ini`` — Replace ``YOUR_INFOMANIAK_API_TOKEN`` with your token from `Infomaniak API`_
   - ``.env`` — Set ``CERTBOT_DOMAIN`` to your domain (e.g. ``example.com``)

.. _Infomaniak API: https://manager.infomaniak.com/v3/infomaniak-api

Usage
-----

Get certificates (run once, or when renewing)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: bash

 docker compose run create_or_renew_certificate

Create or update the txt records in your domain when asked.

This obtains the wildcard cert and creates ``traefik-tls.yml`` in the letsencrypt volume.

This certificate will not auto-renew, but if you run the same command again it will renew it automatically without further manual change to the DNS being required. It will also skip the renewal if the certificate is not close to expiry yet.

.. code-block:: bash

 docker compose run create_or_renew_certificate

Feel free to schedule this command to update the cert automatically.

Start the stack
^^^^^^^^^^^^^^^

.. code-block:: bash

 docker compose up -d

Homepage is available at ``https://<your-domain>``.

Adding more services
--------------------

Place other containers on the ``proxy-net`` network and add Traefik labels. Example:

.. code-block:: yaml

 labels:
   - "traefik.enable=true"
   - "traefik.http.routers.myservice.rule=Host(`myservice.example.com`)"
   - "traefik.http.routers.myservice.tls=true"
   - "traefik.http.services.myservice.loadbalancer.server.port=80"
 networks:
   - proxy

Files
-----

====================== ====================================================
File                   Purpose
====================== ====================================================
``docker-compose.yml`` Service definitions
``infomaniak_credentials.ini.example`` Template for Infomaniak API credentials
``.env.example``       Template for domain and other variables
``config/``            Homepage dashboard configuration
====================== ====================================================

``.env`` and ``infomaniak_credentials.ini`` are ignored by git; do not commit them.

Acknowledgments
---------------

This setup was created with assistance from `Cursor`_ (AI-powered code editor).

.. _Cursor: https://cursor.com/
