# IntelMQ Extensions

[![Running tests](https://github.com/certat/intelmq-extensions/actions/workflows/ci.yml/badge.svg)](https://github.com/certat/intelmq-extensions/actions/workflows/ci.yml)

This project collects customized bots and some helper scripts for
[IntelMQ](https://github.com/certtools/intelmq) used primary by CERT.at.

It's a combination of customization previously available in [certat/intelmq](https://github.com/certat/intelmq)
as well as newer solutions.

## Usage

Install the package on the machine or virtualenv, where you have the IntelMQ, using
`pip install intelmq-extensions`. Then, the bots will be available as any other IntelMQ
bot in the Manager as well to import using `intelmq.bots.*.certat` namespace, e.g.
`intelmq.bots.experts.certat.vulnerability_lookup.expert`

## Documentation

There is a limited documentation available. Consult bot Python code to see information
about the usage and available configuration.

## Running tests

This package comes with test runners configured using `tox`. To use them:

```bash

    tox -elint  # run code style checks
    tox -epy310  # run simple unittests against Python 3.10

    # For running all unittests, including connecting to external services / database
    # use on of the following:
    tox -efull  # assuming you run redis, postgres etc. on your own
    tox -efull-with-docker  # this will use docker compose to provision services for tests;
                            # please note it uses default ports

    # You can pass arguments to the pytest, e.g. to run a specific test:
    tox -efull-with-docker -- intelmq_extensions/tests/bots/experts/squelcher/test_expert.py::TestSquelcherExpertBot::test_address_match1

```

---

Part of the development was financed by the European Union.

![CEF-Logo](https://github.com/certat/intelmq-extensions/blob/main/docs/cef_logo.png?raw=true)