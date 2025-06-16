# IntelMQ Extensions

This project collects customized bots used primary by CERT.at.

## Usage

Install the package on the machine. Then, it's enough to just declare the bot's module
pointing to this package, e.g. `intelmq_extensions.bots.collectors.xmpp`



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