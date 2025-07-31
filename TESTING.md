# Testing

_For details on how to write integration tests and a deep dive into the testing utilities of the collection, check out the [README within the `tests` directory](./tests/README.md)._

The collection uses the [pytest](https://pytest.org) to run a set of integration tests for the majority of the modules and plugins.  The tests require a functioning _minimally_ configured deployment of Cloudera Manager and its agents.

> [!IMPORANT]
> The Cloudera Manager Service nor a cluster are required for testing; the tests will construct the appropriate resources as needed.
>
> You must provide at minimum **three (3) servers** within the deployment.

All (or most of) the tests require the following environment variables:

- `CM_USERNAME`
- `CM_PASSWORD`
- `CDH_VERSION`

And either:

- `CM_HOST`
- `CM_PORT`

Or:
 
- `CM_ENDPOINT` (which is the full URL to the Cloudera Manager API endpoint)

Optionally,

- `CM_PROXY`

Running the tests from the CLI is simply a `pytest` execution.
