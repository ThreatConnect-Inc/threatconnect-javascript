# ThreatConnect Javascript SDK Testing Framework

This is a framework for testing the ThreatConnect Javascript SDK. It uses [mocha](https://mochajs.org/) and [chai](http://chaijs.com/) and the results will be provided in a browser (it works best with Firefox).

## Usage

Assuming you have this repository cloned locally, do the following to the run the tests:

1. The test runner expects a tc.conf.js file in the `/tests/` directory. If you have a tc.conf.js file, move it into the `/tests/` directory. If not, create a tc.conf.js as detailed below and move it to the right location:

```
var apiSettings = {
    apiId: '12345678901234567890',
    apiSec: 'typeyourapisecuritykeyhere',
    apiUrl: 'https://app.threatconnect.com/api'
};
```

2. To run the tests, move into the `/tests/` and run `make test`. This will open the test results in the browser for triage.

```
cd /tests/
make test
```
