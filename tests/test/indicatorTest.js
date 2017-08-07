var assert = chai.assert;

var indicatorTypes = [
  {
    indicatorType: "address",
    indicator: "0.0.0.0"
  },
  {
    indicatorType: "emailaddress",
    indicator: "adversary@example.com"
  },
  {
    indicatorType: "file",
    indicator: {
      md5: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      sha1: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  },
  {
    indicatorType: "host",
    indicator: "example.com"
  },
  {
    indicatorType: "url",
    indicator: "http://example.com/"
  }
];

describe('ThreatConnect Indicators', function() {
  var tc = new ThreatConnect(apiSettings);

  for (var i = 0; i <= indicatorTypes.length - 1; i++) {
    describe(indicatorTypes[i].indicatorType, function() {
      var indicatorType = indicatorHelper(indicatorTypes[i].indicatorType);
      var indicator = indicatorTypes[i].indicator;

      /* Test commit indicators. */
      describe('#commit()', function() {
        it('should commit without error', function(done) {
          // re-initialize instance of indicator class
          var indicators = tc.indicators();

          indicators.owner(testOwner)
            .indicator(indicator)
            .type(indicatorType)
            .done(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            })
            .error(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            });

          indicators.commit(done);
        });
      });
      /* Test retrieve indicators. */
      describe('#retrieve()', function() {
        it('should retrieve at least one result', function(done) {
          // re-initialize instance of indicators class
          var indicators = tc.indicators();

          indicators.owner(testOwner)
            .type(indicatorType)
            .done(function(response) {
              // make sure there is at least one indicator of the current type (we just created one so there should be)
              assert.isAbove(response.data.length, 0);
              // make sure there are no errors
              assert.equal(response.error, undefined);
            })
            .error(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            });

          indicators.retrieve(done);
        });
      });
      /* Test delete indicators. */
      describe('#delete()', function() {
        it('should delete without error', function(done) {
          // re-initialize instance of indicators class
          var indicators = tc.indicators();

          indicators.owner(testOwner)
            .indicator(indicator)
            .type(indicatorType)
            .done(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            })
            .error(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            });

          indicators.delete(done);
        });
      });
    });
  }
});
