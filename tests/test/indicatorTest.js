var assert = chai.assert;
var tc = new ThreatConnect(apiSettings);

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

function deleteIndicator(indicator, indicatorType) {
  /* Test indicator deletion. */
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
}

describe('ThreatConnect Indicators', function() {
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
      describe('#retrieve multiple()', function() {
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
      /* Test retrieving a specific indicator. */
      describe('#retrieve single()', function() {
        it('should retrieve at least one result', function(done) {
          // re-initialize instance of indicators class
          var indicators = tc.indicators();

          indicators.owner(testOwner)
            .type(indicatorType)
            .indicator(indicator)
            .done(function(response) {
              // make sure there is at least one indicator of the current type (we just created one so there should be)
              assert.isAbove(response.data.length, 0);
              // make sure that the indicator is actually returned
              assert.notEqual(response.data[0].indicator, undefined);
              assert.notEqual(response.data[0].indicator, "");

              // if the current indicator type is a file, make sure the indicator is an Object
              if (indicatorType.type === "File") {
                assert.isObject(response.data[0].indicator);
              } else {  // if the indicator type is not a file, make sure the response is a string
                assert.isString(response.data[0].indicator);
              }

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
      /* Test update indicators. */
      describe('#update()', function() {
        it('should update without error', function(done) {
          // re-initialize instance of indicators class
          var indicators = tc.indicators();

          // test updating the indicator with a threat and confidence rating
          indicators.owner(testOwner)
            .indicator(indicator)
            .type(indicatorType)
            .rating(3)
            .confidence(50)
            .done(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            })
            .error(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            });

          indicators.update(done);
        });
      });
      /* Test indicator deletion. */
      deleteIndicator(indicator, indicatorType);
    });
  }
});

describe('File Indicator Specific Properties', function() {
  var testFile = {
    md5: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    sha1: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  };

  /* Test adding a file with a file size. */
  describe('File Size', function() {
    var indicatorType = indicatorHelper('file');

    it('should commit without error', function(done) {
      // re-initialize instance of indicator class
      var indicators = tc.indicators();

      indicators.owner(testOwner)
        .indicator(testFile)
        .size('afds')
        .type(indicatorType)
        .done(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
          // delete the file indicator we just created
          deleteIndicator(testFile, indicatorType);
        })
        .error(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        });

      indicators.commit(done);
    });
  });
});
