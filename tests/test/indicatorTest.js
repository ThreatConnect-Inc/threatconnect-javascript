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
        .size(12345)
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
  /* Test adding a file action to a file. */
  describe('File Archive Action', function() {
    var indicatorType = indicatorHelper('file');

    // create an indicator with which we will associate the file
    var indicators = tc.indicators();
    var new_indicator = {
      indicator: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
      type: TYPE.FILE
    };

    indicators.owner(testOwner)
      .indicator({
        md5: new_indicator.indicator
      })
      .type(new_indicator.type)
      .done(function(response) {
        // make sure there are no errors
        assert.equal(response.error, undefined);
      })
      .error(function(response) {
        console.error("Error: ", response);
      });

    indicators.commit();

    it('should commit without error', function(done) {
      // re-initialize instance of indicator class
      var indicators = tc.indicators();

      indicators.owner(testOwner)
        .indicator(testFile)
        .type(indicatorType)
        .done(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        })
        .error(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        });

      indicators.commitFileAction('archive', {
          type: new_indicator.type,
          id: new_indicator.indicator
      });
    });
  });
  /* Test adding a file action to a file. */
  describe('File Drop Action', function() {
    var indicatorType = indicatorHelper('file');

    // create an indicator with which we will associate the file
    var indicators = tc.indicators();
    var new_indicator = {
      indicator: 'cccccccccccccccccccccccccccccccc',
      type: TYPE.FILE
    };

    indicators.owner(testOwner)
      .indicator({
        md5: new_indicator.indicator
      })
      .type(new_indicator.type)
      .done(function(response) {
        // make sure there are no errors
        assert.equal(response.error, undefined);
      })
      .error(function(response) {
        console.error("Error: ", response);
      });

    indicators.commit();

    it('should commit without error', function(done) {
      // re-initialize instance of indicator class
      var indicators = tc.indicators();

      indicators.owner(testOwner)
        .indicator(testFile)
        .type(indicatorType)
        .done(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        })
        .error(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        });

      indicators.commitFileAction('drop', {
          type: new_indicator.type,
          id: new_indicator.indicator
      });
    });
  });
  /* Test adding a file action to a file. */
  describe('File Traffic Action (to IP Address)', function() {
    var indicatorType = indicatorHelper('file');

    // create an indicator with which we will associate the file
    var indicators = tc.indicators();
    var new_indicator = {
      indicator: '1.2.3.4',
      type: TYPE.ADDRESS
    };

    indicators.owner(testOwner)
      .indicator(new_indicator.indicator)
      .type(new_indicator.type)
      .done(function(response) {
        // make sure there are no errors
        assert.equal(response.error, undefined);
      })
      .error(function(response) {
        // make sure there are no errors
        assert.equal(response.error, undefined);
      });

    indicators.commit();

    it('should commit without error', function(done) {
      // re-initialize instance of indicator class
      var indicators = tc.indicators();

      indicators.owner(testOwner)
        .indicator(testFile)
        .type(indicatorType)
        .done(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        })
        .error(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        });

      indicators.commitFileAction('traffic', {
          type: new_indicator.type,
          id: new_indicator.indicator
      });
    });
  });
  /* Test adding a file action to a file. */
  describe('File Traffic Action (to Host)', function() {
    var indicatorType = indicatorHelper('file');

    // create an indicator with which we will associate the file
    var indicators = tc.indicators();
    var new_indicator = {
      indicator: 'example.com',
      type: TYPE.HOST
    };

    indicators.owner(testOwner)
      .indicator(new_indicator.indicator)
      .type(new_indicator.type)
      .done(function(response) {
        // make sure there are no errors
        assert.equal(response.error, undefined);
      })
      .error(function(response) {
        // make sure there are no errors
        assert.equal(response.error, undefined);
      });

    indicators.commit();

    it('should commit without error', function(done) {
      // re-initialize instance of indicator class
      var indicators = tc.indicators();

      indicators.owner(testOwner)
        .indicator(testFile)
        .type(indicatorType)
        .done(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        })
        .error(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        });

      indicators.commitFileAction('traffic', {
          type: new_indicator.type,
          id: new_indicator.indicator
      });
    });
  });
  /* Test adding a file action to a file. */
  describe('File Traffic Action (to URL)', function() {
    var indicatorType = indicatorHelper('file');

    // create an indicator with which we will associate the file
    var indicators = tc.indicators();
    var new_indicator = {
      indicator: 'http://example.com',
      type: TYPE.URL
    };

    indicators.owner(testOwner)
      .indicator(new_indicator.indicator)
      .type(new_indicator.type)
      .done(function(response) {
        // make sure there are no errors
        assert.equal(response.error, undefined);
      })
      .error(function(response) {
        // make sure there are no errors
        assert.equal(response.error, undefined);
      });

    indicators.commit();

    it('should commit without error', function(done) {
      // re-initialize instance of indicator class
      var indicators = tc.indicators();

      indicators.owner(testOwner)
        .indicator(testFile)
        .type(indicatorType)
        .done(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        })
        .error(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        });

      indicators.commitFileAction('traffic', {
          type: new_indicator.type,
          id: new_indicator.indicator
      });
    });
  });
  // /* Test adding a file action to a file. */
  // describe('File Mutex Action', function() {
  //   var indicatorType = indicatorHelper('file');

  //   // create an indicator with which we will associate the file
  //   var indicators = tc.indicators();
  //   var new_indicator = {
  //     indicator: 'test',
  //     type: TYPE.MUTEX
  //   };

  //   indicators.owner(testOwner)
  //     .indicator(new_indicator.indicator)
  //     .type(new_indicator.type)
  //     .done(function(response) {
  //       // make sure there are no errors
  //       assert.equal(response.error, undefined);
  //     })
  //     .error(function(response) {
  //       // make sure there are no errors
  //       assert.equal(response.error, undefined);
  //     });

  //   indicators.commit();

  //   it('should commit without error', function(done) {
  //     // re-initialize instance of indicator class
  //     var indicators = tc.indicators();

  //     indicators.owner(testOwner)
  //       .indicator(testFile)
  //       .type(indicatorType)
  //       .done(function(response) {
  //         // make sure there are no errors
  //         assert.equal(response.error, undefined);
  //       })
  //       .error(function(response) {
  //         // make sure there are no errors
  //         assert.equal(response.error, undefined);
  //       });

  //     indicators.commitFileAction('mutex', {
  //         type: new_indicator.type,
  //         id: new_indicator.indicator
  //     });
  //   });
  // });
  // /* Test adding a file action to a file. */
  // describe('File registryKey Action', function() {
  //   var indicatorType = indicatorHelper('file');

  //   // create an indicator with which we will associate the file
  //   var indicators = tc.indicators();
  //   var new_indicator = {
  //     indicator: {
  //         "Key Name": "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Hardware Profiles\Current",
  //         "Value Name": "Autopopulate",
  //         "Value Type": "REG_DWORD"
  //     },
  //     type: TYPE.REGISTRYKEY
  //   };

  //   indicators.owner(testOwner)
  //     .indicator(new_indicator.indicator)
  //     .type(new_indicator.type)
  //     .done(function(response) {
  //       // make sure there are no errors
  //       assert.equal(response.error, undefined);
  //     })
  //     .error(function(response) {
  //       // make sure there are no errors
  //       assert.equal(response.error, undefined);
  //     });

  //   indicators.commit();

  //   it('should commit without error', function(done) {
  //     // re-initialize instance of indicator class
  //     var indicators = tc.indicators();

  //     indicators.owner(testOwner)
  //       .indicator(testFile)
  //       .type(indicatorType)
  //       .done(function(response) {
  //         // make sure there are no errors
  //         assert.equal(response.error, undefined);
  //       })
  //       .error(function(response) {
  //         // make sure there are no errors
  //         assert.equal(response.error, undefined);
  //       });

  //     indicators.commitFileAction('registryKey', {
  //         type: new_indicator.type,
  //         id: new_indicator.indicator
  //     });
  //   });
  // });
  // /* Test adding a file action to a file. */
  // describe('File userAgent Action', function() {
  //   var indicatorType = indicatorHelper('file');

  //   // create an indicator with which we will associate the file
  //   var indicators = tc.indicators();
  //   var new_indicator = {
  //     indicator: 'PeachWebKit/100.00 (KHTML, like Nothing Else)',
  //     type: TYPE.USERAGENT
  //   };

  //   indicators.owner(testOwner)
  //     .indicator(new_indicator.indicator)
  //     .type(new_indicator.type)
  //     .done(function(response) {
  //       // make sure there are no errors
  //       assert.equal(response.error, undefined);
  //     })
  //     .error(function(response) {
  //       // make sure there are no errors
  //       assert.equal(response.error, undefined);
  //     });

  //   indicators.commit();

  //   it('should commit without error', function(done) {
  //     // re-initialize instance of indicator class
  //     var indicators = tc.indicators();

  //     indicators.owner(testOwner)
  //       .indicator(testFile)
  //       .type(indicatorType)
  //       .done(function(response) {
  //         // make sure there are no errors
  //         assert.equal(response.error, undefined);
  //       })
  //       .error(function(response) {
  //         // make sure there are no errors
  //         assert.equal(response.error, undefined);
  //       });

  //     indicators.commitFileAction('userAgent', {
  //         type: new_indicator.type,
  //         id: new_indicator.indicator
  //     });
  //   });
  // });
  /* Test adding a file action to a file. */
  describe('File dnsQuery Action', function() {
    var indicatorType = indicatorHelper('file');

    // create an indicator with which we will associate the file
    var indicators = tc.indicators();
    var new_indicator = {
      indicator: 'example.com',
      type: TYPE.HOST
    };

    indicators.owner(testOwner)
      .indicator(new_indicator.indicator)
      .type(new_indicator.type)
      .done(function(response) {
        // make sure there are no errors
        assert.equal(response.error, undefined);
      })
      .error(function(response) {
        // make sure there are no errors
        assert.equal(response.error, undefined);
      });

    indicators.commit();

    it('should commit without error', function(done) {
      // re-initialize instance of indicator class
      var indicators = tc.indicators();

      indicators.owner(testOwner)
        .indicator(testFile)
        .type(indicatorType)
        .done(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        })
        .error(function(response) {
          // make sure there are no errors
          assert.equal(response.error, undefined);
        });

      indicators.commitFileAction('dnsQuery', {
          type: new_indicator.type,
          id: new_indicator.indicator
      });
    });
  });
  /* Test adding a file with a file occurrence. */
  describe('File Occurrence', function() {
    var indicatorType = indicatorHelper('file');

    /* Test file occurrence commit. */
    describe('#commit()', function() {
      it('should commit without error', function(done) {
        // re-initialize instance of indicator class
        var indicators = tc.indicators();

        indicators.owner(testOwner)
          .indicator(testFile)
          .type(indicatorType)
          .done(function(response) {
            // make sure there are no errors
            assert.equal(response.error, undefined);
          })
          .error(function(response) {
            // make sure there are no errors
            assert.equal(response.error, undefined);
          });

        indicators.commitFileOccurrence({
            "fileName": "filename.dll",
            "path": "C:\\\\test\\System",
            "date": "2017-11-13T05:00:00Z"
          });
      });
    });
    /* Test file occurrence retrieval. */
    describe('#retrieve()', function() {
      it('should commit without error', function(done) {
        // re-initialize instance of indicator class
        var indicators = tc.indicators();

        indicators.owner(testOwner)
          .indicator(testFile)
          .type(indicatorType)
          .done(function(response) {
            // make sure there are no errors
            assert.equal(response.data.resultCount, 1);
            // delete the file indicator we just created
            deleteIndicator(testFile, indicatorType);
          })
          .error(function(response) {
            // make sure there are no errors
            assert.equal(response.error, undefined);
          })
          .fileOccurrences();
      });
    });
  });
});
