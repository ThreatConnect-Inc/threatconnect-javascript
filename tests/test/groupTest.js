var assert = chai.assert;

var groupTypes = ["adversary", "campaign", "email", "incident", "signature", "threat"];

describe('ThreatConnect Groups', function() {
  var tc = new ThreatConnect(apiSettings);

  for (var i = 0; i <= groupTypes.length - 1; i++) {
    describe(groupTypes[i], function() {
      var groupType = groupHelper(groupTypes[i]);
      var groupId;

      /* Test commit groups. */
      describe('#commit()', function() {
        it('should commit without error', function(done) {
          // re-initialize instance of groups class
          var groups = tc.groups();

          groups.owner(testOwner)
            .name('test group')
            .type(groupType)
            .done(function(response) {
              // get the ID of the recently created group
              groupId = response.data[0].id;
              // make sure there are no errors
              assert.equal(response.error, undefined);
            })
            .error(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            });

          groups.commit(done);
        });
      });
      /* Test retrieve groups. */
      describe('#retrieve()', function() {
        it('should retrieve at least one result', function(done) {
          // re-initialize instance of groups class
          var groups = tc.groups();

          groups.owner(testOwner)
            .type(groupType)
            .done(function(response) {
              // make sure there is at least one group of the current type (we just created one so there should be)
              assert.isAbove(response.data.length, 0);
              // make sure there are no errors
              assert.equal(response.error, undefined);
            })
            .error(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            });

          groups.retrieve(done);
        });
      });
      /* Test delete groups. */
      describe('#delete()', function() {
        it('should delete without error', function(done) {
          // re-initialize instance of groups class
          var groups = tc.groups();

          groups.owner(testOwner)
            .id(groupId)
            .type(groupType)
            .done(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            })
            .error(function(response) {
              // make sure there are no errors
              assert.equal(response.error, undefined);
            });

          groups.delete(done);
        });
      });
    });
  }
});
