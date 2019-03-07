Run tests with the "WarpedEpoch" build time flag set to "true" to decrease epochtime.Period to 2 minutes and the pki recheck interval to 20 seconds.

Pass this flag at test time like this:

  go test -timeout 0 -ldflags "-X github.com/katzenpost/kimchi/vendor/github.com/katzenpost/core/epochtime.WarpedEpoch=true -X github.com/katzenpost/kimchi/vendor/github.com/katzenpost/server/internal/pki.WarpedEpoch=true"

You can specify a specific test to run with the -run option, e.g.

  go test -timeout 0 -ldflags "-X github.com/katzenpost/kimchi/vendor/github.com/katzenpost/core/epochtime.WarpedEpoch=true -X github.com/katzenpost/kimchi/vendor/github.com/katzenpost/server/internal/pki.WarpedEpoch=true" -run TestAuthorityJoinConsensus
