module github.com/codeGROOVE-dev/prcost

go 1.25.4

require (
	github.com/codeGROOVE-dev/bdcache v0.6.1
	github.com/codeGROOVE-dev/bdcache/persist/cloudrun v0.0.0-20251121210535-3893c2b92813
	github.com/codeGROOVE-dev/gsm v0.0.0-20251019065141-833fe2363d22
	github.com/codeGROOVE-dev/prx v0.0.0-20251109164430-90488144076d
	github.com/codeGROOVE-dev/turnclient v0.0.0-20251107215141-ee43672b3dc7
	golang.org/x/time v0.14.0
)

require (
	github.com/codeGROOVE-dev/bdcache/persist/datastore v0.0.0 // indirect
	github.com/codeGROOVE-dev/bdcache/persist/localfs v0.0.0 // indirect
	github.com/codeGROOVE-dev/ds9 v0.7.1 // indirect
	github.com/codeGROOVE-dev/retry v1.3.0 // indirect
)

replace (
	github.com/codeGROOVE-dev/bdcache/persist/datastore => github.com/codeGROOVE-dev/bdcache/persist/datastore v0.0.0-20251121210535-3893c2b92813
	github.com/codeGROOVE-dev/bdcache/persist/localfs => github.com/codeGROOVE-dev/bdcache/persist/localfs v0.0.0-20251121210535-3893c2b92813
)
