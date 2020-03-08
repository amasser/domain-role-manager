Session Role Manager [![Coverage Status](https://coveralls.io/repos/github/dovics/domain-role-manager/badge.svg?branch=master)](https://coveralls.io/github/dovics/domain-role-manager?branch=master) [![Build Status](https://travis-ci.org/dovics/domain-role-manager.svg?branch=master)](https://travis-ci.org/dovics/domain-role-manager) 
====

Domain Role Manager is the role manager for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can use matching func in domain

## Installation

    go get github.com/dovics/domain-role-manager

## Simple Example

```go
package main

import (
	"github.com/casbin/casbin/v2"
	"github.com/dovics/domain-role-manager"
)

func main() {
	e, _ := casbin.NewEnforcer("examples/domainmatch_model.conf","examples/domainmatch_policy.csv")

	// Use our role manager.
	rm := domainrolemanager.NewRoleManager(10)
	e.SetRoleManager(rm)

	// If our role manager relies on Casbin policy (like reading "g"
	// policy rules), then we have to set the role manager before loading
	// policy.
	//
	// Otherwise, we can set the role manager at any time, because role
	// manager has nothing to do with the adapter.
	e.LoadPolicy()
	
	// Check the permission.
	e.Enforce("alice", "domain1", "data1", "read")
}
```

## Getting Help

- [Casbin](https://github.com/casbin/casbin)

## License

This project is under Apache 2.0 License. See the [LICENSE](LICENSE) file for the full license text.
