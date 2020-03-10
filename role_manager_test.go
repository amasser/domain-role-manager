// Copyright 2017 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package domainrolemanager

import (
	"net"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/rbac"
	"github.com/casbin/casbin/v2/util"
)

func testDomainRole(t *testing.T, rm rbac.RoleManager, name1 string, name2 string, domain string, res bool) {
	t.Helper()
	myRes, _ := rm.HasLink(name1, name2, domain)
	t.Logf("%s :: %s, %s: %t", domain, name1, name2, myRes)

	if myRes != res {
		t.Errorf("%s :: %s < %s: %t, supposed to be %t", domain, name1, name2, !res, res)
	}
}

func testPrintRoles(t *testing.T, rm rbac.RoleManager, name string, domain string, res []string) {
	t.Helper()
	myRes, _ := rm.GetRoles(name, domain)
	t.Logf("%s: %s", name, myRes)

	if !util.ArrayEquals(myRes, res) {
		t.Errorf("%s: %s, supposed to be %s", name, myRes, res)
	}
}

func testGetUsers(t *testing.T, rm rbac.RoleManager, name string, domain string, res []string) {
	t.Helper()
	myRes, _ := rm.GetUsers(name, domain)
	t.Logf("%s: %s", name, myRes)

	if !util.ArrayEquals(myRes, res) {
		t.Errorf("%s: %s, supposed to be %s", name, myRes, res)
	}
}

func testDomainEnforce(t *testing.T, e *casbin.Enforcer, sub string, dom string, obj string, act string, res bool) {
	t.Helper()
	if myRes, _ := e.Enforce(sub, dom, obj, act); myRes != res {
		t.Errorf("%s, %s, %s, %s: %t, supposed to be %t", sub, dom, obj, act, myRes, res)
	}
}

func TestDomainRole(t *testing.T) {
	rm := NewRoleManager(3)
	rm.AddLink("u1", "g1", "domain1")
	rm.AddLink("u2", "g1", "domain1")
	rm.AddLink("u3", "admin", "domain2")
	rm.AddLink("u4", "admin", "domain2")
	rm.AddLink("u4", "admin", "domain1")
	rm.AddLink("g1", "admin", "domain1")

	// Current role inheritance tree:
	//       domain1:admin    domain2:admin
	//            /       \  /       \
	//      domain1:g1     u4         u3
	//         /  \
	//       u1    u2

	testDomainRole(t, rm, "u1", "g1", "domain1", true)
	testDomainRole(t, rm, "u1", "g1", "domain2", false)
	testDomainRole(t, rm, "u1", "admin", "domain1", true)
	testDomainRole(t, rm, "u1", "admin", "domain2", false)

	testDomainRole(t, rm, "u2", "g1", "domain1", true)
	testDomainRole(t, rm, "u2", "g1", "domain2", false)
	testDomainRole(t, rm, "u2", "admin", "domain1", true)
	testDomainRole(t, rm, "u2", "admin", "domain2", false)

	testDomainRole(t, rm, "u3", "g1", "domain1", false)
	testDomainRole(t, rm, "u3", "g1", "domain2", false)
	testDomainRole(t, rm, "u3", "admin", "domain1", false)
	testDomainRole(t, rm, "u3", "admin", "domain2", true)

	testDomainRole(t, rm, "u4", "g1", "domain1", false)
	testDomainRole(t, rm, "u4", "g1", "domain2", false)
	testDomainRole(t, rm, "u4", "admin", "domain1", true)
	testDomainRole(t, rm, "u4", "admin", "domain2", true)

	rm.DeleteLink("g1", "admin", "domain1")
	rm.DeleteLink("u4", "admin", "domain2")

	// Current role inheritance tree after deleting the links:
	//       domain1:admin    domain2:admin
	//                    \          \
	//      domain1:g1     u4         u3
	//         /  \
	//       u1    u2

	testDomainRole(t, rm, "u1", "g1", "domain1", true)
	testDomainRole(t, rm, "u1", "g1", "domain2", false)
	testDomainRole(t, rm, "u1", "admin", "domain1", false)
	testDomainRole(t, rm, "u1", "admin", "domain2", false)

	testDomainRole(t, rm, "u2", "g1", "domain1", true)
	testDomainRole(t, rm, "u2", "g1", "domain2", false)
	testDomainRole(t, rm, "u2", "admin", "domain1", false)
	testDomainRole(t, rm, "u2", "admin", "domain2", false)

	testDomainRole(t, rm, "u3", "g1", "domain1", false)
	testDomainRole(t, rm, "u3", "g1", "domain2", false)
	testDomainRole(t, rm, "u3", "admin", "domain1", false)
	testDomainRole(t, rm, "u3", "admin", "domain2", true)

	testDomainRole(t, rm, "u4", "g1", "domain1", false)
	testDomainRole(t, rm, "u4", "g1", "domain2", false)
	testDomainRole(t, rm, "u4", "admin", "domain1", true)
	testDomainRole(t, rm, "u4", "admin", "domain2", false)
}

func TestDomainPartternRole(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddLink("u1", "g1", "domain1")
	rm.AddLink("u2", "g1", "domain2")
	rm.AddLink("u3", "g1", "*")
	rm.AddLink("u4", "g2", "domain3")
	// Current role inheritance tree after deleting the links:
	//       domain1:g1    domain2:g1			domain3:g2
	//		   /      \    /      \					|
	//	 domain1:u1    *:g1     domain2:u2		domain3:u4
	// 					|
	// 				   *:u3
	testDomainRole(t, rm, "u1", "g1", "domain1", true)
	testDomainRole(t, rm, "u2", "g1", "domain1", false)
	testDomainRole(t, rm, "u2", "g1", "domain2", true)
	testDomainRole(t, rm, "u3", "g1", "domain1", true)
	testDomainRole(t, rm, "u3", "g1", "domain2", true)
	testDomainRole(t, rm, "u1", "g2", "domain1", false)
	testDomainRole(t, rm, "u4", "g2", "domain3", true)
	testDomainRole(t, rm, "u3", "g2", "domain3", false)
	// use * when querying permissions，it will return true always, so I forbid to use * for query in domain
	testDomainRole(t, rm, "u3", "g2", "*", false)
	testDomainRole(t, rm, "u3", "g1", "*", false)
	testDomainRole(t, rm, "u2", "g1", "*", false)
	testDomainRole(t, rm, "u3", "g1", "*", false)
}

func TestPrintRoles(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddLink("u1", "g1", "domain1")
	rm.AddLink("u2", "g1", "domain2")
	rm.AddLink("u3", "g1", "*")
	rm.AddLink("u4", "g2", "domain3")
	// Current role inheritance tree after deleting the links:
	//       domain1:g1    domain2:g1			domain3:g2
	//		   /      \    /      \					|
	//	 domain1:u1    *:g1     domain2:u2		domain3:u4
	// 					|
	// 				   *:u3

	testPrintRoles(t, rm, "u3", "domain1", []string{"g1"})
	testPrintRoles(t, rm, "u1", "domain1", []string{"g1"})
	testPrintRoles(t, rm, "u3", "domain2", []string{"g1"})
	testPrintRoles(t, rm, "u1", "domain2", []string{})
	testPrintRoles(t, rm, "u4", "domain3", []string{"g2"})
}

func TestGetUsers(t *testing.T) {
	rm := NewRoleManager(10)
	rm.AddLink("u1", "g1", "domain1")
	rm.AddLink("u2", "g1", "domain2")
	rm.AddLink("u3", "g1", "*")
	rm.AddLink("u4", "g2", "domain3")
	// Current role inheritance tree after deleting the links:
	//       domain1:g1    domain2:g1			domain3:g2
	//		   /      \    /      \					|
	//	 domain1:u1    *:g1     domain2:u2		domain3:u4
	// 					|
	// 				   *:u3

	// The order of the elements in the slice may be chaotic due to the order of the map's allrange
	testGetUsers(t, rm, "u3", "domain1", []string{})
	testGetUsers(t, rm, "g1", "domain1", []string{"u1", "u3"})
	testGetUsers(t, rm, "g2", "domain3", []string{"u4"})
}

func TestDomainMatchModel(t *testing.T) {
	e, _ := casbin.NewEnforcer("examples/domainmatch_model.conf", "examples/domainmatch_policy.csv")
	rm := NewRoleManager(10)
	e.SetRoleManager(rm)
	e.LoadPolicy()
	testDomainEnforce(t, e, "alice", "domain1", "data1", "read", true)
	testDomainEnforce(t, e, "alice", "domain1", "data1", "write", true)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "read", false)
	testDomainEnforce(t, e, "alice", "domain1", "data2", "write", false)
	testDomainEnforce(t, e, "alice", "domain2", "data2", "read", true)
	testDomainEnforce(t, e, "alice", "domain2", "data2", "write", true)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "read", false)
	testDomainEnforce(t, e, "bob", "domain2", "data1", "write", false)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "read", true)
	testDomainEnforce(t, e, "bob", "domain2", "data2", "write", true)
}

func TestMatchingFunc(t *testing.T) {
	rm := NewRoleManager(10)
	rm.(*RoleManager).AddMatchingFunc(IPMatch)

	rm.AddLink("u1", "g1", "192.168.2.1")
	rm.AddLink("u2", "g1", "192.168.2.1")
	rm.AddLink("u2", "g2", "192.168.2.2")

	rm.AddLink("u3", "g1", "192.168.2.0/24")

	// Current role inheritance tree after deleting the links:
	// 	 	                  192.168.2.1::g1				        192.168.2.2::g2
	//                  /      \	           \				          /
	//    192.168.2.1::u1    192.168.2.1::u2  192.168.2.0/24::g1   192.168.2.2::u2
	//                                          /
	// 									192.168.2.0/24::u3
	testDomainRole(t, rm, "u1", "g1", "192.168.2.1", true)
	testDomainRole(t, rm, "u3", "g1", "192.168.2.1", true)
	testDomainRole(t, rm, "u2", "g2", "192.168.2.1", false)
	testDomainRole(t, rm, "u3", "g2", "192.168.2.1", false)
	testDomainRole(t, rm, "u3", "g1", "192.168.2.2", true)
	testDomainRole(t, rm, "u2", "g2", "192.168.2.2", true)
}
func IPMatch(ip1 string, ip2 string) bool {
	objIP1 := net.ParseIP(ip1)
	if objIP1 == nil {
		return false
	}

	_, cidr, err := net.ParseCIDR(ip2)
	if err != nil {
		objIP2 := net.ParseIP(ip2)
		if objIP2 == nil {
			return false
		}

		return objIP1.Equal(objIP2)
	}

	return cidr.Contains(objIP1)
}
