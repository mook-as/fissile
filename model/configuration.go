package model

import (
	"gopkg.in/yaml.v2"

	"code.cloudfoundry.org/fissile/util"
)

// Configuration contains information about how to configure the
// resulting images
type Configuration struct {
	Authorization struct {
		RoleUse             map[string]int
		Roles               map[string]AuthRole           `yaml:"roles,omitempty"`
		ClusterRoles        map[string]AuthRole           `yaml:"cluster-roles,omitempty"`
		PodSecurityPolicies map[string]*PodSecurityPolicy `yaml:"pod-security-policies,omitempty"`
		Accounts            map[string]AuthAccount        `yaml:"accounts,omitempty"`
	} `yaml:"auth,omitempty"`
	Templates yaml.MapSlice `yaml:"templates"`
}

// Notes: It was decided to use a separate `RoleUse` map to hold the
// usage count for the roles to keep the API to the role manifest
// yaml.  Going to a structure for AuthRole, with a new field for the
// counter would change the structure of the yaml as well.

// An AuthRule is a single rule for a RBAC authorization role
type AuthRule struct {
	APIGroups     []string `yaml:"apiGroups"`
	Resources     []string `yaml:"resources"`
	ResourceNames []string `yaml:"resourceNames"`
	Verbs         []string `yaml:"verbs"`
}

// IsPodSecurityPolicyRule checks if the rule is a pod security policy rule
func (rule *AuthRule) IsPodSecurityPolicyRule() bool {
	if !util.StringInSlice("extensions", rule.APIGroups) {
		return false
	}
	if !util.StringInSlice("use", rule.Verbs) {
		return false
	}
	if !util.StringInSlice("podsecuritypolicies", rule.Resources) {
		return false
	}
	return true
}

// An AuthRole is a role for RBAC authorization
type AuthRole []AuthRule

// An AuthAccount is a service account for RBAC authorization
// The NumGroups field records the number of instance groups
// referencing the account in question.
type AuthAccount struct {
	NumGroups           int
	Roles               []string                      `yaml:"roles"`
	ClusterRoles        []string                      `yaml:"cluster-roles"`
	PodSecurityPolicies map[string]*PodSecurityPolicy `yaml:"-"` // The PSPs calculated to have been attached to this account
}
