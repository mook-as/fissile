package model

// This part of the model encapsulates fissile's knowledge of pod
// security policies (psp). fissile actually does not know about any
// concrete psp at all. What it knows/has are abstract names for
// levels of privilege the writer of a manifest can assign to
// jobs. The operator deploying the chart resulting from such a
// manifest is then responsible for mapping the abstract names/levels
// to concrete policies implementing them.

import (
	apipolicy "k8s.io/api/policy/v1beta1"
)

// Pod security policy constants
const (
	PodSecurityPolicyNonPrivileged = "nonprivileged"
	PodSecurityPolicyPrivileged    = "privileged"
)

// PodSecurityPolicy defines a pod security policy
type PodSecurityPolicy struct {
	apipolicy.PodSecurityPolicySpec
	roleManifest *RoleManifest
}

// PodSecurityPolicies returns the names of the pod security policies
// usable in fissile manifests
func PodSecurityPolicies() []string {
	return []string{
		PodSecurityPolicyNonPrivileged,
		PodSecurityPolicyPrivileged,
	}
}

// KnownPodSecurityPolicy checks if the given pod security policy name is the
// name of a known pod security policy
func (policy *PodSecurityPolicy) KnownPodSecurityPolicy(name string) bool {
	if policy.roleManifest != nil {
		for policyName := range policy.roleManifest.Configuration.Authorization.PodSecurityPolicies {
			if policyName == name {
				return true
			}
		}
	}
	for _, builtInName := range PodSecurityPolicies() {
		if builtInName == name {
			return true
		}
	}
	return false
}

// PrivilegeEscalationAllowed checks if this policy is set to allow privilege escalation
func (policy PodSecurityPolicy) PrivilegeEscalationAllowed() bool {
	return policy.AllowPrivilegeEscalation != nil && *policy.AllowPrivilegeEscalation
}

// CloneAsPrivileged returns a new pod security policy that allows privilege escalation
func (policy PodSecurityPolicy) CloneAsPrivileged() *PodSecurityPolicy {
	if policy.PrivilegeEscalationAllowed() {
		return &policy
	}
	dummy := true
	policy.AllowPrivilegeEscalation = &dummy
	return &policy
}

func DefaultPodSecurityPolicyName() string {
	return PodSecurityPolicyNonPrivileged
}
