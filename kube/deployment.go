package kube

import (
	"fmt"

	"github.com/SUSE/fissile/helm"
	"github.com/SUSE/fissile/model"
	"github.com/SUSE/fissile/util"
)

// NewDeployment creates a Deployment for the given role, and its attached services
func NewDeployment(role *model.Role, settings *ExportSettings) (helm.Node, helm.Node, error) {
	podTemplate, err := NewPodTemplate(role, settings)
	if err != nil {
		return nil, nil, err
	}

	svc, err := NewClusterIPServiceList(role, false, settings)
	if err != nil {
		return nil, nil, err
	}
	spec := helm.NewMapping()
	spec.Add("selector", newSelector(role.Name))
	spec.Add("template", podTemplate)

	deployment := newKubeConfig("extensions/v1beta1", "Deployment", role.Name, helm.Comment(role.GetLongDescription()))
	err = replicaCheck(role, deployment, spec, svc, settings)
	deployment.Add("spec", spec.Sort())

	return deployment.Sort(), svc, err
}

func replicaCheck(role *model.Role, controller *helm.Mapping, spec *helm.Mapping, service helm.Node, settings *ExportSettings) error {
	if role.Run.Affinity != nil {
		var cond string
		if settings.CreateHelmChart {
			podSpec := spec.Get("template", "spec").(*helm.Mapping)

			// affinity spec is only supported in kube 1.6 and later
			cond = "if or (gt (int .Capabilities.KubeVersion.Major) 1) (gt (int .Capabilities.KubeVersion.Minor) 5)"
			podSpec.Add("affinity", role.Run.Affinity, helm.Block(cond))
			podSpec.Sort()

			// in kube 1.5 affinity is declared via annotation
			cond = "if and (eq (int .Capabilities.KubeVersion.Major) 1) (le (int .Capabilities.KubeVersion.Minor) 5)"
		}

		meta := spec.Get("template", "metadata").(*helm.Mapping)
		if meta.Get("annotations") == nil {
			meta.Add("annotations", helm.NewMapping())
			meta.Sort()
		}
		annotations := meta.Get("annotations").(*helm.Mapping)

		affinity, err := util.JSONMarshal(role.Run.Affinity)
		if err != nil {
			return err
		}
		annotations.Add("scheduler.alpha.kubernetes.io/affinity", string(affinity), helm.Block(cond))
	}

	if !settings.CreateHelmChart {
		spec.Add("replicas", role.Run.Scaling.Min)
		return nil
	}

	roleName := makeVarName(role.Name)
	spec.Add("replicas", fmt.Sprintf("{{ .Values.sizing.%s.count }}", roleName))
	if role.Run.Scaling.Min == 0 {
		block := helm.Block(fmt.Sprintf("if gt (int .Values.sizing.%s.count) 0", roleName))
		controller.Set(block)
		if service != nil {
			service.Set(block)
		}
	} else {
		fail := fmt.Sprintf(`{{ fail "%s must have at least %d instances" }}`, roleName, role.Run.Scaling.Min)
		block := fmt.Sprintf("if lt (int .Values.sizing.%s.count) %d", roleName, role.Run.Scaling.Min)
		controller.Add("_minReplicas", fail, helm.Block(block))
	}

	fail := fmt.Sprintf(`{{ fail "%s cannot have more than %d instances" }}`, roleName, role.Run.Scaling.Max)
	block := fmt.Sprintf("if gt (int .Values.sizing.%s.count) %d", roleName, role.Run.Scaling.Max)
	controller.Add("_maxReplicas", fail, helm.Block(block))

	return nil
}
