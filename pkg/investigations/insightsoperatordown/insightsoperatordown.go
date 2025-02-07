// insightsoperatordown remediates InsightOperatorDownSRE alerts
// SOP https://github.com/openshift/ops-sop/blob/master/v4/troubleshoot/clusteroperators/insights.md

// step: check banned user

// step: cycle pod when hitting https://issues.redhat.com/browse/OCPBUGS-22226
// to trigger this bug we can block console.redhat.com via rule group in aws account

package insightsoperatordown

import (
	"context"
	"fmt"
	"strings"

	configv1 "github.com/openshift/api/config/v1"
	investigation "github.com/openshift/configuration-anomaly-detection/pkg/investigations"
	k8sclient "github.com/openshift/configuration-anomaly-detection/pkg/k8s"
	"github.com/openshift/configuration-anomaly-detection/pkg/logging"
	"github.com/openshift/configuration-anomaly-detection/pkg/notewriter"
	"k8s.io/apimachinery/pkg/fields"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func Investigate(r *investigation.Resources) (investigation.InvestigationResult, error) {
	result := investigation.InvestigationResult{}

	// Initialize k8s client with the investigations name
	k8scli, err := k8sclient.New(r.Cluster.ID(), r.OcmClient, r.Name)
	if err != nil {
		return result, fmt.Errorf("unable to initialize k8s cli: %w", err)
	}

	// Initialize PagerDuty note writer
	notes := notewriter.New(r.Name, logging.RawLogger)

	// List the insights cluster operator
	coList := &configv1.ClusterOperatorList{}
	listOptions := &client.ListOptions{FieldSelector: fields.SelectorFromSet(fields.Set{"metadata.name": "insights"})}
	err = k8scli.List(context.TODO(), coList, listOptions)
	if err != nil {
		return result, fmt.Errorf("unable to list insights clusteroperator: %w", err)
	}

	// Make sure our list output only finds a single cluster operator for `metadata.name = insights`
	if len(coList.Items) != 1 {
		return result, fmt.Errorf("found %d clusteroperators, expected 1", len(coList.Items))
	}
	co := coList.Items[0]

	// Check for https://issues.redhat.com/browse/OCPBUGS-22226
	if isOCPBUG22226(&co) {
		notes.AppendAutomation("Found symptom of OCPBUG22226. Try deleting the pod to remediate.")
		return result, r.PdClient.EscalateIncidentWithNote(notes.String())
	}

	notes.AppendSuccess("User is not banned and its not OCPBUG22226. Please investigate.")
	return result, r.PdClient.EscalateIncidentWithNote(notes.String())
}

// Check if the `Available` status condition reports a broken UWM config
func isOCPBUG22226(co *configv1.ClusterOperator) bool {
	symptomStatusString := `Failed to pull SCA certs`

	for _, condition := range co.Status.Conditions {
		// if condition.Type == "SCAAvailable" {
		if strings.Contains(condition.Message, symptomStatusString) {
			return true
		}
	}
	return false
}
