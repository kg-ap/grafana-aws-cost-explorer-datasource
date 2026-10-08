package awsclient

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/costexplorer"
	"github.com/ivlabs-dev/grafana-aws-cost-explorer-datasource/pkg/models"
)

// isolateAmbientCredentials points the SDK at process credentials only, so a
// developer's ~/.aws files cannot decide the outcome of these tests.
func isolateAmbientCredentials(t *testing.T, accessKeyID, secretAccessKey string) {
	t.Helper()
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_ACCESS_KEY_ID", accessKeyID)
	t.Setenv("AWS_SECRET_ACCESS_KEY", secretAccessKey)
}

func TestAccessKeyAuthenticationIgnoresAmbientCredentials(t *testing.T) {
	isolateAmbientCredentials(t, "ambient-access-key", "ambient-secret")

	bundle, err := NewFactory().New(context.Background(), models.PluginSettings{
		AuthType: models.AuthProviderKeys,
		Region:   "us-east-1",
		Secrets: &models.SecretPluginSettings{
			AccessKeyID:     "configured-access-key",
			SecretAccessKey: "configured-secret",
		},
	})
	if err != nil {
		t.Fatalf("build access key client: %v", err)
	}
	if got := retrieveAccessKeyID(t, bundle); got != "configured-access-key" {
		t.Fatalf("access key authentication resolved %q; explicit Grafana credentials must win", got)
	}
}

func costExplorerClient(t *testing.T, bundle *Bundle) *costexplorer.Client {
	t.Helper()
	client, ok := bundle.CostExplorer.(*costexplorer.Client)
	if !ok {
		t.Fatalf("Cost Explorer client is a %T, not an SDK client", bundle.CostExplorer)
	}
	return client
}

func retrieveAccessKeyID(t *testing.T, bundle *Bundle) string {
	t.Helper()
	credentials, err := costExplorerClient(t, bundle).Options().Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatalf("retrieve credentials: %v", err)
	}
	return credentials.AccessKeyID
}
