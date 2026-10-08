package models

import "testing"

func validSettings() PluginSettings {
	return PluginSettings{
		AuthType:        AuthProviderKeys,
		Region:          "us-east-1",
		RoleSessionName: "grafana-cost-explorer",
		CacheTTLSeconds: DefaultCacheTTLSeconds,
		CacheMaxEntries: DefaultCacheMaxEntries,
		Secrets: &SecretPluginSettings{
			AccessKeyID:     "test-access-key",
			SecretAccessKey: "test-secret",
		},
	}
}

func TestPluginSettingsAssumeRoleValidation(t *testing.T) {
	settings := validSettings()

	settings.AssumeRoleARN = "not-an-arn"
	if err := settings.Validate(); err == nil {
		t.Fatal("expected malformed role ARN to fail validation")
	}

	settings.AssumeRoleARN = "arn:aws:iam::123456789012:role/GrafanaCostExplorer"
	if err := settings.Validate(); err != nil {
		t.Fatalf("valid AssumeRole settings failed validation: %v", err)
	}

	settings.RoleSessionName = "!"
	if err := settings.Validate(); err == nil {
		t.Fatal("expected malformed role session name to fail validation")
	}
}

func TestPluginSettingsAssumeRoleRequiresExplicitSourceCredentials(t *testing.T) {
	settings := validSettings()
	settings.AssumeRoleARN = "arn:aws:iam::123456789012:role/GrafanaCostExplorer"
	settings.Secrets = &SecretPluginSettings{}

	if err := settings.Validate(); err == nil {
		t.Fatal("expected missing AssumeRole source credentials to fail validation")
	}
}

func TestPluginSettingsAccessKeyValidation(t *testing.T) {
	settings := validSettings()
	settings.Secrets = &SecretPluginSettings{}
	if err := settings.Validate(); err == nil {
		t.Fatal("expected missing access key credentials to fail validation")
	}

	settings.Secrets.AccessKeyID = "test-access-key"
	settings.Secrets.SecretAccessKey = "test-secret"
	if err := settings.Validate(); err != nil {
		t.Fatalf("valid access key settings failed validation: %v", err)
	}
}

func TestPluginSettingsRejectsUnknownAuthType(t *testing.T) {
	for _, authType := range []string{"static", "assumeRole", "default", "ec2_iam_role", "nonsense"} {
		settings := validSettings()
		settings.AuthType = authType
		if err := settings.Validate(); err == nil {
			t.Errorf("expected authentication provider %q to be unsupported", authType)
		}
	}
}

func TestPluginSettingsAssumesRole(t *testing.T) {
	settings := validSettings()
	if settings.AssumesRole() {
		t.Error("no role ARN means no role hop")
	}
	settings.AssumeRoleARN = "   "
	if settings.AssumesRole() {
		t.Error("a blank role ARN means no role hop")
	}
}

func TestPluginSettingsAdoptLegacyAuthModes(t *testing.T) {
	legacyStatic := PluginSettings{LegacyAuthMode: "static"}
	legacyStatic.ApplyDefaults()
	if legacyStatic.AuthType != AuthProviderKeys || legacyStatic.AssumesRole() {
		t.Errorf("legacy static became %q assuming %q", legacyStatic.AuthType, legacyStatic.AssumeRoleARN)
	}

	legacyAssume := PluginSettings{
		LegacyAuthMode: "assumeRole",
		LegacyRoleARN:  "arn:aws:iam::123456789012:role/GrafanaCostExplorer",
	}
	legacyAssume.ApplyDefaults()
	if legacyAssume.AuthType != AuthProviderKeys {
		t.Errorf("legacy assumeRole should authenticate with keys, got %q", legacyAssume.AuthType)
	}
	if legacyAssume.AssumeRoleARN != "arn:aws:iam::123456789012:role/GrafanaCostExplorer" {
		t.Errorf("legacy assumeRole lost its role ARN: %q", legacyAssume.AssumeRoleARN)
	}
}

// An unrecognised authMode must not be reinterpreted as the provider that
// happens to share its name.
func TestPluginSettingsDoNotAdoptAnUnrecognisedAuthMode(t *testing.T) {
	legacy := PluginSettings{LegacyAuthMode: "default"}
	legacy.ApplyDefaults()

	if legacy.AuthType != AuthProviderKeys {
		t.Fatalf("an unrecognised mode should fall through to %q, got %q", AuthProviderKeys, legacy.AuthType)
	}
	legacy.Secrets = &SecretPluginSettings{}
	if err := legacy.Validate(); err == nil {
		t.Fatal("an unrecognised mode must not silently start working")
	}
}

func TestPluginSettingsPreferTheCurrentAuthType(t *testing.T) {
	settings := PluginSettings{
		AuthType:       AuthProviderKeys,
		LegacyAuthMode: "assumeRole",
		LegacyRoleARN:  "arn:aws:iam::123456789012:role/GrafanaCostExplorer",
	}
	settings.ApplyDefaults()

	if settings.AssumesRole() {
		t.Error("a data source with a current authType adopted a superseded role ARN")
	}
}
