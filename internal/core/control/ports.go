package control

import (
	"context"
	"time"
)

// ControlStore defines the driven port interface for vendor-agnostic Control Plane persistence.
type ControlStore interface {
	// Apps
	ListApps(ctx context.Context) ([]SiteApp, error)
	GetApp(ctx context.Context, id string) (SiteApp, error)
	CreateApp(ctx context.Context, app SiteApp) error
	UpdateApp(ctx context.Context, app SiteApp) error
	DeleteApp(ctx context.Context, id string) error

	// Exceptions
	ListExceptions(ctx context.Context) ([]ExceptionRule, error)
	ListActiveExceptions(ctx context.Context) ([]ExceptionRule, error)
	GetException(ctx context.Context, id string) (ExceptionRule, error)
	CreateException(ctx context.Context, exc ExceptionRule) error
	UpdateException(ctx context.Context, exc ExceptionRule) error
	DeleteException(ctx context.Context, id string) error

	// ACL Rules
	ListACLRules(ctx context.Context) ([]AclRule, error)
	ListActiveACLRules(ctx context.Context) ([]AclRule, error)
	GetACLRule(ctx context.Context, id string) (AclRule, error)
	CreateACLRule(ctx context.Context, rule AclRule) error
	UpdateACLRule(ctx context.Context, rule AclRule) error
	DeleteACLRule(ctx context.Context, id string) error

	// Rate Policies
	ListRatePolicies(ctx context.Context) ([]RatePolicy, error)
	ListActiveRatePolicies(ctx context.Context) ([]RatePolicy, error)
	GetRatePolicy(ctx context.Context, id string) (RatePolicy, error)
	CreateRatePolicy(ctx context.Context, policy RatePolicy) error
	UpdateRatePolicy(ctx context.Context, policy RatePolicy) error
	DeleteRatePolicy(ctx context.Context, id string) error

	// Bot Configs
	ListBotConfigs(ctx context.Context) ([]BotConfig, error)
	ListActiveBotConfigs(ctx context.Context) ([]BotConfig, error)
	GetBotConfig(ctx context.Context, id string) (BotConfig, error)
	CreateBotConfig(ctx context.Context, cfg BotConfig) error
	UpdateBotConfig(ctx context.Context, cfg BotConfig) error
	DeleteBotConfig(ctx context.Context, id string) error

	// Snapshots
	CreateSnapshot(ctx context.Context, snap ConfigSnapshotRecord) (ConfigSnapshotRecord, error)
	GetSnapshotByVersion(ctx context.Context, version int64) (ConfigSnapshotRecord, error)
	GetLatestSnapshot(ctx context.Context) (ConfigSnapshotRecord, error)
	ListSnapshots(ctx context.Context) ([]ConfigSnapshotRecord, error)

	// Users
	ListUsers(ctx context.Context) ([]UserRecord, error)
	GetUserByID(ctx context.Context, id string) (UserRecord, error)
	GetUserByUsername(ctx context.Context, username string) (UserRecord, error)
	CreateUser(ctx context.Context, user UserRecord) error
	UpdateUser(ctx context.Context, user UserRecord) error
	DeleteUser(ctx context.Context, id string) error

	// API Keys
	ListAPIKeys(ctx context.Context) ([]ApiKeyRecord, error)
	GetAPIKeyByID(ctx context.Context, id string) (ApiKeyRecord, error)
	GetAPIKeyByHash(ctx context.Context, keyHash string) (ApiKeyRecord, error)
	CreateAPIKey(ctx context.Context, key ApiKeyRecord) error
	UpdateAPIKeyLastUsed(ctx context.Context, id string, lastUsedAt time.Time) error
	DeleteAPIKey(ctx context.Context, id string) error

	// Forwarding Rules
	ListForwardingRules(ctx context.Context) ([]ForwardingRuleRecord, error)
	ListForwardingRulesByApp(ctx context.Context, appID string) ([]ForwardingRuleRecord, error)
	ListActiveForwardingRulesByApp(ctx context.Context, appID string) ([]ForwardingRuleRecord, error)
	ListAllActiveForwardingRules(ctx context.Context) ([]ForwardingRuleRecord, error)
	GetForwardingRule(ctx context.Context, id string) (ForwardingRuleRecord, error)
	CreateForwardingRule(ctx context.Context, rule ForwardingRuleRecord) error
	UpdateForwardingRule(ctx context.Context, rule ForwardingRuleRecord) error
	DeleteForwardingRule(ctx context.Context, id string) error
	DeleteForwardingRulesByApp(ctx context.Context, appID string) error

	// API Resources
	ListAPIResourcesByApp(ctx context.Context, appID string) ([]ApiResourceRecord, error)
	GetAPIResource(ctx context.Context, id string) (ApiResourceRecord, error)
	UpsertAPIResource(ctx context.Context, res ApiResourceRecord) error
	DeleteAPIResource(ctx context.Context, id string) error
	DeleteAPIResourcesByApp(ctx context.Context, appID string) error

	// IP Groups
	ListIPGroups(ctx context.Context) ([]IPGroupRecord, error)
	GetIPGroup(ctx context.Context, id string) (IPGroupRecord, error)
	GetIPGroupByName(ctx context.Context, name string) (IPGroupRecord, error)
	CreateIPGroup(ctx context.Context, group IPGroupRecord) error
	UpdateIPGroup(ctx context.Context, group IPGroupRecord) error
	DeleteIPGroup(ctx context.Context, id string) error
	ListIPGroupEntries(ctx context.Context, groupID string) ([]IPGroupEntryRecord, error)
	CreateIPGroupEntry(ctx context.Context, entry IPGroupEntryRecord) error
	DeleteIPGroupEntry(ctx context.Context, id string) error

	// Response Templates
	ListTemplates(ctx context.Context) ([]TemplateRecord, error)
	GetTemplate(ctx context.Context, statusCode int) (TemplateRecord, error)
	UpsertTemplate(ctx context.Context, tmpl TemplateRecord) error
	DeleteTemplate(ctx context.Context, statusCode int) error

	// Semantic Detector Matrix
	ListDetectorConfig(ctx context.Context) ([]DetectorConfigRecord, error)
	UpsertDetectorConfig(ctx context.Context, cfg DetectorConfigRecord) error
	DeleteDetectorConfig(ctx context.Context, module string) error
	ListAppSemanticPolicies(ctx context.Context) ([]AppSemanticPolicyRecord, error)
	UpsertAppSemanticPolicy(ctx context.Context, rec AppSemanticPolicyRecord) error
	DeleteAppSemanticPolicy(ctx context.Context, appID string) error

	// Transactions & Lifecycle
	WithTx(ctx context.Context, fn func(store ControlStore) error) error
	Close() error
}

// ControlStorePort defines the driven port for configuration persistence.
type ControlStorePort interface {
	CompileSnapshot(ctx context.Context) (*ConfigSnapshot, error)
	RollbackSnapshot(ctx context.Context, version int64) (*ConfigSnapshot, error)
}

// ClusterPublisherPort defines the driven port for publishing config updates across nodes.
type ClusterPublisherPort interface {
	PublishVersion(ctx context.Context, version uint64) error
	PublishSnapshot(ctx context.Context, snap *ConfigSnapshot, author string) error
}

// SnapshotManagerPort defines the port for managing active snapshots.
type SnapshotManagerPort interface {
	StoreSnapshot(newSnap *ConfigSnapshot)
	LoadSnapshot() *ConfigSnapshot
}
