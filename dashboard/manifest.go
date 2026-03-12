package dashboard

import (
	"github.com/xraph/forge/extensions/dashboard/contributor"
)

// NewManifest builds a contributor.Manifest for the chronicle dashboard.
func NewManifest() *contributor.Manifest {
	return &contributor.Manifest{
		Name:        "chronicle",
		DisplayName: "Chronicle",
		Icon:        "scroll-text",
		Version:     "1.0.0",
		Layout:      "extension",
		ShowSidebar: boolPtr(true),
		TopbarConfig: &contributor.TopbarConfig{
			Title:       "Chronicle",
			LogoIcon:    "scroll-text",
			AccentColor: "#8b5cf6",
			ShowSearch:  true,
			Actions: []contributor.TopbarAction{
				{Label: "API Docs", Icon: "file-text", Href: "/docs", Variant: "ghost"},
			},
		},
		Nav:      baseNav(),
		Widgets:  baseWidgets(),
		Settings: baseSettings(),
		Capabilities: []string{
			"searchable",
		},
	}
}

// baseNav returns the core navigation items for the chronicle dashboard.
func baseNav() []contributor.NavItem {
	return []contributor.NavItem{
		// Overview
		{Label: "Overview", Path: "/", Icon: "layout-dashboard", Group: "Overview", Priority: 0},

		// Audit Trail
		{Label: "Events", Path: "/events", Icon: "activity", Group: "Audit Trail", Priority: 0},
		{Label: "Verification", Path: "/verify", Icon: "shield-check", Group: "Audit Trail", Priority: 1},

		// Compliance
		{Label: "Reports", Path: "/reports", Icon: "file-check", Group: "Compliance", Priority: 0},
		{Label: "Erasures", Path: "/erasures", Icon: "eraser", Group: "Compliance", Priority: 1},

		// Data Lifecycle
		{Label: "Retention", Path: "/retention", Icon: "clock", Group: "Data Lifecycle", Priority: 0},
		{Label: "Archives", Path: "/retention/archives", Icon: "archive", Group: "Data Lifecycle", Priority: 1},

		// Configuration
		{Label: "Settings", Path: "/settings", Icon: "settings", Group: "Configuration", Priority: 0},
	}
}

// baseWidgets returns the core widget descriptors for the chronicle dashboard.
func baseWidgets() []contributor.WidgetDescriptor {
	return []contributor.WidgetDescriptor{
		{
			ID:          "chronicle-stats",
			Title:       "Audit Stats",
			Description: "Audit trail overview metrics",
			Size:        "md",
			RefreshSec:  30,
			Group:       "Chronicle",
		},
		{
			ID:          "chronicle-recent-events",
			Title:       "Recent Events",
			Description: "Latest audit trail events",
			Size:        "lg",
			RefreshSec:  15,
			Group:       "Chronicle",
		},
	}
}

// baseSettings returns the core settings descriptors for the chronicle dashboard.
func baseSettings() []contributor.SettingsDescriptor {
	return []contributor.SettingsDescriptor{
		{
			ID:          "chronicle-config",
			Title:       "Chronicle Configuration",
			Description: "Audit trail engine settings",
			Group:       "Chronicle",
			Icon:        "scroll-text",
		},
	}
}

func boolPtr(b bool) *bool { return &b }
