//go:build !commercial

package app

func inventoryNativeMetadata(*Session) []inventoryMetadata { return nil }
func inventoryNativeRows() string                          { return inventoryEmptyRows }
func inventoryCandidateSearchRows() string                 { return inventoryCandidateRows }
