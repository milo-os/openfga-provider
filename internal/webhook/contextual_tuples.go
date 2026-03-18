package webhook

// contextual_tuples.go previously contained helpers that injected system group
// memberships and RootBinding links as per-request contextual tuples on every
// OpenFGA Check call. Under the direct-permission model all relationships are
// stored tuples written at PolicyBinding / SystemGroupMaterializer
// reconciliation time, so contextual tuples are no longer needed.
//
// The file is retained to document this decision and to serve as an extension
// point if conditional / ephemeral tuple injection is ever needed in the future.
