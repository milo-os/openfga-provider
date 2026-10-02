package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func TestSubresourceAuthorizationFlagDefaultsOff(t *testing.T) {
	for _, command := range []*cobra.Command{createManagerCommand(), createWebhookCommand()} {
		flag := command.Flags().Lookup("enable-subresource-authorization")
		require.NotNil(t, flag)
		require.Equal(t, "false", flag.DefValue)
		require.NoError(t, command.Flags().Parse([]string{"--enable-subresource-authorization=true"}))
		enabled, err := command.Flags().GetBool("enable-subresource-authorization")
		require.NoError(t, err)
		require.True(t, enabled)
	}
}
