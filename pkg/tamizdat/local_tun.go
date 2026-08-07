package tamizdat

type LocalTUNConfig struct {
	UserID        string
	UserName      string
	Enabled       bool
	FallbackTag   string
	Interface     string
	TunName       string
	TunAddress    string
	MTU           int
	AutoRoute     bool
	BypassPrivate bool
	BlockQUIC     bool
	Sniff         bool
	FailClosed    bool
}

// LocalTUNConfigs returns panel-managed local users. These users are loaded
// from the same registry as remote users but are never placed in the ShortID
// authentication map.
func (s *Server) LocalTUNConfigs() []LocalTUNConfig {
	if s == nil || s.userRegistry == nil {
		return nil
	}
	users := s.userRegistry.Snapshot()
	out := make([]LocalTUNConfig, 0, 1)
	for _, user := range users {
		if user.Kind != "local_tun" {
			continue
		}
		out = append(out, LocalTUNConfig{
			UserID: user.ID, UserName: user.Name,
			Enabled: user.LocalEnabled, FallbackTag: user.OutboundTag,
			Interface: user.LocalInterface, TunName: user.LocalTunName,
			TunAddress: user.LocalTunAddress, MTU: user.LocalTunMTU,
			AutoRoute: user.LocalAutoRoute, BypassPrivate: user.LocalBypassPrivate,
			BlockQUIC: user.LocalBlockQUIC, Sniff: user.LocalSniff,
			FailClosed: user.LocalFailClosed,
		})
	}
	return out
}
