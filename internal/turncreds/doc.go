// Package turncreds manages periodic acquisition and caching of TURN
// relay credentials from VK video-call infrastructure via the vkcreds
// package. The Manager runs a background refresh loop and exposes
// thread-safe access to the latest credentials for injection into
// the server-pushed CoverConfigBundle.
package turncreds
