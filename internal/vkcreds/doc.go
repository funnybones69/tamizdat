// Package vkcreds acquires TURN server credentials from VK (VKontakte)
// video-call infrastructure.
//
// VK exposes anonymous video-call joining via a public API. When a caller
// joins a call link, VK allocates TURN relay credentials (username +
// password + server URLs) so the WebRTC session can traverse NATs. This
// package drives the same 5-step HTTP flow programmatically to obtain
// those credentials for use with any TURN-compatible transport.
//
// # The 5-step flow
//
//  1. get_anonym_token (profile scope) -- obtain an anonymous OAuth token
//     with audio/video/photos/profile scopes.
//  2. get_anonym_token (messages scope) -- exchange the profile token for
//     a messages-scoped token required to join a call.
//  3. calls.getAnonymousToken -- present the messages token + call hash
//     to VK's calls API. If VK responds with a captcha challenge (error
//     code 14), the package solves it automatically via the reverse-JS
//     captcha solver or delegates to a user-supplied CaptchaSolver.
//  4. OK FB auth.anonymLogin -- authenticate anonymously with the OK
//     (Odnoklassniki) calls backend to get a session key.
//  5. vchat.joinConversationByLink -- join the call via OK's backend and
//     receive TURN server URLs, username, credential, and lifetime.
//
// # Usage
//
//	cfg := &vkcreds.Config{
//	    AppID:     "6287487",
//	    AppSecret: "QbYic1K3lEV5kTGiqlq2",
//	    UserAgent: "Mozilla/5.0 (Linux; Android 13; ...) ...",
//	    DeviceID:  "some-unique-device-id",
//	}
//	creds, err := vkcreds.GetCredentials(ctx, cfg, "abcdef123456")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(creds.User, creds.Pass, creds.TurnURLs)
package vkcreds
