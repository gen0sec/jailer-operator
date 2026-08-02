// Package jailer speaks the enrollment protocol of the bpfjailer daemon.
//
// The daemon accepts one newline-terminated JSON request per connection and
// replies before closing. Requests are a serde enum in its externally tagged
// form, and the pod and role ids are newtype structs there, so they appear on
// the wire as bare numbers rather than objects.
package jailer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
)

// DefaultSocketPath is where the daemon listens.
const DefaultSocketPath = "/run/bpfjailer/enrollment.sock"

// Client talks to a local bpfjailer daemon.
type Client struct{ SocketPath string }

func New(socketPath string) *Client {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	return &Client{SocketPath: socketPath}
}

type enrollCgroup struct {
	CgroupPath string `json:"cgroup_path"`
	PodID      uint64 `json:"pod_id"`
	RoleID     uint32 `json:"role_id"`
}

type removeCgroup struct {
	CgroupPath string `json:"cgroup_path"`
}

// EnrollCgroup binds a cgroup, and everything beneath it, to a role.
func (c *Client) EnrollCgroup(ctx context.Context, cgroupPath string, podID uint64, roleID uint32) error {
	return c.call(ctx, map[string]any{"EnrollCgroup": enrollCgroup{
		CgroupPath: cgroupPath, PodID: podID, RoleID: roleID}})
}

// RemoveCgroup drops an enrollment.
func (c *Client) RemoveCgroup(ctx context.Context, cgroupPath string) error {
	return c.call(ctx, map[string]any{"RemoveCgroup": removeCgroup{CgroupPath: cgroupPath}})
}

func (c *Client) call(ctx context.Context, request any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encoding request: %w", err)
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", c.SocketPath)
	if err != nil {
		// Named, because a daemon that is not running is the normal state on
		// a node without jailer and must be distinguishable from a refusal.
		return fmt.Errorf("connecting to the jailer daemon at %s: %w", c.SocketPath, err)
	}
	defer conn.Close()

	// A daemon that accepts and never answers must not hang the agent.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("setting deadline: %w", err)
		}
	}

	if _, err := conn.Write(append(body, '\n')); err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	// The daemon replies then closes, so the response is everything up to EOF.
	raw, err := io.ReadAll(conn)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	return decodeResponse(raw)
}

// decodeResponse maps the daemon's reply onto an error or nil. Anything not
// recognised is an error: counting it as success would report a pod enrolled
// when nothing reached a map.
func decodeResponse(raw []byte) error {
	var unit string
	if err := json.Unmarshal(raw, &unit); err == nil {
		if unit == "Success" {
			return nil
		}
		return fmt.Errorf("jailer daemon replied %q", unit)
	}

	var tagged map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tagged); err != nil {
		return fmt.Errorf("unreadable response from the jailer daemon: %q", string(raw))
	}
	if reason, ok := tagged["Error"]; ok {
		var message string
		if err := json.Unmarshal(reason, &message); err != nil {
			message = string(reason)
		}
		return fmt.Errorf("jailer daemon refused: %s", message)
	}
	for variant := range tagged {
		return fmt.Errorf("unexpected response %q from the jailer daemon", variant)
	}
	return fmt.Errorf("empty response from the jailer daemon")
}

// Role mirrors the daemon's policy Role. Field names and the set of them have
// to match: the daemon deserialises strictly, and a role it rejects means an
// enrollment that is refused as unknown.
type Role struct {
	ID                  uint32        `json:"id"`
	Name                string        `json:"name"`
	Flags               Flags         `json:"flags"`
	FilePaths           []PathPattern `json:"file_paths"`
	NetworkRules        []any         `json:"network_rules"`
	ExecutionRules      []any         `json:"execution_rules"`
	RequireSignedBinary bool          `json:"require_signed_binary"`
	IPRules             []IPRule      `json:"ip_rules"`
	DomainRules         []DomainRule  `json:"domain_rules"`
	Proxy               *Proxy        `json:"proxy"`
}

// Flags are all required by the daemon except the two it defaults, so every
// one is sent explicitly rather than relying on omitempty.
type Flags struct {
	AllowFileAccess     bool `json:"allow_file_access"`
	AllowNetwork        bool `json:"allow_network"`
	AllowExec           bool `json:"allow_exec"`
	RequireSignedBinary bool `json:"require_signed_binary"`
	AllowSetuid         bool `json:"allow_setuid"`
	AllowPtrace         bool `json:"allow_ptrace"`
	AllowModuleLoad     bool `json:"allow_module_load"`
	AllowBpfLoad        bool `json:"allow_bpf_load"`
}

type PathPattern struct {
	Pattern string `json:"pattern"`
	Allow   bool   `json:"allow"`
}

type IPRule struct {
	CIDR      string `json:"cidr"`
	Direction string `json:"direction"`
	Allow     bool   `json:"allow"`
}

type DomainRule struct {
	Domain string `json:"domain"`
	Allow  bool   `json:"allow"`
}

type Proxy struct {
	Address  string `json:"address"`
	Required bool   `json:"required"`
}

// DefineRole installs a role so an enrollment can name it. Roles otherwise
// only exist if they were in the policy file the daemon started with.
func (c *Client) DefineRole(ctx context.Context, role Role) error {
	// Nil slices marshal as null, which the daemon's Vec fields reject.
	if role.FilePaths == nil {
		role.FilePaths = []PathPattern{}
	}
	if role.NetworkRules == nil {
		role.NetworkRules = []any{}
	}
	if role.ExecutionRules == nil {
		role.ExecutionRules = []any{}
	}
	if role.IPRules == nil {
		role.IPRules = []IPRule{}
	}
	if role.DomainRules == nil {
		role.DomainRules = []DomainRule{}
	}
	return c.call(ctx, map[string]any{"DefineRole": map[string]any{"role": role}})
}
