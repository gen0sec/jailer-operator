package jailer

import (
	"bufio"
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serve stands in for the daemon: it records one request and replies.
func serve(t *testing.T, reply string) (socket string, got chan string) {
	t.Helper()
	socket = filepath.Join(t.TempDir(), "enrollment.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	got = make(chan string, 1)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		got <- line
		_, _ = conn.Write([]byte(reply))
	}()
	return socket, got
}

// receive fails the test rather than hanging until the go test timeout.
func receive(t *testing.T, got chan string) string {
	t.Helper()
	select {
	case line := <-got:
		return line
	case <-time.After(3 * time.Second):
		t.Fatal("the daemon received nothing")
		return ""
	}
}

func TestEnrollSendsTheDaemonsExactWireFormat(t *testing.T) {
	socket, got := serve(t, `"Success"`)
	if err := New(socket).EnrollCgroup(context.Background(),
		"/sys/fs/cgroup/kubepods.slice", 7, 3); err != nil {
		t.Fatal(err)
	}
	// Externally tagged, snake_case fields, newline terminated. The ids are
	// newtype structs on the daemon side and serialise as bare numbers, so
	// sending objects would be rejected.
	want := `{"EnrollCgroup":{"cgroup_path":"/sys/fs/cgroup/kubepods.slice","pod_id":7,"role_id":3}}` + "\n"
	if line := receive(t, got); line != want {
		t.Errorf("\n got: %s want: %s", line, want)
	}
}

func TestRemoveSendsTheRemoveVariant(t *testing.T) {
	socket, got := serve(t, `"Success"`)
	if err := New(socket).RemoveCgroup(context.Background(), "/sys/fs/cgroup/x"); err != nil {
		t.Fatal(err)
	}
	line := receive(t, got)
	want := `{"RemoveCgroup":{"cgroup_path":"/sys/fs/cgroup/x"}}` + "\n"
	if line != want {
		t.Errorf("\n got: %s want: %s", line, want)
	}
}

// A refusal from the daemon must reach the caller. Treating it as success
// would report a pod enrolled when nothing was written to any map.
func TestADaemonErrorIsReturned(t *testing.T) {
	socket, _ := serve(t, `{"Error":"role 3 not found"}`)
	err := New(socket).EnrollCgroup(context.Background(), "/x", 7, 3)
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "role 3 not found") {
		t.Errorf("the daemon's reason should survive, got %q", err)
	}
}

func TestAnUnrecognisedReplyIsAnError(t *testing.T) {
	socket, _ := serve(t, `{"Something":"else"}`)
	if err := New(socket).EnrollCgroup(context.Background(), "/x", 7, 3); err == nil {
		t.Error("an unrecognised reply must not count as success")
	}
}

// The daemon not running is the normal state on a node where jailer is not
// installed, and it must be distinguishable from a rejected enrollment.
func TestAMissingSocketIsAnErrorNamingIt(t *testing.T) {
	err := New(filepath.Join(t.TempDir(), "absent.sock")).
		EnrollCgroup(context.Background(), "/x", 7, 3)
	if err == nil {
		t.Fatal("want an error")
	}
	if !strings.Contains(err.Error(), "absent.sock") {
		t.Errorf("the error should name the socket, got %q", err)
	}
}

func TestAContextDeadlineIsHonoured(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "silent.sock")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// Accept but never reply, so the client must give up on its own.
	go func() {
		c, err := l.Accept()
		if err == nil {
			time.Sleep(30 * time.Second)
			c.Close()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if err := New(socket).EnrollCgroup(ctx, "/x", 7, 3); err == nil {
		t.Error("a daemon that never replies must not hang the agent")
	}
}

// The daemon deserialises strictly: a missing field or a null where it wants a
// list is a rejected role, and then every enrollment naming it is refused as
// unknown.
func TestDefineRoleSendsEveryFieldTheDaemonRequires(t *testing.T) {
	socket, got := serve(t, `"Success"`)
	err := New(socket).DefineRole(context.Background(), Role{
		ID: 68, Name: "jailer-68",
		Flags:   Flags{AllowNetwork: true},
		IPRules: []IPRule{{CIDR: "10.0.0.0/8", Direction: "connect"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	line := receive(t, got)
	for _, required := range []string{
		`"DefineRole"`, `"role"`, `"id":68`, `"name":"jailer-68"`,
		`"allow_file_access"`, `"allow_network":true`, `"allow_ptrace"`,
		`"file_paths":[]`, `"network_rules":[]`, `"execution_rules":[]`,
		`"require_signed_binary"`, `"domain_rules":[]`,
		`"cidr":"10.0.0.0/8"`,
	} {
		if !strings.Contains(line, required) {
			t.Errorf("missing %s in:\n  %s", required, line)
		}
	}
	// null lists are rejected by the daemon's Vec fields
	if strings.Contains(line, "null") && !strings.Contains(line, `"proxy":null`) {
		t.Errorf("unexpected null in %s", line)
	}
}
