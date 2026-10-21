package core

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func associationUser() AssociatedUser {
	return AssociatedUser{Principal: Principal{Issuer: "https://issuer.example", Subject: "employee-a"}, Name: "Employee A"}
}
func TestDeviceAssociationHandoff(t *testing.T) {
	e, _ := grantFixture(t)
	ticket := newGrant(t, e)
	before := grantLookup(t, e, ticket.UserCode)
	if before.AssociatedUser != nil {
		t.Fatal("ordinary enrollment acquired a user")
	}
	user := associationUser()
	confirmed, err := e.ConfirmDeviceGrantAssociation(testActorContext(), before.GrantID, user)
	if err != nil || !reflect.DeepEqual(confirmed.AssociatedUser, &user) {
		t.Fatalf("confirm: %+v %v", confirmed, err)
	}
	if DeviceGrantETag(before) == DeviceGrantETag(confirmed) {
		t.Fatal("confirmation did not invalidate reviewed null association")
	}
	if _, err := e.DecideDeviceGrant(testActorContext(), before.GrantID, "approve", []string{DeviceGrantETag(before)}); !errors.Is(err, ErrDeviceGrantPrecondition) {
		t.Fatalf("stale approval: %v", err)
	}
	admin := Actor{Issuer: user.Issuer, Subject: "admin-b", Kind: "human"}
	if _, err := e.DecideDeviceGrant(WithActor(context.Background(), admin), before.GrantID, "approve", []string{DeviceGrantETag(confirmed)}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.ConfirmDeviceGrantAssociation(testActorContext(), before.GrantID, user); !errors.Is(err, ErrDeviceGrantDecided) {
		t.Fatalf("late confirm: %v", err)
	}
	poll := grantPoll(t, e, ticket.DeviceCode)
	node, ok := e.AuthenticateClient(poll.Connection.Token)
	if !ok || !reflect.DeepEqual(node.AssociatedUser, &user) {
		t.Fatalf("node lost employee association: %+v", node)
	}
	if err := e.RevokeClient(testActorContext(), node.ID); err != nil {
		t.Fatal(err)
	}
	nodes, err := e.ClientNodes()
	if err != nil || !reflect.DeepEqual(nodes[0].AssociatedUser, &user) {
		t.Fatal("revocation lost historical user", err)
	}
	audits, err := e.Audits()
	if err != nil {
		t.Fatal(err)
	}
	seen := false
	for _, audit := range audits {
		if audit.Action == "client.device.enroll" && audit.Subject == node.ID {
			seen = true
			if audit.Actor != admin {
				t.Fatal("employee replaced approving actor")
			}
		}
	}
	if !seen {
		t.Fatal("issuance audit missing")
	}
}
func TestDeviceAssociationExpiryReplayAndConcurrentClaim(t *testing.T) {
	e, advance := grantFixture(t)
	ticket := newGrant(t, e)
	g := grantLookup(t, e, ticket.UserCode)
	const claimants = 8 // Existing device-grant concurrent-redemption fixture.
	var wg sync.WaitGroup
	errs := make([]error, claimants)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = e.ConfirmDeviceGrantAssociation(testActorContext(), g.GrantID, associationUser())
		}(i)
	}
	wg.Wait()
	winners := 0
	for _, err := range errs {
		if err == nil {
			winners++
		} else if !errors.Is(err, ErrDeviceGrantDecided) {
			t.Fatal(err)
		}
	}
	if winners != 1 {
		t.Fatalf("claim winners: %d", winners)
	}
	if _, err := e.ConfirmDeviceGrantAssociation(testActorContext(), g.GrantID, associationUser()); !errors.Is(err, ErrDeviceGrantDecided) {
		t.Fatalf("replay: %v", err)
	}
	pending := grantLookup(t, e, newGrant(t, e).UserCode)
	advance(deviceGrantLifetime)
	if _, err := e.DeviceGrantAssociation(pending.GrantID); !errors.Is(err, ErrDeviceGrantNotFound) {
		t.Fatalf("expired preview: %v", err)
	}
	if _, err := e.ConfirmDeviceGrantAssociation(testActorContext(), pending.GrantID, associationUser()); !errors.Is(err, ErrDeviceGrantNotFound) {
		t.Fatalf("expired confirm: %v", err)
	}
}
func TestDeviceAssociationDecisionWinsAndLegacyNull(t *testing.T) {
	e, _ := grantFixture(t)
	ticket := newGrant(t, e)
	g := approveGrant(t, e, testActorContext(), ticket.UserCode)
	if _, err := e.ConfirmDeviceGrantAssociation(testActorContext(), g.GrantID, associationUser()); !errors.Is(err, ErrDeviceGrantDecided) {
		t.Fatal("association changed decided grant", err)
	}
	poll := grantPoll(t, e, ticket.DeviceCode)
	node, _ := e.AuthenticateClient(poll.Connection.Token)
	if node.AssociatedUser != nil {
		t.Fatal("admin decision automatically associated a user")
	}
	key, err := e.CreateEnrollment(testActorContext(), "legacy")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.EnrollClient(key.Code, "linux")
	if err != nil {
		t.Fatal(err)
	}
	node, _ = e.AuthenticateClient(conn.Token)
	if node.AssociatedUser != nil {
		t.Fatal("setup-key enrollment acquired a user")
	}
}
func TestDeviceAssociationRollback(t *testing.T) {
	for _, phase := range []string{"confirm", "redeem"} {
		t.Run(phase, func(t *testing.T) {
			e, _ := grantFixture(t)
			ticket := newGrant(t, e)
			g := grantLookup(t, e, ticket.UserCode)
			if phase == "redeem" {
				var err error
				g, err = e.ConfirmDeviceGrantAssociation(testActorContext(), g.GrantID, associationUser())
				if err != nil {
					t.Fatal(err)
				}
				if _, err = e.DecideDeviceGrant(testActorContext(), g.GrantID, "approve", []string{DeviceGrantETag(g)}); err != nil {
					t.Fatal(err)
				}
			}
			before, err := e.Audits()
			if err != nil {
				t.Fatal(err)
			}
			rejectAudit(t, e)
			if phase == "confirm" {
				if _, err := e.ConfirmDeviceGrantAssociation(testActorContext(), g.GrantID, associationUser()); err == nil {
					t.Fatal("failed audit committed association")
				}
			} else {
				if _, err := e.PollDeviceGrant(ticket.DeviceCode); err == nil {
					t.Fatal("failed audit issued credential")
				}
			}
			current := grantLookup(t, e, ticket.UserCode)
			if phase == "confirm" && current.AssociatedUser != nil {
				t.Fatal("association escaped rollback")
			}
			if phase == "redeem" && (current.Status != "approved" || current.AssociatedUser == nil) {
				t.Fatal("rollback lost approved association")
			}
			nodes, err := e.ClientNodes()
			if err != nil || len(nodes) != 0 {
				t.Fatal("node escaped rollback", err)
			}
			after, err := e.Audits()
			if err != nil || len(after) != len(before) {
				t.Fatal("audit escaped rollback", err)
			}
		})
	}
}
func TestDeviceAssociationPollDoesNotInvalidateReview(t *testing.T) {
	e, advance := grantFixture(t)
	ticket := newGrant(t, e)
	before := grantLookup(t, e, ticket.UserCode)
	grantPoll(t, e, ticket.DeviceCode)
	advance(time.Second)
	grantPoll(t, e, ticket.DeviceCode)
	after := grantLookup(t, e, ticket.UserCode)
	if DeviceGrantETag(before) != DeviceGrantETag(after) {
		t.Fatal("private polling cadence invalidated admin review")
	}
}
