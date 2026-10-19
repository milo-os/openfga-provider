package controller

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	openfgav1 "github.com/openfga/api/proto/openfga/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"go.miloapis.com/auth-provider-openfga/internal/openfga"

	iamdatumapiscomv1alpha1 "go.miloapis.com/milo/pkg/apis/iam/v1alpha1"
	resourcemanagerv1alpha1 "go.miloapis.com/milo/pkg/apis/resourcemanager/v1alpha1"
)

const (
	resourceManagerGroup = "resourcemanager.miloapis.com"
	projectType          = resourceManagerGroup + "/Project"
	organizationType     = resourceManagerGroup + "/Organization"
	workloadType         = "compute.miloapis.com/Workload"
	grantRelation        = "granted-permission"
	testStoreID          = "store"
	// fgaReadPageSize is OpenFGA's default page size for Read.
	fgaReadPageSize = 50
)

// fgaTupleStore keeps tuples in memory under OpenFGA's rules for Read and
// Write: each field of a read key filters only when it is set, an object with
// no id matches its whole type and needs a user, reads come in pages, and one
// write holds at most openfga.MaxTuplesPerWrite tuples, none twice. Deleting a
// tuple that is not stored fails the whole write unless the delete asks to
// ignore it, and writing one that is stored fails it too.
type fgaTupleStore struct {
	openfgav1.OpenFGAServiceClient
	mu     sync.Mutex
	tuples []*openfgav1.TupleKey
	// added counts the writes that added tuples.
	added int
	// beforeWrite runs before a write that adds tuples is applied, and
	// afterWrite after each successful write; both stand in for other actors.
	beforeWrite func(*fgaTupleStore)
	afterWrite  func(*fgaTupleStore)
}

func (s *fgaTupleStore) Read(_ context.Context, in *openfgav1.ReadRequest, _ ...grpc.CallOption) (*openfgav1.ReadResponse, error) {
	key := in.GetTupleKey()
	if strings.HasSuffix(key.GetObject(), ":") && key.GetUser() == "" {
		return nil, status.Error(codes.InvalidArgument, "the object id and the user cannot both be empty")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var matched []*openfgav1.TupleKey
	for _, t := range s.tuples {
		if readKeyMatches(key, t) {
			matched = append(matched, t)
		}
	}
	start, _ := strconv.Atoi(in.GetContinuationToken())
	end := min(start+fgaReadPageSize, len(matched))
	resp := &openfgav1.ReadResponse{}
	for _, t := range matched[start:end] {
		resp.Tuples = append(resp.Tuples, &openfgav1.Tuple{Key: t})
	}
	if end < len(matched) {
		resp.ContinuationToken = strconv.Itoa(end)
	}
	return resp, nil
}

func readKeyMatches(key *openfgav1.ReadRequestTupleKey, t *openfgav1.TupleKey) bool {
	return objectMatches(key.GetObject(), t.GetObject()) &&
		(key.GetRelation() == "" || t.GetRelation() == key.GetRelation()) &&
		(key.GetUser() == "" || t.GetUser() == key.GetUser())
}

func objectMatches(want, got string) bool {
	if strings.HasSuffix(want, ":") {
		return strings.HasPrefix(got, want)
	}
	return got == want
}

func (s *fgaTupleStore) Write(_ context.Context, in *openfgav1.WriteRequest, _ ...grpc.CallOption) (*openfgav1.WriteResponse, error) {
	writes := in.GetWrites().GetTupleKeys()
	if len(writes) > 0 && s.beforeWrite != nil {
		s.beforeWrite(s)
	}
	if err := s.apply(in.GetDeletes(), writes); err != nil {
		return nil, err
	}
	if s.afterWrite != nil {
		s.afterWrite(s)
	}
	return &openfgav1.WriteResponse{}, nil
}

func (s *fgaTupleStore) apply(deletes *openfgav1.WriteRequestDeletes, writes []*openfgav1.TupleKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.validateWrite(deletes, writes); err != nil {
		return err
	}
	for _, d := range deletes.GetTupleKeys() {
		s.remove(d)
	}
	s.tuples = append(s.tuples, writes...)
	if len(writes) > 0 {
		s.added++
	}
	return nil
}

func (s *fgaTupleStore) validateWrite(deletes *openfgav1.WriteRequestDeletes, writes []*openfgav1.TupleKey) error {
	keys := deletes.GetTupleKeys()
	if len(keys)+len(writes) > openfga.MaxTuplesPerWrite {
		return status.Errorf(codes.InvalidArgument, "%d tuples exceed the limit of %d per write", len(keys)+len(writes), openfga.MaxTuplesPerWrite)
	}
	seen := map[string]bool{}
	for _, d := range append(keysOf(writes), keys...) {
		key := d.GetUser() + "|" + d.GetRelation() + "|" + d.GetObject()
		if seen[key] {
			return status.Errorf(codes.InvalidArgument, "duplicate tuple in write: %v", d)
		}
		seen[key] = true
	}
	for _, d := range keys {
		if deletes.GetOnMissing() != "ignore" && !s.stored(d) {
			return status.Errorf(codes.InvalidArgument, "cannot delete a tuple which does not exist: %v", d)
		}
	}
	for _, w := range keysOf(writes) {
		if s.stored(w) {
			return status.Errorf(codes.InvalidArgument, "cannot write a tuple which already exists: %v", w)
		}
	}
	return nil
}

func keysOf(tuples []*openfgav1.TupleKey) []*openfgav1.TupleKeyWithoutCondition {
	keys := make([]*openfgav1.TupleKeyWithoutCondition, 0, len(tuples))
	for _, t := range tuples {
		keys = append(keys, &openfgav1.TupleKeyWithoutCondition{User: t.GetUser(), Relation: t.GetRelation(), Object: t.GetObject()})
	}
	return keys
}

func sameTuple(t *openfgav1.TupleKey, d *openfgav1.TupleKeyWithoutCondition) bool {
	return t.GetUser() == d.GetUser() && t.GetRelation() == d.GetRelation() && t.GetObject() == d.GetObject()
}

func (s *fgaTupleStore) stored(d *openfgav1.TupleKeyWithoutCondition) bool {
	for _, t := range s.tuples {
		if sameTuple(t, d) {
			return true
		}
	}
	return false
}

func (s *fgaTupleStore) remove(d *openfgav1.TupleKeyWithoutCondition) {
	kept := s.tuples[:0]
	for _, t := range s.tuples {
		if !sameTuple(t, d) {
			kept = append(kept, t)
		}
	}
	s.tuples = kept
}

// put stores a tuple, as another writer would.
func (s *fgaTupleStore) put(t *openfgav1.TupleKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tuples = append(s.tuples, t)
}

// naming returns the tuples that name the object, as the object or as the user.
func (s *fgaTupleStore) naming(object string) []*openfgav1.TupleKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	var found []*openfgav1.TupleKey
	for _, t := range s.tuples {
		if t.GetObject() == object || t.GetUser() == object {
			found = append(found, t)
		}
	}
	return found
}

// childOf registers kind under serviceRef with one parent type, as a
// ProtectedResource does in the authorization model.
func childOf(serviceRef, kind, parentGroup, parentKind string) *iamdatumapiscomv1alpha1.ProtectedResource {
	pr := protectedResource(serviceRef, kind)
	pr.Spec.ParentResources = []iamdatumapiscomv1alpha1.ParentResourceRef{{APIGroup: parentGroup, Kind: parentKind}}
	return pr
}

// hierarchyResources are the ProtectedResources the cleanup reads parents from:
// an Organization is a Project's parent and a Project is a Workload's.
func hierarchyResources() []client.Object {
	return []client.Object{
		protectedResource(resourceManagerGroup, "Organization"),
		childOf(resourceManagerGroup, "Project", resourceManagerGroup, "Organization"),
		childOf("compute.miloapis.com", "Workload", resourceManagerGroup, "Project"),
	}
}

func newFinalizerLogic(t *testing.T, store *fgaTupleStore) *ResourceOwnerHierarchyFinalizerLogic {
	t.Helper()
	c := fake.NewClientBuilder().WithScheme(protectedResourceScheme(t)).WithObjects(hierarchyResources()...).Build()
	return &ResourceOwnerHierarchyFinalizerLogic{Client: c, FGAClient: store, FGAStoreID: testStoreID}
}

func grant(user, object string) *openfgav1.TupleKey {
	return &openfgav1.TupleKey{User: "iam.miloapis.com/InternalUser:" + user, Relation: grantRelation, Object: object}
}

func parentTuple(parent, child string) *openfgav1.TupleKey {
	return &openfgav1.TupleKey{User: parent, Relation: RelationName, Object: child}
}

func TestProjectFinalizerRemovesEveryTupleNamingTheProject(t *testing.T) {
	const deleted = projectType + ":p1"
	const other = projectType + ":p2"
	store := &fgaTupleStore{tuples: []*openfgav1.TupleKey{
		parentTuple(organizationType+":org-a", deleted),
		grant("alice", deleted),
		parentTuple(deleted, workloadType+":w1"),
		grant("bob", other),
		parentTuple(other, workloadType+":w2"),
	}}
	project := &resourcemanagerv1alpha1.Project{ObjectMeta: metav1.ObjectMeta{Name: "p1"}}

	_, err := newFinalizerLogic(t, store).Finalize(context.Background(), project)

	require.NoError(t, err)
	require.Empty(t, store.naming(deleted), "a tuple naming the deleted Project survived its finalizer")
	require.Len(t, store.naming(other), 2, "the finalizer touched another Project's tuples")
}

func TestOrganizationFinalizerRemovesEveryTupleNamingTheOrganization(t *testing.T) {
	const deleted = organizationType + ":org-a"
	const other = organizationType + ":org-b"
	store := &fgaTupleStore{tuples: []*openfgav1.TupleKey{
		grant("alice", deleted),
		parentTuple(deleted, projectType+":p1"),
		parentTuple(deleted, projectType+":p2"),
		grant("bob", other),
		parentTuple(other, projectType+":p3"),
	}}
	org := &resourcemanagerv1alpha1.Organization{ObjectMeta: metav1.ObjectMeta{Name: "org-a"}}

	_, err := newFinalizerLogic(t, store).Finalize(context.Background(), org)

	require.NoError(t, err)
	require.Empty(t, store.naming(deleted), "a tuple naming the deleted Organization, as object or as user, survived")
	require.Len(t, store.naming(other), 2, "the finalizer touched another Organization's tuples")
}

// A Project can carry more grants than one read page or one write holds.
func TestFinalizerRemovesTuplesAcrossPagesAndWrites(t *testing.T) {
	const deleted = projectType + ":p1"
	store := &fgaTupleStore{}
	for i := range 3*openfga.MaxTuplesPerWrite + 7 {
		store.tuples = append(store.tuples, grant(fmt.Sprintf("user-%d", i), deleted))
	}
	project := &resourcemanagerv1alpha1.Project{ObjectMeta: metav1.ObjectMeta{Name: "p1"}}

	_, err := newFinalizerLogic(t, store).Finalize(context.Background(), project)

	require.NoError(t, err)
	require.Empty(t, store.naming(deleted))
}

// Two ProtectedResources may register the same type, as two files of one
// service do; the type's tuples must still be read, and deleted, once.
func TestFinalizerReadsATypeRegisteredTwiceOnce(t *testing.T) {
	const deleted = projectType + ":p1"
	store := &fgaTupleStore{tuples: []*openfgav1.TupleKey{parentTuple(deleted, workloadType+":w1")}}
	logic := newFinalizerLogic(t, store)
	twice := childOf("compute.miloapis.com", "Workload", resourceManagerGroup, "Project")
	twice.Name = "workloads-second-registration"
	require.NoError(t, logic.Create(context.Background(), twice))
	project := &resourcemanagerv1alpha1.Project{ObjectMeta: metav1.ObjectMeta{Name: "p1"}}

	_, err := logic.Finalize(context.Background(), project)

	require.NoError(t, err)
	require.Empty(t, store.naming(deleted))
}

// The finalizer may finish only when a fresh read finds no tuple naming the
// object, so a tuple written meanwhile keeps the object in storage.
func TestFinalizerHoldsWhileATupleNamingTheObjectRemains(t *testing.T) {
	const deleted = projectType + ":p1"
	store := &fgaTupleStore{tuples: []*openfgav1.TupleKey{grant("alice", deleted)}}
	store.afterWrite = func(s *fgaTupleStore) {
		s.afterWrite = nil
		s.put(grant("carol", deleted))
	}
	logic := newFinalizerLogic(t, store)
	project := &resourcemanagerv1alpha1.Project{ObjectMeta: metav1.ObjectMeta{Name: "p1"}}

	_, err := logic.Finalize(context.Background(), project)
	require.Error(t, err, "the finalizer finished while a tuple named the Project")

	_, err = logic.Finalize(context.Background(), project)
	require.NoError(t, err)
	require.Empty(t, store.naming(deleted))
}

// A tuple another writer deleted first does not fail the delete of the rest,
// as a binding's own finalizer may remove a grant while the target's runs.
func TestDeleteSkipsATupleAlreadyGone(t *testing.T) {
	const object = projectType + ":p1"
	store := &fgaTupleStore{tuples: []*openfgav1.TupleKey{grant("alice", object)}}

	err := openfga.DeleteTuples(context.Background(), store, testStoreID, "", []*openfgav1.TupleKey{grant("alice", object), grant("gone", object)})

	require.NoError(t, err)
	require.Empty(t, store.naming(object))
}
