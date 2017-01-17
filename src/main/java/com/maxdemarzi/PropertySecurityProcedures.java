package com.maxdemarzi;

import apoc.result.MapResult;
import apoc.result.NodeResult;
import apoc.result.RelationshipResult;
import apoc.result.StringResult;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.neo4j.cursor.Cursor;
import org.neo4j.graphdb.*;
import org.neo4j.graphdb.traversal.Evaluators;
import org.neo4j.graphdb.traversal.TraversalDescription;
import org.neo4j.graphdb.traversal.Uniqueness;
import org.neo4j.kernel.api.KernelTransaction;
import org.neo4j.kernel.api.ReadOperations;
import org.neo4j.kernel.api.exceptions.EntityNotFoundException;
import org.neo4j.kernel.api.exceptions.index.IndexNotFoundKernelException;
import org.neo4j.kernel.api.exceptions.schema.IndexBrokenKernelException;
import org.neo4j.kernel.api.exceptions.schema.SchemaRuleNotFoundException;
import org.neo4j.kernel.api.index.IndexDescriptor;
import org.neo4j.kernel.impl.api.store.RelationshipIterator;
import org.neo4j.kernel.impl.core.ThreadToStatementContextBridge;
import org.neo4j.kernel.internal.GraphDatabaseAPI;
import org.neo4j.logging.Log;
import org.neo4j.procedure.*;
import org.neo4j.storageengine.api.NodeItem;
import org.neo4j.storageengine.api.RelationshipItem;
import org.roaringbitmap.buffer.MutableRoaringBitmap;

import java.io.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static com.maxdemarzi.RelationshipTypes.IN_SECURITY_GROUP;
import static java.lang.Math.toIntExact;

public class PropertySecurityProcedures {

    public static GraphDatabaseAPI dbapi;

    // This field declares that we need a GraphDatabaseService
    // as context when any procedure in this class is invoked
    @Context
    public GraphDatabaseService db;

    // This gives us a log instance that outputs messages to the
    // standard log, normally found under `data/log/console.log`
    @Context
    public Log log;

    // This gives us access to the security context
    @Context
    public KernelTransaction ktx;

    // This caches our property key ids
    private static final HashMap<String, Integer> keys = new HashMap<>();

    private static final LoadingCache<String, MutableRoaringBitmap> permissions = Caffeine.newBuilder()
            .maximumSize(10_000)
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .refreshAfterWrite(1, TimeUnit.MINUTES)
            .build(userId -> getPermissions(userId));

    private static MutableRoaringBitmap getPermissions(String username) throws SchemaRuleNotFoundException, IndexBrokenKernelException, IndexNotFoundKernelException, IOException, EntityNotFoundException {
        MutableRoaringBitmap permissions = new MutableRoaringBitmap();
        try (Transaction tx = dbapi.beginTx()) {
            ThreadToStatementContextBridge ctx = dbapi.getDependencyResolver().resolveDependency(ThreadToStatementContextBridge.class);
            ReadOperations ops = ctx.get().readOperations();
            Integer inSecurityGroupRelationshipTypeId = ops.relationshipTypeGetForName(RelationshipTypes.IN_SECURITY_GROUP.name());
            Integer securityUserLabelId = ops.labelGetForName(Labels.SecurityUser.name());
            Integer securityUsernamePropertyKeyId = ops.propertyKeyGetForName("username");
            IndexDescriptor descriptor = ops.indexGetForLabelAndPropertyKey(securityUserLabelId, securityUsernamePropertyKeyId);
            Cursor<NodeItem> users = ops.nodeCursorGetFromUniqueIndexSeek(descriptor, username);
            if (users.next()) {
                permissions = getRoaringBitmap(ops, users.get().id());
                RelationshipIterator relationshipIterator = ops.nodeGetRelationships(users.get().id(), Direction.OUTGOING, inSecurityGroupRelationshipTypeId );
                Cursor<RelationshipItem> c;
                while (relationshipIterator.hasNext()) {
                    c = ops.relationshipCursor(relationshipIterator.next());
                    if (c.next()) {
                        permissions.or(getRoaringBitmap(ops, c.get().endNode()));
                    }
                }
            }
            tx.success();
        }
        return permissions;
    }

    private static MutableRoaringBitmap getRoaringBitmap(ReadOperations ops, long userNodeId) throws IOException, EntityNotFoundException {
        MutableRoaringBitmap rb = new MutableRoaringBitmap();
        byte[] nodeIds;
        Integer permissionsPropertyKeyId = ops.propertyKeyGetForName("permissions");
        if (ops.nodeHasProperty(userNodeId, permissionsPropertyKeyId)) {
            nodeIds = (byte[]) ops.nodeGetProperty(userNodeId, permissionsPropertyKeyId);
            ByteArrayInputStream bais = new ByteArrayInputStream(nodeIds);
            rb.deserialize(new DataInputStream(bais));
        }
        return rb;

    }

    @Description("com.maxdemarzi.connected(label, key, value, relationshipType, depth) | Find connected nodes out to a certain depth")
    @Procedure(name = "com.maxdemarzi.connected")
    public Stream<MapResult> connected(@Name("label") String label,
                                       @Name("key") String key,
                                       @Name("value") Object value,
                                       @Name("relationshipType") String relationshipType,
                                       @Name("depth") Number depth) {
        ArrayList<MapResult> results = new ArrayList<>();
            this.dbapi = (GraphDatabaseAPI) db;

            if (keys.isEmpty()) {
                try (Transaction tx = db.beginTx()) {
                    ThreadToStatementContextBridge ctx = dbapi.getDependencyResolver().resolveDependency(ThreadToStatementContextBridge.class);
                    ReadOperations ops = ctx.get().readOperations();

                    for (String name : db.getAllPropertyKeys()) {
                        keys.put(name, ops.propertyKeyGetForName(name));
                    }
                    tx.success();
                }
            }

            String username;
            try (Transaction tx = db.beginTx()) {
                username = ktx.securityContext().subject().username();
                tx.success();
            }
            MutableRoaringBitmap userPermissions = permissions.get(username);

            try (Transaction tx = db.beginTx()) {
                final Node start = db.findNode(Label.label(label), key, value);
                TraversalDescription td = db.traversalDescription()
                        .depthFirst()
                        .expand(PathExpanders.forType(RelationshipType.withName(relationshipType)))
                        .uniqueness(Uniqueness.NODE_GLOBAL)
                        .evaluator(Evaluators.toDepth(depth.intValue()));

                Set<Long> connectedIds = new HashSet<>();
                for (org.neo4j.graphdb.Path position : td.traverse(start)) {
                    connectedIds.add(position.endNode().getId());
                }
                connectedIds.forEach((Long nodeId) -> {
                    Node node = db.getNodeById(nodeId);
                    Map<String, Object> properties = node.getAllProperties();
                    Map<String, Object> filteredProperties = new HashMap<>();
                    for (String property : properties.keySet()) {
                        Integer permission = toIntExact((nodeId << 8) | (keys.get(property) & 0x3FF));
                        if (userPermissions.contains(permission)) {
                            filteredProperties.put(key, properties.get(key));
                        }
                    }
                    if (!filteredProperties.isEmpty()) {
                        results.add(new MapResult(filteredProperties));
                    }
                });
                tx.success();
            }
        return results.stream();
    }

    @Description("com.maxdemarzi.generateSecuritySchema() | Creates schema for SecurityUser and SecurityGroup")
    @Procedure(name = "com.maxdemarzi.generateSecuritySchema", mode = Mode.SCHEMA)
    public Stream<StringResult> generateSecuritySchema() throws IOException {
        try (Transaction tx = db.beginTx()) {
            if ( ktx.securityContext().isAdmin() ) {
                org.neo4j.graphdb.schema.Schema schema = db.schema();
                if (!schema.getConstraints(Labels.SecurityUser).iterator().hasNext()) {
                    schema.constraintFor(Labels.SecurityUser)
                            .assertPropertyIsUnique("username")
                            .create();
                }
                if (!schema.getConstraints(Labels.SecurityGroup).iterator().hasNext()) {
                    schema.constraintFor(Labels.SecurityGroup)
                            .assertPropertyIsUnique("name")
                            .create();
                }

                db.execute("CALL dbms.security.createRole(\"secured\")");
            }
            tx.success();
        }
        return Stream.of(new StringResult("Security Schema Generated"));
    }

    @Description("com.maxdemarzi.createUserWithPropertyRights(username, password, mustChange) | Creates a User and SecurityUser Node")
    @Procedure(mode = Mode.WRITE)
    public Stream<NodeResult> createUserWithPropertyRights(@Name("username") String username,
                                                           @Name("password") String password,
                                                           @Name("mustChange") boolean mustChange) throws IOException {
        Node user = null;
         try( Transaction tx = db.beginTx()) {
             if ( ktx.securityContext().isAdmin() ) {
                 Map<String, Object> params = new HashMap<>();
                 params.put("username", username);
                 params.put("password", password);
                 params.put("mustChange", mustChange);
                 params.put("group", "secured");

                 String request = "CALL dbms.security.createUser({username},{password},{mustChange})";
                 db.execute(request, params);
                 request = "CALL dbms.security.addRoleToUser({group}, {username})";
                 db.execute(request, params);
                 user = db.createNode(Labels.SecurityUser);
                 user.setProperty("username", username);
                 createPermissionsProperty(user);
             }
             tx.success();
         }
         return Stream.of(new NodeResult(user));
    }

    @Description("com.maxdemarzi.createGroupWithPropertyRights(name) | Creates a SecurityGroup Node")
    @Procedure(mode = Mode.WRITE)
    public Stream<NodeResult> createGroupWithPropertyRights(@Name("name") String name) throws IOException {
       Node group = null;
        try( Transaction tx = db.beginTx()) {
            if ( ktx.securityContext().isAdmin() ) {
                group = db.createNode(Labels.SecurityGroup);
                group.setProperty("name", name);
                createPermissionsProperty(group);
            }
            tx.success();
        }
        return Stream.of(new NodeResult(group));
    }

    @Description("com.maxdemarzi.addUserMembership(username, group) | Creates a IN_SECURITY_GROUP relationship between user and group")
    @Procedure(mode = Mode.WRITE)
    public Stream<RelationshipResult> addUserMembership(@Name("username") String username, @Name("group") String name) throws IOException {
        Relationship rel = null;
        try( Transaction tx = db.beginTx()) {
            if ( ktx.securityContext().isAdmin() ) {
                Node user = db.findNode(Labels.SecurityUser, "username", username);
                Node group = db.findNode(Labels.SecurityGroup, "name", name);
                rel = user.createRelationshipTo(group, IN_SECURITY_GROUP);
            }
            tx.success();
        }
        return Stream.of(new RelationshipResult(rel));
    }

    @Description("com.maxdemarzi.removeUserMembership(username, group) | Removes the IN_SECURITY_GROUP relationship between user and group")
    @Procedure(mode = Mode.WRITE)
    public Stream<RelationshipResult> removeUserMembership(@Name("username") String username, @Name("group") String name) throws IOException {
        Relationship rel = null;
        try( Transaction tx = db.beginTx()) {
            if ( ktx.securityContext().isAdmin() ) {
                Node user = db.findNode(Labels.SecurityUser, "username", username);
                Node group = db.findNode(Labels.SecurityGroup, "name", name);
                for (Relationship relationship : user.getRelationships(IN_SECURITY_GROUP, Direction.OUTGOING)) {
                    if (relationship.getEndNode().equals(group)) {
                        rel = relationship;
                        relationship.delete();
                        break;
                    }
                }
            }
            tx.success();
        }
        return Stream.of(new RelationshipResult(rel));
    }

    @Description("com.maxdemarzi.addUserPermission(username, node, property) | Gives user access to node.property")
    @Procedure(mode = Mode.WRITE)
    public Stream<StringResult> addUserPermission(@Name("username") String username,
                                                  @Name("node") Node node,
                                                  @Name("property") String property) throws IOException {

        cachePropertyId(property);
        updatePermission(Labels.SecurityUser, "username",  username, node, property, true);
        return Stream.of(new StringResult("User " + username + " permission to node " + node.getId() + " " + property + " added"));
    }

    @Description("com.maxdemarzi.removeUserPermission(username, node, property) | Removes user access to node.property")
    @Procedure(mode = Mode.WRITE)
    public Stream<StringResult> removeUserPermission(@Name("username") String username,
                                               @Name("node") Node node,
                                               @Name("property") String property) throws IOException {

        cachePropertyId(property);
        updatePermission(Labels.SecurityUser, "username",  username, node, property, false);
        return Stream.of(new StringResult("User " + username + " permission to node " + node.getId() + " " + property + " removed"));
    }
    
    @Description("com.maxdemarzi.addGroupPermission(name, node, property) | Gives group access to node.property")
    @Procedure(mode = Mode.WRITE)
    public Stream<StringResult> addGroupPermission(@Name("name") String name,
                                            @Name("node") Node node,
                                            @Name("property") String property) throws IOException {

        cachePropertyId(property);
        updatePermission(Labels.SecurityGroup, "name", name, node, property, true);
        return Stream.of(new StringResult("Group " + name + " permission to node " + node.getId() + " " + property + " added"));
    }

    @Description("com.maxdemarzi.removeGroupPermission(name, node, property) | Removes group access to node.property")
    @Procedure(mode = Mode.WRITE)
    public Stream<StringResult> removeGroupPermission(@Name("name") String name,
                                               @Name("node") Node node,
                                               @Name("property") String property) throws IOException {

        cachePropertyId(property);
        updatePermission(Labels.SecurityGroup, "name", name, node, property, false);
        return Stream.of(new StringResult("Group " + name + " permission to node " + node.getId() + " " + property + " removed"));
    }

    private void updatePermission(Label label, String key, String value, @Name("node") Node node, @Name("property") String property, boolean set) throws IOException {
        try (Transaction transaction = db.beginTx()) {
            if (ktx.securityContext().isAdmin()) {
                Node securityNode = db.findNode(label, key, value);
                changePermission(securityNode, node, property, set);
                transaction.success();
            }
        }
    }

    private void changePermission(Node user, @Name("node") Node node, @Name("property") String property, boolean set ) throws IOException {
        Integer permission = toIntExact((node.getId() << 8) | (keys.get(property) & 0x3FF));
        byte[] bytes;
        MutableRoaringBitmap userPermissions = getPermissions(user);
        if (set) {
            userPermissions.add(permission);
        } else {
            userPermissions.remove(permission);
        }
        userPermissions.runOptimize();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        userPermissions.serialize(new DataOutputStream(baos));
        bytes = baos.toByteArray();
        user.setProperty("permissions", bytes);
    }

    private static MutableRoaringBitmap getPermissions(Node node) throws IOException {
        MutableRoaringBitmap rb = new MutableRoaringBitmap();
        if(node.hasProperty("permissions")) {
            byte[] nodeIds = (byte[]) node.getProperty("permissions", new MutableRoaringBitmap());
            ByteArrayInputStream bais = new ByteArrayInputStream(nodeIds);
            rb.deserialize(new DataInputStream(bais));
        }
        return rb;
    }

    private void cachePropertyId(@Name("property") String property) {
        if (!keys.containsKey(property)) {
            try( Transaction tx = db.beginTx()) {
                ThreadToStatementContextBridge ctx = ((GraphDatabaseAPI)db).getDependencyResolver().resolveDependency(ThreadToStatementContextBridge.class);
                ReadOperations ops = ctx.get().readOperations();
                for (String key :db.getAllPropertyKeys() ) {
                    keys.put(key, ops.propertyKeyGetForName(key));
                }
                tx.success();
            }
        }
    }

    private void createPermissionsProperty(Node node) throws IOException {
        byte[] bytes;
        MutableRoaringBitmap userPermissions = new MutableRoaringBitmap();
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        userPermissions.serialize(new DataOutputStream(baos));
        bytes = baos.toByteArray();
        node.setProperty("permissions", bytes);
    }
}
