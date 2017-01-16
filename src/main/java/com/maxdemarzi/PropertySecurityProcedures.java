package com.maxdemarzi;

import apoc.result.NodeResult;
import apoc.result.RelationshipResult;
import apoc.result.StringResult;
import org.neo4j.graphdb.*;
import org.neo4j.kernel.api.KernelTransaction;
import org.neo4j.kernel.api.ReadOperations;
import org.neo4j.kernel.impl.core.ThreadToStatementContextBridge;
import org.neo4j.kernel.internal.GraphDatabaseAPI;
import org.neo4j.logging.Log;
import org.neo4j.procedure.*;
import org.roaringbitmap.buffer.MutableRoaringBitmap;

import java.io.*;
import java.util.HashMap;
import java.util.stream.Stream;

import static com.maxdemarzi.RelationshipTypes.IN_SECURITY_GROUP;
import static java.lang.Math.toIntExact;

public class PropertySecurityProcedures {

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
    public KernelTransaction tx;

    // This caches our property key ids
    private static final HashMap<String, Integer> keys = new HashMap();


    @Description("com.maxdemarzi.createUserWithPropertyRights(username, password, mustChange) | Creates a User and SecurityUser Node")
    @Procedure(mode = Mode.WRITE)
    public Stream<NodeResult> createUserWithPropertyRights(@Name("username") String username,
                                                           @Name("password") String password,
                                                           @Name("mustChange") boolean mustChange) throws IOException {
        Node user = null;
         try( Transaction transaction = db.beginTx()) {
             if ( tx.securityContext().isAdmin() ) {
                 String request = "CALL com.maxdemarzi.createUser(\"" + username + "\", \"" + password + "\" , " + mustChange + ")";
                 db.execute(request);
                 user = db.createNode(Labels.SecurityUser);
                 user.setProperty("username", username);
                 createPermissionsProperty(user);
                 transaction.success();

             }
         }
         return Stream.of(new NodeResult(user));
    }

    @Description("com.maxdemarzi.createGroupWithPropertyRights(name) | Creates a SecurityGroup Node")
    @Procedure(mode = Mode.WRITE)
    public Stream<NodeResult> createGroupWithPropertyRights(@Name("name") String name) throws IOException {
       Node group = null;
        try( Transaction transaction = db.beginTx()) {
            if ( tx.securityContext().isAdmin() ) {
                group = db.createNode(Labels.SecurityGroup);
                group.setProperty("name", name);
                createPermissionsProperty(group);
                transaction.success();
            }
        }
        return Stream.of(new NodeResult(group));
    }

    @Description("com.maxdemarzi.addUserMembership(username, group) | Creates a IN_SECURITY_GROUP relationship between user and group")
    @Procedure(mode = Mode.WRITE)
    public Stream<RelationshipResult> addUserMembership(@Name("username") String username, @Name("group") String name) throws IOException {
        Relationship rel = null;
        try( Transaction transaction = db.beginTx()) {
            if ( tx.securityContext().isAdmin() ) {
                Node user = db.findNode(Labels.SecurityUser, "username", username);
                Node group = db.findNode(Labels.SecurityGroup, "name", name);
                rel = user.createRelationshipTo(group, IN_SECURITY_GROUP);
                transaction.success();
            }
        }
        return Stream.of(new RelationshipResult(rel));
    }

    @Description("com.maxdemarzi.removeUserMembership(username, group) | Removes the IN_SECURITY_GROUP relationship between user and group")
    @Procedure(mode = Mode.WRITE)
    public Stream<RelationshipResult> removeUserMembership(@Name("username") String username, @Name("group") String name) throws IOException {
        Relationship rel = null;
        try( Transaction transaction = db.beginTx()) {
            if ( tx.securityContext().isAdmin() ) {
                Node user = db.findNode(Labels.SecurityUser, "username", username);
                Node group = db.findNode(Labels.SecurityGroup, "name", name);
                for (Relationship relationship : user.getRelationships(IN_SECURITY_GROUP, Direction.OUTGOING)) {
                    if (relationship.getEndNode().equals(group)) {
                        rel = relationship;
                        relationship.delete();
                        break;
                    }
                }
                transaction.success();
            }
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
            if (tx.securityContext().isAdmin()) {
                Node securityNode = db.findNode(label, key, value);
                changePermission(securityNode, node, property, set);
                transaction.success();
            }
        }
    }

    private void changePermission(Node user, @Name("node") Node node, @Name("property") String property, boolean set ) throws IOException {
        Integer permission = toIntExact((node.getId() << 8) | (keys.get(property) & 0xF));
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
            try( Transaction transaction = db.beginTx()) {
                ThreadToStatementContextBridge ctx = ((GraphDatabaseAPI)db).getDependencyResolver().resolveDependency(ThreadToStatementContextBridge.class);
                ReadOperations ops = ctx.get().readOperations();
                for (String key :db.getAllPropertyKeys() ) {
                    keys.put(key, ops.propertyKeyGetForName(key));
                }
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
