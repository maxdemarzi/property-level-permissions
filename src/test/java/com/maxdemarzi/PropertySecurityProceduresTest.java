package com.maxdemarzi;

import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Transaction;
import org.neo4j.graphdb.factory.GraphDatabaseSettings;
import org.neo4j.kernel.impl.proc.Procedures;
import org.neo4j.kernel.internal.GraphDatabaseAPI;
import org.neo4j.test.TestEnterpriseGraphDatabaseFactory;

public class PropertySecurityProceduresTest {

    private GraphDatabaseService db;

    @Before
    public void setUp() throws Exception {
        db = new TestEnterpriseGraphDatabaseFactory().
                newImpermanentDatabaseBuilder().
                setConfig(GraphDatabaseSettings.auth_enabled, "false").
                newGraphDatabase();

        Procedures proceduresService = ((GraphDatabaseAPI) db).getDependencyResolver().resolveDependency(Procedures.class);
        proceduresService.registerProcedure(PropertySecurityProcedures.class);
    }

    @After
    public void tearDown() {
        db.shutdown();
    }

    @Test
    @Ignore
    public void shouldCreateUserWithPropertyRights() {
        try (Transaction tx = db.beginTx()) {
            String cypher = "CALL com.maxdemarzi.generateSecuritySchema()";
            db.execute(cypher);
            cypher = "CALL com.maxdemarzi.createUserWithPropertyRights('max', 'swordfish', false)";
            db.execute(cypher);
            tx.success();
        }
    }

}