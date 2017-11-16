# neo_prop_perms
POC Property Level Permissions for Neo4j


Setup
---

1. Build it:
        
        mvn clean package
        
2. Copy jar to  to the plugins/ directory of your Neo4j server.
        
        cp target/property-level-permissions-1.0-SNAPSHOT.jar neo4j-enterprise-3.3.0/plugins/.
        
3. Configure Neo4j by adding these lines to conf/neo4j.conf:
        
        dbms.security.procedures.roles=com.maxdemarzi.connected:secured       
        dbms.security.procedures.unrestricted=com.maxdemarzi.*
                
4. Start Neo4j server.



Instructions
----

1. Loggin as neo4j admin user, set your new password if needed.

2. Create the schema:

        CALL com.maxdemarzi.generateSecuritySchema;

3. Create a user with property rights:
 
        CALL com.maxdemarzi.createUserWithPropertyRights('max', 'swordfish', false);
                        
        the parameters are:
        
        CALL com.maxdemarzi.createUserWithPropertyRights(username, password, mustChange);
        
4. Create some data:
        
        CREATE (n1:Person {name:'Tom', age:37})
        CREATE (n2:Person {name:'Tim', age:38})
        CREATE (n1)-[:KNOWS]->(n2);
        
5. Give user 'max' access to the name property of n2.
        
        MATCH (n2:Person {name:'Tim'})
        CALL com.maxdemarzi.addUserPermission('max', n2, 'name') 
        YIELD value RETURN value; 
 
6. Using Cypher-shell (in the Neo4j/bin directory) log in as user 'max', password 'swordfish'.        
        
7. Try a query:
        
        CALL com.maxdemarzi.connected('Person', 'name', 'Tom', 'KNOWS', 2)
        YIELD value RETURN value;
        
You will not be able to log in via the Browser with the user "max", because it requires the Reader role.        