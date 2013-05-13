Build the STS
----------------------------


STS with LDAP backend
---------------------

Build the STS:
mvn clean install -Pldap


STS with two realms
-------------------

Build the STS:
mvn clean install -Prealms

Proceed with the following steps to update the signing certificates:

keytool -genkeypair -validity 3600 -alias realma -keystore stsrealm_a.jks -dname "cn=REALMA" -keypass realma -storepass storepass
keytool -keystore stsrealm_a.jks -storepass storepass -export -alias realma -file realma.cert


keytool -genkeypair -validity 3600 -alias realmb -keystore stsrealm_b.jks -dname "cn=REALMB" -keypass realmb -storepass storepass
keytool -keystore stsrealm_b.jks -storepass storepass -export -alias realmb -file realmb.cert

keytool -import -trustcacerts -keystore ststrust.jks -storepass storepass -alias realma -file realma.cert -noprompt
keytool -import -trustcacerts -keystore ststrust.jks -storepass storepass -alias realmb -file realmb.cert -noprompt


