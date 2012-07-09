Here are sample (non-production use!!!) self-signed keys to run the FEDIZ samples.

Don't use these keys in production--everyone has them!  At a minimum, regenerate new keys using the scripts (with different passwords) below.  These will be just self-signed keys however, for real production use having third-party signed CA keys is highly recommended.

1.) Tomcat keys:  The Tomcat keys can be simply placed in the root folder of each Tomcat installation.  They are used to configure SSL for the Tomcat instances as described here: http://cxf.apache.org/fediz-tomcat.html.

Keys:
a.) tomcat-idp.jks: keystore for the Tomcat instance holding the IDP and IDP STS.
Alias: mytomidpkey
Needs to trust: Nobody.
Needs to be trusted by: IDP WAR

Scripts:
keytool -genkeypair -validity 730 -alias mytomidpkey -keystore tomcat-idp.jks -dname "cn=localhost" -keypass tompass -storepass tompass

keytool -keystore tomcat-idp.jks -storepass tompass -export -alias mytomidpkey -file MyTCIDP.cer

b.) tomcat-rp.jks: keystore for the Tomcat instance holding the relying party applications for both samples (simpleWebapp and wsclientWebapp)
Alias: mytomrpkey
Needs to trust: Nobody.
Needs to be trusted by: Nobody.

Scripts:
keytool -genkeypair -validity 730 -alias mytomrpkey -keystore tomcat-rp.jks -dname "cn=localhost" -keypass tompass -storepass tompass

c.) tomcat-wsp.jks: keystore for the Tomcat instance holding the web service provider in the second (wsclientWebapp) sample.
Alias: mytomwspkey
Needs to trust: Nobody.
Needs to be trusted by: wsclientWebapp's webapp module

Script:
keytool -genkeypair -validity 730 -alias mytomwspkey -keystore tomcat-wsp.jks -dname "cn=localhost" -keypass tompass -storepass tompass

2.) IDP keystore:
Alias: myidpkey
Location: services/idp/src/main/resources/idpstore.jks
Needs to trust: mytomidpkey (because it makes an SSL call to the IDP STS)
Needs to be trusted by: IDP STS

Scripts:
keytool -genkey -keyalg RSA -sigalg SHA1withRSA -validity 730 -alias myidpkey -keypass ikpass -storepass ispass -keystore idpstore.jks

keytool -import -trustcacerts -keystore idpstore.jks -storepass ispass -alias mytomidpkey -file MyTCIDP.cer -noprompt

keytool -export -rfc -keystore idpstore.jks -storepass ispass -alias myidpkey -file MyIDP.cer

3.) Making the key for the IDP STS:
Alias: mystskey
Location: services/idp/src/main/resources/stsstore.jks
Needs to trust: myidpkey (because of X.509 auth between IDP and IDP STS)
Needs to be trusted by: wsclientWebapp's webservice

Scripts:
keytool -genkey -keyalg RSA -sigalg SHA1withRSA -validity 730 -alias mystskey -keypass stskpass -storepass stsspass -keystore stsstore.jks

keytool -import -trustcacerts -keystore stsstore.jks -storepass stsspass -alias myidpkey -file MyIDP.cer -noprompt

4.) Making the key for the simpleWebapp sample:  No additional keys needed.

5.) Making the key for the wsclientWebapp "webapp" sample:  
Location: examples/wsclientWebapp/webapp/src/main/resources/webappKeystore.jks
Trust relationships needed: mytomidpkey (to access IDP STS via HTTPS, mytomwspkey (to access web service via HTTPS)
Needs to be trusted by: Nobody.


6.) Making the keystore for the wsclientWebapp "webservice" sample:
Location: examples/wsclientWebapp/webservice/service/src/main/resources/webserviceKeystore.jks (has no key, just a truststore)
Trust relationships needed: IDP STS (signature verification)
Needs to be trusted by: Nobody.

keytool -import -trustcacerts -keystore webserviceKeystore.jks -storepass wsspass -alias mystskey -file MySTS.cer -noprompt



