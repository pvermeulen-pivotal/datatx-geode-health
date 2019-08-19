package util.geode.health;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.openmbean.CompositeDataSupport;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.geode.cache.Region;
import org.apache.geode.cache.client.ClientCache;
import org.apache.geode.cache.client.ClientCacheFactory;
import org.apache.geode.cache.client.ClientRegionShortcut;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.json.JSONArray;
import org.json.JSONObject;

import util.geode.health.domain.GatewaySender;
import util.geode.health.domain.GatewaySender.GatewayType;
import util.geode.health.domain.Health;
import util.geode.health.domain.Member;
import util.geode.monitor.Constants;
import util.geode.monitor.Util;
import util.geode.monitor.impl.MonitorImpl;
import util.geode.monitor.log.LogHeader;
import util.geode.monitor.log.LogMessage;

public class HealthCheck {
	private static final String ALERT_URL = "alert-url";
	private static final String ALERT_URL_PARMS = "alert-url-parms";
	private static final String ALERT_CLUSTER_FQDN = "alert-cluster-fqdn";
	private static final String HEALTH_PROPS = "health.properties";
	private static final String ALERT_PROPS = "alert.properties";
	private static final String SERVER_COUNT= "serverCount";
	private static final String GC_TIME_MILLIS = "gcTimeMillis";
	private static final String MAX_GC_TIME_MILLIS = "maximumGCTimeMillis";
	private static final String MAX_HEAP_USAGE_PERCENT = "maximumHeapUsagePercent";
	private static final String GATEWAY_SENDER = "gatewaySender";
	private static final String EVENT_QUEUE_SIZE = "EventQueueSize";
	private static final String CONNECTED = "Connected";
	private static final String MEMBER = "member";
	private static final String CLUSTER_NAME = "clusterName";
	private static final String GATEWAY_MAX_QUEUE_SIZE = "gatewayMaximumQueueSize";
	private static final String MAJOR = "MAJOR";
	private static final String MINOR = "MINOR";
	private static final String APPL_LOG = "applicationLog";
	private static final String LOG4J_PROPS = "log4j.properties";
	private static final String NAME= "name";
	private static final String HOST = "host";
	private static final String PORT = "port";
	private static final String SHOW_JVM_METRICS = "showJVMMetrics";
	private static final String MEMBER_COUNT ="MemberCount";
	private static final String LOCATOR_COUNT = "LocatorCount";
	private static final String TOT_HEAP_SPACE = "TotalHeapSize";
	private static final String USED_HEAP_SPACE = "UsedHeapSize";
	private static final String TLS = "TLS";
	private static final String SEVERITY = "severity";
	private static final String FQDN = "fqdn";
	private static final String MESSAGE="message";
	private static final String CMDB_HEALTH_JSON = "cmdb-health.json";
	private static final String LOCATORS = "locators";
	private static final String SERVERS = "servers";
	private static final String PARALLEL = "Parallel";
	private static final String PRIMARY = "Primary";

	private Util util = new Util();

	private HashMap<String, String> httpParams = new HashMap<String, String>();

	private String jmxHost;
	private List<String> jmxHosts = new ArrayList<String>();
	private int nextHostIndex = 1;
	private int jmxPort = 1099;
	private JMXServiceURL url = null;
	private JMXConnector jmxConnection;
	private MBeanServerConnection mbs;
	private ObjectName systemName;
	private Logger LOG;
	private AtomicBoolean jmxConnectionActive = new AtomicBoolean(false);
	private Properties alertProps;
	private String alertUrl;
	private String alertClusterFqdn;
	private String cmdbUrl;

	public enum MemberType {
		LOCATOR, SERVER
	};

	/**
	 * start the health check for GemFire cluster
	 * 
	 * @throws Exception
	 */
	public void start() throws Exception {
		// create log4j log file appender
		createLogAppender();
		LOG.info("Started health check at " + new Date());
		// load health properties from file
		loadHealthProps();
		// load alert properties from file
		getSendAlertPropertyFile();
		// connect to locator JMX
		if (connect()) {
			// if sucessfully connected to JMX perform health check pn cluster
			doHealthCheck();
			// close JMX connections
			closeConnections();
		}
	}
	
	/**
	 * Perform the health check using GemFire cluster and CMDB
	 * 
	 * @throws Exception
	 */
	private void doHealthCheck() throws Exception {
		// get GemFire health
		Health health = getHealthDetails();
		// get CMDB health
		JSONObject jsonObj = new JSONObject(getCmdbHealth());
		// get all locators
		List<Member> locators = getMembers(Arrays.asList(health.getLocators()), jsonObj, LOCATORS,
				MemberType.LOCATOR);
		// check locator count to CMDB
		if (!checkMemberCount(health.getLocatorCnt(), jsonObj, LOCATOR_COUNT)) {
			// If missing locator(s) send alert
			sendMissingMemberAlert(locators, jsonObj);
		}
		// Connect to all locators
		List<Member> unresponsiveMembers = connectToMembers(locators, health.getRegions(), jsonObj, true);
		// send alert for non-responsive locator(s)
		sendUnresponsiveMemberAlert(unresponsiveMembers, jsonObj);

		// get all cache servers
		List<Member> servers = getMembers(Arrays.asList(health.getServers()), jsonObj, SERVERS, MemberType.SERVER);
		// check cache server count to CMDB
		if (!checkMemberCount(health.getServerCnt(), jsonObj, SERVER_COUNT)) {
			// If missing cache server(s) send alert
			sendMissingMemberAlert(servers, jsonObj);
		}
		// connect to all servers
		unresponsiveMembers = connectToMembers(servers, null, jsonObj, false);
		// send alert for non-responsive cache server(s)
		sendUnresponsiveMemberAlert(unresponsiveMembers, jsonObj);

		// for each cache server get GC Time
		for (Member member : servers) {
			// get GC time and verify against threshold
			getJVMGCTime(member, GC_TIME_MILLIS, jsonObj, MAX_GC_TIME_MILLIS);
		}

		// check to see if cluster used heap greater than threshold
		double usagePercent = jsonObj.getDouble(MAX_HEAP_USAGE_PERCENT);
		if (health.getUsedHeap() > (health.getTotalHeap() * usagePercent)) {
			// used heap over threshold send alert
			buildSpecialLogMessage(
					"Cluster's maximum heap for all cache servers exceeded. Total used heap=" + health.getUsedHeap(),
					MAJOR, jsonObj.getString(CLUSTER_NAME));
			LOG.error("Cluster: " + jsonObj.getString(CLUSTER_NAME)
					+ " maximum heap for all cache servers exceeded. Total used heap=" + health.getUsedHeap());
		}

		// get gateway senders if any
		ObjectName[] objects = util.getObjectNames(mbs, systemName, Constants.ObjectNameType.GATEWAY_SENDERS);
		if (objects == null || objects.length == 0)
			return;

		health.setGateway(true);
		List<String> gatewaySenders = new ArrayList<String>();
		for (ObjectName name : objects) {
			String prop = name.getKeyProperty(GATEWAY_SENDER);
			// add to list all gateway senders with different sender ids
			if (!gatewaySenders.contains(prop))
				gatewaySenders.add(name.getKeyProperty(GATEWAY_SENDER));
		}

		// for each gateway sender see if connected and queue size is not over threshold
		for (String sender : gatewaySenders) {
			List<ObjectName> objectsByName = getGatewayObjectsByName(objects, sender);
			for (ObjectName object : objectsByName) {
				AttributeList attrs = util.getAttributes(mbs, object, new String[] { EVENT_QUEUE_SIZE, CONNECTED });
				if (attrs == null || attrs.size() == 0)
					break;
				Attribute attr = (Attribute) attrs.get(0);
				int eventQueueSize = (int) attr.getValue();
				attr = (Attribute) attrs.get(1);
				boolean connected = (boolean) attr.getValue();
				// check to see if gateway is a parallel gateway
				if (checkForParallelGateway(object)) {
					// if parallel create sender and add to list
					health.addGatewaySender(
							new GatewaySender(object.getKeyProperty(GATEWAY_SENDER), object.getKeyProperty(MEMBER),
									object, GatewayType.PARALLEL, false, eventQueueSize, connected));
				} else {
					// if gateway sender is a serial gateway
					if (getPrimarySerialGateway(object)) {
						// get the primary serial gateway create sender and add to list
						health.addGatewaySender(new GatewaySender(object.getKeyProperty(GATEWAY_SENDER),
								object.getKeyProperty(MEMBER), object, GatewayType.SERIAL, true, eventQueueSize,
								connected));
					} else {
						// add secondary gateway to list
						health.addGatewaySender(new GatewaySender(object.getKeyProperty(GATEWAY_SENDER),
								object.getKeyProperty(MEMBER), object, GatewayType.SERIAL, false, eventQueueSize,
								connected));
					}
				}
			}
		}

		// for each unique gateway sender
		for (GatewaySender gatewaySender : health.getGatewaySenders()) {
			// if parallel gateway
			if (gatewaySender.getType().equals(GatewayType.PARALLEL)) {
				if (!gatewaySender.isConnected()) {
					// if gateway not connected to remote side send event
					buildSpecialLogMessage(
							"Cluster: " + jsonObj.getString(CLUSTER_NAME) + " Sender not connected to remote system",
							MAJOR, gatewaySender.getMember());
					LOG.warn("Cluster: " + jsonObj.getString(CLUSTER_NAME)
							+ " Sender not connected to remote system. Member=" + gatewaySender.getMember());
				} else if (gatewaySender.getEventQueueSize() > jsonObj.getInt(GATEWAY_MAX_QUEUE_SIZE)) {
					// if gateway is connected and maximum queue size exceeds threashold send alert
					buildSpecialLogMessage("Cluster: " + jsonObj.getString(CLUSTER_NAME)
							+ " Queue size greater than limit of " + jsonObj.getInt(GATEWAY_MAX_QUEUE_SIZE), MAJOR,
							gatewaySender.getMember());
					LOG.warn("Cluster: " + jsonObj.getString(CLUSTER_NAME) + " Queue size greater than limit of "
							+ jsonObj.getInt(GATEWAY_MAX_QUEUE_SIZE) + " Member: " + gatewaySender.getMember());
				}
			} else {
				// if a serial gateway
				if (gatewaySender.isPrimary()) {
					// if gateway is the primary serial gateway
					if (!gatewaySender.isConnected()) {
						// if gateway is not connected to remote side send alert
						buildSpecialLogMessage("Cluster: " + jsonObj.getString(CLUSTER_NAME)
								+ " Sender not connected to remote system", MAJOR, gatewaySender.getMember());
						LOG.warn("Cluster: " + jsonObj.getString(CLUSTER_NAME)
								+ " Sender not connected to remote system. Member: " + gatewaySender.getMember());
					} else if (gatewaySender.getEventQueueSize() > jsonObj.getInt(GATEWAY_MAX_QUEUE_SIZE)) {
						// if serial gateway is connected and maximum queue size exceeds threshold send
						// alert
						buildSpecialLogMessage(
								"Cluster: " + jsonObj.getString(CLUSTER_NAME) + " Queue size greater than limit of "
										+ jsonObj.getInt(GATEWAY_MAX_QUEUE_SIZE),
										MAJOR, gatewaySender.getMember());
						LOG.warn("Cluster: " + jsonObj.getString(CLUSTER_NAME) + " Queue size greater than limit of "
								+ jsonObj.getInt(GATEWAY_MAX_QUEUE_SIZE) + " Member: " + gatewaySender.getMember());
					}
				}
			}
		}
	}

	/**
	 * Creates the log appender for application and exception log
	 */
	private void createLogAppender() {
		ClassLoader loader = Thread.currentThread().getContextClassLoader();
		URL url = loader.getResource(LOG4J_PROPS);
		PropertyConfigurator.configure(url);
		LOG = Logger.getLogger(APPL_LOG);
	}

	/**
	 * Build event log message
	 * 
	 * @param message
	 * @param level
	 * @param member
	 */
	private void buildSpecialLogMessage(String message, String level, String member) {
		long timeStamp = new Date().getTime();
		SimpleDateFormat df = new SimpleDateFormat(Constants.DATE_FORMAT);
		SimpleDateFormat tf = new SimpleDateFormat(Constants.TIME_FORMAT);
		SimpleDateFormat zf = new SimpleDateFormat(Constants.ZONE_FORMAT);

		LogHeader header = new LogHeader(level, df.format(timeStamp), tf.format(timeStamp), zf.format(timeStamp),
				member, null, null);

		LogMessage logMessage = new LogMessage(header, message);
		logMessage.setEvent(null);
		sendAlert(logMessage);
	}

	/**
	 * Get gateway mbean objects by name
	 * 
	 * @param objects
	 * @param name
	 * @return
	 */
	private List<ObjectName> getGatewayObjectsByName(ObjectName[] objects, String name) {
		List<ObjectName> objectsByName = new ArrayList<ObjectName>();
		if (objects != null && objects.length > 0) {
			for (ObjectName object : objects) {
				if (object.getKeyProperty(GATEWAY_SENDER).equals(name)) {
					objectsByName.add(object);
				}
			}
		}
		return objectsByName;
	}

	/**
	 * Check gateway mbeans for a parallel gateway implementation
	 * 
	 * @param name
	 * @return
	 * @throws Exception
	 */
	private boolean checkForParallelGateway(ObjectName name) throws Exception {
		if (name == null) {
			return false;
		}
		AttributeList attrs = util.getAttributes(mbs, name, new String[] { PARALLEL });
		if (attrs != null && attrs.size() == 1) {
			Attribute attr = (Attribute) attrs.get(0);
			if (PARALLEL.equalsIgnoreCase(attr.getName())) {
				return (boolean) attr.getValue();
			}
		}
		return false;
	}

	/**
	 * Check gateway mbeans for a serial gateway implementation
	 * 
	 * @param name
	 * @return
	 * @throws Exception
	 */
	private boolean getPrimarySerialGateway(ObjectName name) throws Exception {
		if (name == null) {
			return false;
		}

		boolean primary = false;
		AttributeList attrs = util.getAttributes(mbs, name, new String[] { PRIMARY });
		if (attrs != null && attrs.size() == 1) {
			Attribute attr = (Attribute) attrs.get(0);
			if (PRIMARY.equalsIgnoreCase(attr.getName())) {
				primary = (boolean) attr.getValue();
				if (primary)
					return primary;
			}
		}
		return false;
	}

	/**
	 * Send alert for missing GemFire cluster member(s)
	 * 
	 * @param members
	 */
	private void sendMissingMemberAlert(List<Member> members, JSONObject jsonObj) {
		for (Member member : members) {
			if (member.isMissing()) {
				buildSpecialLogMessage("Cluster: " + jsonObj.getString(CLUSTER_NAME) + jsonObj.getString(CLUSTER_NAME)
						+ " Member " + member.getName() + " is down", MAJOR, member.getName());
				LOG.error("Cluster: " + jsonObj.getString(CLUSTER_NAME) + " Member " + member.getName()
						+ " is down Member: " + member.getName());
			}
		}
	}

	/**
	 * Send alert for unresponsive GemFire member(s)
	 * 
	 * @param members
	 */
	private void sendUnresponsiveMemberAlert(List<Member> members, JSONObject jsonObj) {
		for (Member member : members) {
			buildSpecialLogMessage(
					"Cluster: " + jsonObj.getString(CLUSTER_NAME) + " Member " + member.getName() + " is unresponsive",
					MAJOR, member.getName());
			LOG.error("Cluster: " + jsonObj.getString(CLUSTER_NAME) + " Member " + member.getName()
					+ " is unresponsive Member: " + member.getName());
		}
	}

	/**
	 * Connect to member GemFire locator and/or cache servers
	 * 
	 * @param members
	 * @return
	 */
	private List<Member> connectToMembers(List<Member> members, String[] regions, JSONObject jObj,
			boolean processRegions) {
		boolean regionsProcessed = false;
		List<Member> unresponsiveMembers = new ArrayList<Member>();
		for (Member member : members) {
			if (!member.isMissing()) {
				ClientCache cache = createConnection(member);
				if (cache == null) {
					unresponsiveMembers.add(member);
				} else {
					if (processRegions) {
						if (!regionsProcessed) {
							regionsProcessed = true;
							checkRegion(cache, regions, member, jObj);
						}
					}
					cache.close();
					cache = null;
				}
			}
		}
		return unresponsiveMembers;
	}

	/**
	 * Select only three (3) regions from list of all regions and get three (3) keys
	 * from each of the three (3) regions. After selecting region and region keys
	 * read from the server to ensure server is working correctly.
	 * 
	 * @param cache
	 * @param regions
	 * @param member
	 */
	private void checkRegion(ClientCache cache, String[] regions, Member member, JSONObject json) {
		Region<Object, Object> region = null;
		String lastRegionName = null;
		int[] regionsToCheck = new int[] { 0, 0, 0 };
		Object[] keysToCheck = new Object[] { null, null, null };
		regionsToCheck[0] = 1;
		regionsToCheck[1] = (regions.length / 2) + 1;
		regionsToCheck[2] = regions.length;
		for (int i = 0; i < regionsToCheck.length; i++) {
			if (i < regions.length) {
				String regionName = regions[i];
				if (lastRegionName == null || !lastRegionName.equals(regionName)) {
					region = createRegion(cache, regionName);
					lastRegionName = regionName;
				}
				Set<Object> keys = region.keySetOnServer();
				Object[] objKeys = keys.toArray(new Object[keys.size()]);
				if (objKeys != null && objKeys.length > 0) {
					keysToCheck[0] = objKeys[0];
					int index = objKeys.length / 2;
					keysToCheck[1] = objKeys[index];
					keysToCheck[2] = objKeys[objKeys.length - 1];
					for (int j = 0; j < keysToCheck.length; j++) {
						Object value = region.get(keysToCheck[j]);
						if (value == null) {
							buildSpecialLogMessage("Cluster: " + json.getString(CLUSTER_NAME) + " Member "
									+ member.getName() + " region " + region.getName()
									+ " region object missing for key = " + keysToCheck[j], MAJOR, member.getName());
							LOG.error("Cluster: " + json.getString(CLUSTER_NAME) + " Member " + member.getName()
									+ " region " + region.getName() + " region object missing for key = "
									+ keysToCheck[j] + " Member: " + member.getName());
						}
					}
				}
				region.close();
				region = null;
			}
		}
	}

	/**
	 * Create a client region to access server region
	 * 
	 * @param cache
	 * @param name
	 * @return
	 */
	private Region<Object, Object> createRegion(ClientCache cache, String name) {
		return cache.createClientRegionFactory(ClientRegionShortcut.PROXY).create(name);
	}

	/**
	 * Create GemFire client connection
	 * 
	 * @param member
	 * @return
	 */
	private ClientCache createConnection(Member member) {
		if (member.getType().equals(MemberType.LOCATOR)) {
			return new ClientCacheFactory().addPoolLocator(member.getHost(), member.getPort())
					.set(NAME, member.getName()).setPdxReadSerialized(true).set("log-level", "CONFIG")
					.set("log-file", "logs/health-client.log").create();
		} else {
			return new ClientCacheFactory().addPoolServer(member.getHost(), member.getPort())
					.set(NAME, member.getName()).setPdxReadSerialized(true).set("log-level", "CONFIG")
					.set("log-file", "logs/health-client.log").create();
		}
	}

	/**
	 * Get GemFire cluster members and add to member list
	 * 
	 * @param members
	 * @param jsonObj
	 * @param key
	 * @param type
	 * @return
	 */
	private List<Member> getMembers(List<String> members, JSONObject jsonObj, String key, MemberType type) {
		List<Member> memberList = new ArrayList<Member>();
		JSONArray jarray = jsonObj.getJSONArray(key);
		for (int i = 0; i < jarray.length(); i++) {
			JSONObject jObj = (JSONObject) jarray.get(i);
			String name = jObj.getString(NAME);
			String host = jObj.getString(HOST);
			int port = jObj.getInt(PORT);
			if (!members.contains(name)) {
				memberList.add(new Member(name, host, port, true, type));
			} else {
				memberList.add(new Member(name, host, port, false, type));
			}
		}
		return memberList;
	}

	/**
	 * Check the count GemFire cluster locator and server members
	 * 
	 * @param count
	 * @param jObj
	 * @param key
	 * @return
	 */
	private boolean checkMemberCount(int count, JSONObject jObj, String key) {
		if (count != jObj.getInt(key)) {
			return false;
		}
		return true;
	}

	/**
	 * Get the JCM GC times for each cache server in the GemFire cluster
	 * 
	 * @param member
	 * @param name
	 * @param jObj
	 * @param jsonName
	 * @throws Exception
	 */
	private void getJVMGCTime(Member member, String name, JSONObject jObj, String jsonName) throws Exception {
		CompositeDataSupport cds = null;
		long currentGCTimeMillis = 0;
		long maximumGCTimeMillis = 0;
		if (!member.isMissing()) {
			cds = (CompositeDataSupport) mbs.invoke(systemName, SHOW_JVM_METRICS, new Object[] { member.getName() },
					new String[] { String.class.getName() });
			currentGCTimeMillis = (long) cds.get(name);
			maximumGCTimeMillis = jObj.getLong(jsonName);
			if (currentGCTimeMillis > maximumGCTimeMillis) {
				buildSpecialLogMessage(
						"Cluster: " + jObj.getString(CLUSTER_NAME) + "Member " + member.getName()
								+ " current GC time exceeds limit of " + maximumGCTimeMillis,
								MAJOR, member.getName());
				LOG.error("Cluster: " + jObj.getString(CLUSTER_NAME) + "Member " + member.getName()
						+ " current GC time exceeds limit of " + maximumGCTimeMillis + " Member: " + member.getName());
			}
		}
	}

	/**
	 * Retrieve GemFire cluster health details
	 * 
	 * @return
	 * @throws Exception
	 */
	private Health getHealthDetails() throws Exception {
		LOG.info("Retrieving GemFire health details");
		Health health = new Health();
		AttributeList al = getHealthAttributes(new String[] { MEMBER_COUNT, LOCATOR_COUNT }, systemName);
		health.setLocatorCnt(Integer.parseInt(String.valueOf(((Attribute) al.get(1)).getValue())));
		health.setServerCnt(
				Integer.parseInt(String.valueOf(((Attribute) al.get(0)).getValue())) - health.getLocatorCnt());
		al = getHealthAttributes(new String[] { TOT_HEAP_SPACE, USED_HEAP_SPACE }, systemName);
		health.setTotalHeap(Double.valueOf(String.valueOf(((Attribute) al.get(0)).getValue())));
		health.setUsedHeap(Double.valueOf(String.valueOf(((Attribute) al.get(1)).getValue())));
		String[] senders = getNames(Constants.ListType.SENDERS);
		if (senders.length > 0)
			health.setGateway(true);
		health.setLocators(getNames(Constants.ListType.LOCATORS));
		health.setServers(getNames(Constants.ListType.SERVERS));
		health.setRegions(getNames(Constants.ListType.REGIONS));
		return health;
	}

	/**
	 * Get JMX mbean names
	 * 
	 * @param type
	 * @return
	 * @throws Exception
	 */
	private String[] getNames(Constants.ListType type) throws Exception {
		return util.getNames(mbs, systemName, type);
	}

	/**
	 * Get the health attributes for JMX mbean
	 * 
	 * @param attrs
	 * @param oName
	 * @return
	 * @throws Exception
	 */
	private AttributeList getHealthAttributes(String[] attrs, ObjectName oName) throws Exception {
		return util.getAttributes(mbs, oName, attrs);
	}

	/**
	 * Connect to JMX manager
	 * 
	 * @return
	 */
	private boolean connect() {
		boolean connection = true;
		for (int i = 0; i < jmxHosts.size(); i++) {
			try {
				jmxHost = jmxHosts.get(nextHostIndex - 1);
				if ((nextHostIndex + 1) > jmxHosts.size()) {
					nextHostIndex = 1;
				} else {
					nextHostIndex = (nextHostIndex + 1);
				}
				String urlString = "service:jmx:rmi://" + jmxHost + "/jndi/rmi://" + jmxHost + ":" + jmxPort
						+ "/jmxrmi";
				url = new JMXServiceURL(urlString);
				jmxConnection = JMXConnectorFactory.connect(url);
				systemName = new ObjectName(Constants.DISTRIBUTED_SYSTEM_OBJECT_NAME);
				mbs = jmxConnection.getMBeanServerConnection();
				break;
			} catch (IOException e) {
				LOG.error("Connect: JMX Manager not running for URL: " + url + " " + e.getMessage());
				connection = false;
			} catch (Exception e) {
				LOG.error("Connect: exception: " + e.getMessage());
				connection = false;
			}
		}
		jmxConnectionActive.set(connection);
		return connection;
	}

	/**
	 * Disconnect from JMX manager
	 * 
	 */
	private void disconnect() {
		try {
			jmxConnection.close();
		} catch (Exception e) {
			LOG.error("Internal exception: " + e.getMessage());
		}
	}

	/**
	 * Close JMX connections and set connection active flag to false
	 * 
	 */
	private void closeConnections() {
		disconnect();
		jmxConnectionActive.set(false);
	}

	/**
	 * Load the health.properties configuration file
	 * 
	 */
	private void loadHealthProps() {
		int value = 0;
		String[] split;
		Properties healthProps = new Properties();

		try {
			healthProps.load(MonitorImpl.class.getClassLoader().getResourceAsStream(HEALTH_PROPS));

			jmxHost = healthProps.getProperty(Constants.P_MANAGERS);
			if ((jmxHost == null) || (jmxHost.length() == 0)) {
				throw new RuntimeException(Constants.E_HOST);
			}

			split = jmxHost.split(",");
			if (split.length > 0) {
				for (String str : split) {
					jmxHosts.add(str);
				}
			} else {
				split = jmxHost.split(" ");
				if (split.length > 0) {
					for (String str : split) {
						jmxHosts.add(str);
					}
				}
			}

			nextHostIndex = 1;
			if (jmxHosts.size() == 0) {
				jmxHosts.add(jmxHost);
			}

			value = Integer.parseInt(healthProps.getProperty(Constants.P_PORT));
			if (value == 0) {
				throw new RuntimeException(Constants.E_PORT);
			} else {
				jmxPort = value;
			}

		} catch (IOException e) {
			throw new RuntimeException(Constants.E_PROC_PROPS + e.getMessage());
		}
	}

	/**
	 * Load the alert.properties configuration file
	 * 
	 * @return
	 */
	private boolean getSendAlertPropertyFile() {
		boolean alertLoaded = false;
		try {
			InputStream input = HealthCheck.class.getClassLoader().getResourceAsStream(ALERT_PROPS);
			alertProps = new Properties();
			try {
				alertProps.load(input);
				alertUrl = (String) alertProps.get(ALERT_URL);
				if (alertUrl != null && alertUrl.length() > 0) {
					alertLoaded = true;
					String urlParams = (String) alertProps.get(ALERT_URL_PARMS);
					if (urlParams != null && urlParams.length() > 0) {
						if (!urlParams.endsWith(";")) {
							urlParams = urlParams + ";";
						}
						String[] params = urlParams.split(";");
						if (params != null && params.length > 0) {
							for (String str : params) {
								String[] keyValue = str.split(",");
								if (keyValue != null && keyValue.length > 0) {
									httpParams.put(keyValue[0], keyValue[1]);
								}
							}
						}
					}
					alertClusterFqdn = alertProps.getProperty(ALERT_CLUSTER_FQDN);
				}
			} catch (Exception e) {
				LOG.error("Error loading alert.properties Exception: " + e.getMessage());
			}
		} catch (Exception e) {
			LOG.error("Error loading alert.properties Exception: " + e.getMessage());
		}
		return alertLoaded;
	}

	/**
	 * If the server is using SSL this code is in lieu of a trust store and accepts
	 * any server SSL certificate
	 * 
	 * @return
	 */
	private TrustManager[] get_trust_mgr() {
		TrustManager[] certs = new TrustManager[] { new X509TrustManager() {
			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}

			public void checkClientTrusted(X509Certificate[] certs, String t) {
			}

			public void checkServerTrusted(X509Certificate[] certs, String t) {
			}
		} };
		return certs;
	}

	/**
	 * Setup the SSL default context to use unique trust Manager and noop host
	 * verifier
	 * 
	 * @return
	 * @throws Exception
	 */
	private SSLConnectionSocketFactory setupSSL() throws Exception {
		SSLContext ssl_ctx = SSLContext.getInstance(TLS);
		TrustManager[] trust_mgr = get_trust_mgr();
		ssl_ctx.init(null, trust_mgr, new SecureRandom());
		HostnameVerifier allowAllHosts = new NoopHostnameVerifier();
		return new SSLConnectionSocketFactory(ssl_ctx, allowAllHosts);
	}

	/**
	 * Generates the alert message and send to HTTP URL
	 * 
	 * @param logMessage
	 */
	public void sendAlert(LogMessage logMessage) {
		LOG.info("Sending Alert Message: url=" + alertUrl + " message=" + logMessage.toString());

		CloseableHttpClient httpclient = null;
		try {
			httpclient = HttpClients.custom().setSSLSocketFactory(setupSSL()).build();
		} catch (Exception e) {
			LOG.error("Error creating custom HttpClients exception=" + e.getMessage());
		}
		if (httpclient == null)
			return;

		HttpPost httppost = new HttpPost(alertUrl);

		String severity = logMessage.getHeader().getSeverity();
		if (logMessage.getHeader().getSeverity().equals(Constants.WARNING)) {
			severity = MINOR;
		}

		String json = new JSONObject().put(FQDN, alertClusterFqdn).put(SEVERITY, severity)
				.put(MESSAGE, logMessage.getHeader().toString() + " " + logMessage.getBody()).toString();
		LOG.info("Sending Alert Message json payload=" + json);

		try {
			StringEntity sEntity = new StringEntity(json);
			Set<String> keys = httpParams.keySet();
			for (String key : keys) {
				httppost.addHeader(key, httpParams.get(key));
			}
			try {
				httppost.setEntity(sEntity);
				HttpResponse response = null;
				try {
					response = httpclient.execute(httppost);
					int code = response.getStatusLine().getStatusCode();
					LOG.info("Alert URL Post Response Code: " + code);
					HttpEntity entity = response.getEntity();
					if (entity != null) {
						try {
							InputStream instream = entity.getContent();
							byte[] responseData = new byte[1000];
							int bytesRead = instream.read(responseData);
							if (bytesRead > 0) {
								LOG.info("Alert URL Post Response: " + new String(responseData));
							} else {
								LOG.info("No Alert URL Post Response received");
							}
							instream.close();
						} catch (Exception e) {
							LOG.error("Error reading http response exception: " + e.getMessage());
						}
					}
				} catch (Exception e) {
					LOG.error("Error executing HTTP post exception: " + e.getMessage());
				}
			} catch (Exception e) {
				LOG.error("Error adding header/entity exception: " + e.getMessage());
			}
		} catch (UnsupportedEncodingException e) {
			LOG.error("Error creating string entity exception=" + e.getMessage());
		}

		if (httpclient != null) {
			try {
				httpclient.close();
			} catch (IOException e) {
				LOG.error("Error closing HTTPClient exception=" + e.getMessage());
			}
		}

	}

	/**
	 * HTTP service to get the health properties from the CMDB
	 * 
	 * @return
	 */
	private String getCmdbHealth() {
		String content = "";
		try {
			content = new String(Files.readAllBytes(Paths.get(CMDB_HEALTH_JSON)));
		} catch (IOException e) {
			e.printStackTrace();
		}
		return content;

		// String password = null;
		// LOG.info("Getting Credhub Credentials");
		// CloseableHttpClient httpclient = null;
		// try {
		// if (this.cmdbUrl.startsWith("https")) {
		// httpclient = HttpClients.custom().setSSLSocketFactory(setupSSL()).build();
		// } else {
		// httpclient = HttpClients.createDefault();
		// }
		//
		// URIBuilder builder = new URIBuilder(this.cmdbUrl);
		// builder.setParameter("name", user);
		// HttpGet httpGet = new HttpGet(builder.build());
		// httpGet.addHeader("content-type", "application/json");
		// httpGet.addHeader("authorization", "bearer " + token);
		// HttpResponse response = null;
		// try {
		// response = httpclient.execute(httpGet);
		// int code = response.getStatusLine().getStatusCode();
		// LOG.info("HTTP credhub response code: " + code);
		// if (code == 200) {
		// HttpEntity entity = response.getEntity();
		// if (entity != null) {
		// try {
		// InputStream instream = entity.getContent();
		// byte[] responseData = new byte[5000];
		// int bytesRead = instream.read(responseData);
		// if (bytesRead > 0) {
		// String str = new String(responseData).trim();
		// if (!str.startsWith("{"))
		// str = "{" + str;
		// if (!str.endsWith("}"))
		// str = str + "}";
		// JSONObject json = new JSONObject(str);
		// JSONArray arr = json.getJSONArray("data");
		// int length = json.length();
		// for (int i = 0; i < length; i++) {
		// JSONObject jObj = arr.getJSONObject(i);
		// jObj = jObj.getJSONObject("value");
		// password = (String) jObj.get("password");
		// }
		// LOG.info("Credhub HTTP Get Response: " + str);
		// } else {
		// LOG.info("Credhub HTTP no response to Get received");
		// }
		// instream.close();
		// } catch (Exception e) {
		// LOG.error("Error reading HTTP Credhub Get response exception: " +
		// e.getMessage());
		// }
		// } else {
		// LOG.warn("HTTP Credhub Get response entity was null");
		// }
		// } else {
		// LOG.error("Invalid response code received from HTTP Credhub Get code = " +
		// code);
		// }
		// } catch (Exception e) {
		// LOG.error("Error executing HTTP Credhub Get exception: " + e.getMessage());
		// }
		// } catch (Exception e) {
		// LOG.error("Error adding Credhub header/entity exception: " + e.getMessage());
		// }
		//
		// if (httpclient != null) {
		// try {
		// httpclient.close();
		// } catch (IOException e) {
		// LOG.error("Error closing Credhub HTTP Client exception: " + e.getMessage());
		// }
		// }
		//
		// return password;
		// }

	}

	/**
	 * main routine
	 * 
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		HealthCheck healthCheck = new HealthCheck();
		healthCheck.start();
	}
}
