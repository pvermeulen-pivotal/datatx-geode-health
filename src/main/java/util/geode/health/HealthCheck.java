package util.geode.health;

import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
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

import org.apache.geode.cache.client.ClientCache;
import org.apache.geode.cache.client.ClientCacheFactory;
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
import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import util.geode.health.domain.Health;
import util.geode.health.domain.Member;
import util.geode.monitor.Constants;
import util.geode.monitor.Util;
import util.geode.monitor.impl.MonitorImpl;
import util.geode.monitor.log.LogMessage;
import util.geode.monitor.xml.MxBeans;

public class HealthCheck {
	private static final String ALERT_URL = "alert-url";
	private static final String ALERT_URL_PARMS = "alert-url-parms";
	private static final String ALERT_CLUSTER_FQDN = "alert-cluster-fqdn";

	private Util util = new Util();

	private HashMap<String, String> httpParams = new HashMap<String, String>();

	private String jmxHost;
	private List<String> jmxHosts = new ArrayList<String>();
	private int nextHostIndex = 1;
	private int jmxPort = 1099;
	private JMXServiceURL url = null;
	private MxBeans mxBeans;
	private JMXConnector jmxConnection;
	private MBeanServerConnection mbs;
	private ObjectName systemName;
	private int reconnectRetryAttempts = 5;
	private int reconnectRetryCount = 0;
	private Logger LOG = LoggerFactory.getLogger(HealthCheck.class);
	private AtomicBoolean jmxConnectionActive = new AtomicBoolean(false);
	private Properties alertProps;
	private String alertUrl;
	private String alertClusterFqdn;
	private String cmdbUrl;

	public enum MemberType {
		LOCATOR, SERVER
	};

	public void start() throws Exception {
		loadMonitorProps();
		getSendAlertPropertyFile();
		if (connect()) {
			doHealthCheck();
			closeConnections();
		}
	}

	private void doHealthCheck() throws Exception {
		Health health = getHealthDetails();
		JSONObject jsonObj = new JSONObject(getCmdbHealth());
		List<Member> locators = getMembers(Arrays.asList(health.getLocators()), jsonObj, "locators",
				MemberType.LOCATOR);
		if (!checkMemberCount(health.getLocatorCnt(), jsonObj, "locatorCount")) {
			sendMissingMemberAlert(locators);
		}
		List<Member> unresponsiveMembers = connectToMembers(locators);
		sendUnresponsiveMemberAlert(unresponsiveMembers);

		List<Member> servers = getMembers(Arrays.asList(health.getServers()), jsonObj, "servers", MemberType.SERVER);
		if (!checkMemberCount(health.getServerCnt(), jsonObj, "serverCount")) {
			sendMissingMemberAlert(servers);
		}
		unresponsiveMembers = connectToMembers(servers);
		sendUnresponsiveMemberAlert(unresponsiveMembers);

		for (Member member : servers) {
			getJVMGCTime(member, "gcTimeMillis", jsonObj, "maximumGCTimeMillis");
		}

		if (!checkMemberCount(health.getGatewaySenderCnt(), jsonObj, "gatewaySenderCount")) {
		}

		if (!checkMemberCount(health.getGatewayReceiverCnt(), jsonObj, "gatewayReceiverCount")) {
		}

		double usagePercent = jsonObj.getDouble("maximumHeapUsagePercent");
		if (health.getUsedHeap() > (health.getTotalHeap() * usagePercent)) {
			System.out.println("send maximum heap alert");
		}
	}

	private void sendMissingMemberAlert(List<Member> members) {
		for (Member member : members) {
			if (member.isMissing()) {
				System.out.println(member + " send missing alert");
			}
		}
	}

	private void sendUnresponsiveMemberAlert(List<Member> members) {
		for (Member member : members) {
			System.out.println(member + " send unresponsive alert");
		}
	}

	private List<Member> connectToMembers(List<Member> members) {
		List<Member> unresponsiveMembers = new ArrayList<Member>();
		for (Member member : members) {
			if (!member.isMissing()) {
				ClientCache cache = createConnection(member);
				if (cache == null) {
					unresponsiveMembers.add(member);
				} else {
					cache.close();
					cache = null;
				}
			}
		}
		return unresponsiveMembers;
	}

	private ClientCache createConnection(Member member) {
		if (member.getType().equals(MemberType.LOCATOR)) {
			return new ClientCacheFactory().addPoolLocator(member.getHost(), member.getPort())
					.set("name", member.getName()).create();
		} else {
			return new ClientCacheFactory().addPoolServer(member.getHost(), member.getPort())
					.set("name", member.getName()).create();
		}
	}

	private List<Member> getMembers(List<String> members, JSONObject jsonObj, String key, MemberType type) {
		List<Member> memberList = new ArrayList<Member>();
		JSONArray jarray = jsonObj.getJSONArray(key);
		for (int i = 0; i < jarray.length(); i++) {
			JSONObject jObj = (JSONObject) jarray.get(i);
			String name = jObj.getString("name");
			String host = jObj.getString("host");
			int port = jObj.getInt("port");
			if (!members.contains(name)) {
				memberList.add(new Member(name, host, port, true, type));
			} else {
				memberList.add(new Member(name, host, port, false, type));
			}
		}
		return memberList;
	}

	private boolean checkMemberCount(int count, JSONObject jObj, String key) {
		if (count != jObj.getInt(key)) {
			return false;
		}
		return true;
	}

	private void getJVMGCTime(Member member, String name, JSONObject jObj, String jsonName) throws Exception {
		CompositeDataSupport cds = null;
		long currentGCTimeMillis = 0;
		long maximumGCTimeMillis = 0;
		if (!member.isMissing()) {
			cds = (CompositeDataSupport) mbs.invoke(systemName, "showJVMMetrics", new Object[] { member.getName() },
					new String[] { String.class.getName() });
			currentGCTimeMillis = (long) cds.get(name);
			maximumGCTimeMillis = jObj.getLong(jsonName);
			if (currentGCTimeMillis > maximumGCTimeMillis) {
				System.out.println("send GC Time alert");
			}
		}
	}

	private Health getHealthDetails() throws Exception {
		Health health = new Health();
		AttributeList al = getHealthAttributes(new String[] { "MemberCount", "LocatorCount" }, systemName);
		health.setLocatorCnt(Integer.parseInt(String.valueOf(((Attribute) al.get(1)).getValue())));
		health.setServerCnt(
				Integer.parseInt(String.valueOf(((Attribute) al.get(0)).getValue())) - health.getLocatorCnt());
		al = getHealthAttributes(new String[] { "TotalHeapSize", "UsedHeapSize" }, systemName);
		health.setTotalHeap(Double.valueOf(String.valueOf(((Attribute) al.get(0)).getValue())));
		health.setUsedHeap(Double.valueOf(String.valueOf(((Attribute) al.get(1)).getValue())));
		String[] senders = getNames(Constants.ListType.SENDERS);
		String[] receivers = getNames(Constants.ListType.RECEIVERS);
		health.setGatewaySenderCnt(senders.length);
		health.setGatewayReceiverCnt(receivers.length);
		health.setLocators(getNames(Constants.ListType.LOCATORS));
		health.setServers(getNames(Constants.ListType.SERVERS));
		health.setRegions(getNames(Constants.ListType.REGION_PATHS));
		return health;
	}

	private String[] getNames(Constants.ListType type) throws Exception {
		return util.getNames(mbs, systemName, type);
	}

	private AttributeList getHealthAttributes(String[] attrs, ObjectName oName) throws Exception {
		return util.getAttributes(mbs, oName, attrs);
	}

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
				reconnectRetryCount = 0;
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

	private void disconnect() {
		try {
			jmxConnection.close();
		} catch (Exception e) {
			LOG.error("Internal exception: " + e.getMessage());
		}
	}

	private void closeConnections() {
		disconnect();
		jmxConnectionActive.set(false);
	}

	private void loadMonitorProps() {
		int value = 0;
		String[] split;
		Properties monitorProps = new Properties();

		try {
			monitorProps.load(MonitorImpl.class.getClassLoader().getResourceAsStream(Constants.HM_PROPS));

			jmxHost = monitorProps.getProperty(Constants.P_MANAGERS);
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

			value = Integer.parseInt(monitorProps.getProperty(Constants.P_PORT));
			if (value == 0) {
				throw new RuntimeException(Constants.E_PORT);
			} else {
				jmxPort = value;
			}

		} catch (IOException e) {
			throw new RuntimeException(Constants.E_PROC_PROPS + e.getMessage());
		}
	}

	private boolean getSendAlertPropertyFile() {
		boolean alertLoaded = false;
		try {
			InputStream input = HealthCheck.class.getClassLoader().getResourceAsStream("alert.properties");
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

	private SSLConnectionSocketFactory setupSSL() throws Exception {
		SSLContext ssl_ctx = SSLContext.getInstance("TLS");
		TrustManager[] trust_mgr = get_trust_mgr();
		ssl_ctx.init(null, trust_mgr, new SecureRandom());
		HostnameVerifier allowAllHosts = new NoopHostnameVerifier();
		return new SSLConnectionSocketFactory(ssl_ctx, allowAllHosts);
	}

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
			severity = "MINOR";
		}

		String json = new JSONObject().put("fqdn", alertClusterFqdn).put("severity", severity)
				.put("message", logMessage.getHeader().toString() + " " + logMessage.getBody()).toString();
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

	private String getCmdbHealth() {
		String content = "";
		try {
			content = new String(Files.readAllBytes(Paths.get("cmdb-health.json")));
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

	public static void main(String[] args) throws Exception {
		HealthCheck healthCheck = new HealthCheck();
		healthCheck.start();
	}
}
