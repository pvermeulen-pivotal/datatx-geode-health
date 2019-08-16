package util.geode.health.domain;

import java.util.Arrays;

public class Health {
	private int serverCnt;
	private int locatorCnt;
	private int gatewayReceiverCnt; 
	private int gatewaySenderCnt;
	private double totalHeap;
	private double usedHeap;
	private double gcTimeMillis;
	private String[] locators;
	private String[] servers;
	private String[] regions;

	public Health() {}

	public Health(int serverCnt, int locatorCnt, int gatewayReceiverCnt, int gatewaySenderCnt, double totalHeap,
			double usedHeap, double gcTimeMillis, String[] locators, String[] servers, String[] regions) {
		this.serverCnt = serverCnt;
		this.locatorCnt = locatorCnt;
		this.gatewayReceiverCnt = gatewayReceiverCnt;
		this.gatewaySenderCnt = gatewaySenderCnt;
		this.totalHeap = totalHeap;
		this.usedHeap = usedHeap;
		this.gcTimeMillis = gcTimeMillis;
		this.locators = locators;
		this.servers = servers;
		this.regions = regions;
	}

	public int getServerCnt() {
		return serverCnt;
	}

	public void setServerCnt(int serverCnt) {
		this.serverCnt = serverCnt;
	}

	public int getLocatorCnt() {
		return locatorCnt;
	}

	public void setLocatorCnt(int locatorCnt) {
		this.locatorCnt = locatorCnt;
	}

	public int getGatewayReceiverCnt() {
		return gatewayReceiverCnt;
	}

	public void setGatewayReceiverCnt(int gatewayReceiverCnt) {
		this.gatewayReceiverCnt = gatewayReceiverCnt;
	}

	public int getGatewaySenderCnt() {
		return gatewaySenderCnt;
	}

	public void setGatewaySenderCnt(int gatewaySenderCnt) {
		this.gatewaySenderCnt = gatewaySenderCnt;
	}

	public double getTotalHeap() {
		return totalHeap;
	}

	public void setTotalHeap(double totalHeap) {
		this.totalHeap = totalHeap;
	}

	public double getUsedHeap() {
		return usedHeap;
	}

	public void setUsedHeap(double usedHeap) {
		this.usedHeap = usedHeap;
	}

	public String[] getLocators() {
		return locators;
	}

	public void setLocators(String[] locators) {
		this.locators = locators;
	}

	public String[] getServers() {
		return servers;
	}

	public void setServers(String[] servers) {
		this.servers = servers;
	}

	public String[] getRegions() {
		return regions;
	}

	public void setRegions(String[] regions) {
		this.regions = regions;
	}

	public double getGcTimeMillis() {
		return gcTimeMillis;
	}

	public void setGcTimeMillis(double gcTimeMillis) {
		this.gcTimeMillis = gcTimeMillis;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + gatewayReceiverCnt;
		result = prime * result + gatewaySenderCnt;
		long temp;
		temp = Double.doubleToLongBits(gcTimeMillis);
		result = prime * result + (int) (temp ^ (temp >>> 32));
		result = prime * result + locatorCnt;
		result = prime * result + Arrays.hashCode(locators);
		result = prime * result + Arrays.hashCode(regions);
		result = prime * result + serverCnt;
		result = prime * result + Arrays.hashCode(servers);
		temp = Double.doubleToLongBits(totalHeap);
		result = prime * result + (int) (temp ^ (temp >>> 32));
		temp = Double.doubleToLongBits(usedHeap);
		result = prime * result + (int) (temp ^ (temp >>> 32));
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Health other = (Health) obj;
		if (gatewayReceiverCnt != other.gatewayReceiverCnt)
			return false;
		if (gatewaySenderCnt != other.gatewaySenderCnt)
			return false;
		if (Double.doubleToLongBits(gcTimeMillis) != Double.doubleToLongBits(other.gcTimeMillis))
			return false;
		if (locatorCnt != other.locatorCnt)
			return false;
		if (!Arrays.equals(locators, other.locators))
			return false;
		if (!Arrays.equals(regions, other.regions))
			return false;
		if (serverCnt != other.serverCnt)
			return false;
		if (!Arrays.equals(servers, other.servers))
			return false;
		if (Double.doubleToLongBits(totalHeap) != Double.doubleToLongBits(other.totalHeap))
			return false;
		if (Double.doubleToLongBits(usedHeap) != Double.doubleToLongBits(other.usedHeap))
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "Health [serverCnt=" + serverCnt + ", locatorCnt=" + locatorCnt + ", gatewayReceiverCnt="
				+ gatewayReceiverCnt + ", gatewaySenderCnt=" + gatewaySenderCnt + ", totalHeap=" + totalHeap
				+ ", usedHeap=" + usedHeap + ", gcTimeMillis=" + gcTimeMillis + ", locators="
				+ Arrays.toString(locators) + ", servers=" + Arrays.toString(servers) + ", regions="
				+ Arrays.toString(regions) + "]";
	}
}
