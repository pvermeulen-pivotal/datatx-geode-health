package util.geode.health.domain;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Health {
	private int serverCnt;
	private int locatorCnt;
	private int gatewayQueueSize;
	private double totalHeap;
	private double usedHeap;
	private double gcTimeMillis;
	private String[] locators;
	private String[] servers;
	private String[] regions;
	private boolean gateway = false;
	private List<GatewaySender> gatewaySenders;

	public Health() {
	}

	public Health(int serverCnt, int locatorCnt, int gatewayQueueSize, double totalHeap, double usedHeap,
			double gcTimeMillis, String[] locators, String[] servers, String[] regions, boolean gateway) {
		this.serverCnt = serverCnt;
		this.locatorCnt = locatorCnt;
		this.gatewayQueueSize = gatewayQueueSize;
		this.totalHeap = totalHeap;
		this.usedHeap = usedHeap;
		this.gcTimeMillis = gcTimeMillis;
		this.locators = locators;
		this.servers = servers;
		this.regions = regions;
		this.gateway = gateway;
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

	public int getGatewayQueueSize() {
		return gatewayQueueSize;
	}

	public void setGatewayQueueSize(int gatewayQueueSize) {
		this.gatewayQueueSize = gatewayQueueSize;
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

	public double getGcTimeMillis() {
		return gcTimeMillis;
	}

	public void setGcTimeMillis(double gcTimeMillis) {
		this.gcTimeMillis = gcTimeMillis;
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

	public boolean isGateway() {
		return gateway;
	}

	public void setGateway(boolean gateway) {
		this.gateway = gateway;
	}

	public List<GatewaySender> getGatewaySenders() {
		if (gatewaySenders == null)
			gatewaySenders = new ArrayList<GatewaySender>();
		return gatewaySenders;
	}

	public void setGatewaySenders(List<GatewaySender> gatewaySenders) {
		this.gatewaySenders = gatewaySenders;
	}

	public void addGatewaySender(GatewaySender gatewaySender) {
		if (gatewaySenders == null)
			gatewaySenders = new ArrayList<GatewaySender>();
		this.gatewaySenders.add(gatewaySender);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (gateway ? 1231 : 1237);
		result = prime * result + gatewayQueueSize;
		result = prime * result + ((gatewaySenders == null) ? 0 : gatewaySenders.hashCode());
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
		if (gateway != other.gateway)
			return false;
		if (gatewayQueueSize != other.gatewayQueueSize)
			return false;
		if (gatewaySenders == null) {
			if (other.gatewaySenders != null)
				return false;
		} else if (!gatewaySenders.equals(other.gatewaySenders))
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

}
