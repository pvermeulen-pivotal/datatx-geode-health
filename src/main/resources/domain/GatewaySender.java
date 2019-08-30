package util.geode.health.domain;

import javax.management.ObjectName;

public class GatewaySender {
	public static enum GatewayType {
		SERIAL, PARALLEL
	};

	private String name;
	private String member;
	private ObjectName object;
	private GatewayType type;
	private boolean primary = false;
	private boolean connected;
	private int eventQueueSize;

	public GatewaySender() {
	}

	public GatewaySender(String name, String member, ObjectName object, GatewayType type, boolean primary,
			int eventQueueSize, boolean connected) {
		this.name = name;
		this.member = member;
		this.object = object;
		this.type = type;
		this.primary = primary;
		this.connected = connected;
		this.eventQueueSize = eventQueueSize;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getMember() {
		return member;
	}

	public void setMember(String member) {
		this.member = member;
	}

	public ObjectName getObject() {
		return object;
	}

	public void setObject(ObjectName object) {
		this.object = object;
	}

	public GatewayType getType() {
		return type;
	}

	public void setType(GatewayType type) {
		this.type = type;
	}

	public boolean isPrimary() {
		return primary;
	}

	public void setPrimary(boolean primary) {
		this.primary = primary;
	}

	public boolean isConnected() {
		return connected;
	}

	public void setConnected(boolean connected) {
		this.connected = connected;
	}

	public int getEventQueueSize() {
		return eventQueueSize;
	}

	public void setEventQueueSize(int eventQueueSize) {
		this.eventQueueSize = eventQueueSize;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (connected ? 1231 : 1237);
		result = prime * result + eventQueueSize;
		result = prime * result + ((member == null) ? 0 : member.hashCode());
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((object == null) ? 0 : object.hashCode());
		result = prime * result + (primary ? 1231 : 1237);
		result = prime * result + ((type == null) ? 0 : type.hashCode());
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
		GatewaySender other = (GatewaySender) obj;
		if (connected != other.connected)
			return false;
		if (eventQueueSize != other.eventQueueSize)
			return false;
		if (member == null) {
			if (other.member != null)
				return false;
		} else if (!member.equals(other.member))
			return false;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		if (object == null) {
			if (other.object != null)
				return false;
		} else if (!object.equals(other.object))
			return false;
		if (primary != other.primary)
			return false;
		if (type != other.type)
			return false;
		return true;
	}

	@Override
	public String toString() {
		return "GatewaySender [name=" + name + ", member=" + member + ", object=" + object + ", type=" + type
				+ ", primary=" + primary + ", connected=" + connected + ", eventQueueSize=" + eventQueueSize + "]";
	}
}
