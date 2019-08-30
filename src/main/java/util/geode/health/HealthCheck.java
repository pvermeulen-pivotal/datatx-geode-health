package util.geode.health;

public interface HealthCheck {
	public long getHealthCheckInterval();

	public void initialize() throws Exception;

	public void start() throws Exception;
	
	public void closeConnections();
	
	public boolean isAttachedToManager();
}
