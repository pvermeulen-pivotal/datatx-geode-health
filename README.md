# Datatx Geode Health Check # 

## Overview ##

The health check is an application that performs validation of a GemFire cluster to ensure all locators, cache servers and 
gateways are running and operational. In the event, of component failure an alert will be generated for the failing component.

### Steps Performed ###

The following steps are performed by the health check application:   

|Operation|Description|
|---------|-----------|
|Retrieve GemFire MBeans|Read GemFire MBeans from locator configured as JMX manager|
|Retrieve Cluster CMDB|Call HTTP service to obtain cluster CMDB properties|
|Locator Count|Verify the number of running locators matches CMDB locator count|
|Connect Locator|Connects to each locator defined to validate connectivity is working|
|Server Count|Verify the number of running cache servers matches CMDB server count|
|Connect Server|Connects to each cache server defined to validate connectivity is working|
|Region Check|Performs a keySetOnServer operation on a subset of defined regions on each server|
|GC Time|Validates the GC time for each defined cache server is under the defined threshold|
|Used Heap|Validates the used heap space for the cluster is under the defined threshold|
|Gateway Sender|If gateway sender defined, validate the gateway sender is connected and queue size threshold is under defined limit|
|Gateway Receiver|If gateway receiver defined, validate the gateway receiver is running and connected to remote gateway|   
 
### Properties ####

**Alert Properties**   

|Name|Description|
|----|-----------|
|alert-url|The URL of the alert service|
|alert-url-parms|Required header parameters for posting an alert to the alert service|
|alert-cluster-fqdn|The name assigned to the cluster in the alert service|

**Health Properties**   

|Name|Description|
|----|-----------|
|managers|A comma separated list of all locators in the cluster that act as JMX manager|
|port|The JMX port number assigned to the locators|
|cmdb-url|The URL of the CMDB service|
|health-check-interval|The time interval in minutes the health check waits before performing the health check again|

**Log4j Properties**   

|Name|Description|
|----|-----------|
|log4j.appender.applicationLog.File|The health check application log file name and location|

### CMDB Health ###

The CMDB service provides the CMDB details for a cluster name and the information is requested using the cluster name/id.

**Example CMDB JSON Response**

   {
	   "clusterName": "cluster-1",   
	   "locatorCount": 1,   
	   "serverCount": 2,   
	   "maximumHeapUsagePercent": 0.95,   
	   "maximumGCTimeMillis": 1000,   
	   "gateway": "true",   
	   "gatewayMaximumQueueSize": 500,   
	   "locators": [   
		   {   
			   "name": "locator1",   
			   "host": "192.168.1.5",   
			   "port": 10334   
		   }   
       ],   
	   "servers": [   
		   {   
			   "name": "server1",   
			   "host": "192.168.1.5",   
			   "port": 40404   
		   },   
	 	   {   
			   "name": "server2",   
			   "host": "192.168.1.5",   
			   "port": 40405   
		   }   
	   ]   
   }   
	 
