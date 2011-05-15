package com.challengeandresponse.phishtrack;

/**
 * key config params for the PhishTrack server are in this class so they can be
 * passed to the PhishMonitor servlet
 * 
 * @author jim
 *
 */
public class PhishTrackConfig {

	int maxConsecStopSignals;			// stop tracking a site after N consecutive stop signals
	int showPingCount; 					// show last N pings
	String trackerDBFile;				// file to serialize Trackers to
	String archiveDBFile;				// file to serialize archived Trackers to
	int	dbMessageLevel;
	long checkIntervalMsec;				// check sites every N msec
	int waitForLockMsec;				// max msec to wait for a record lock on automated operations, fail on timeout
	
	String smtpServer;					// server to use for sending mail
	String mailFrom;					// when server sends mail, who is it from?
	String mailTo;						// where to server notifications go?

	int connectTimeoutMsec;
	int readTimeoutMsec;
	int showServerEvents;
	
	
	public PhishTrackConfig() {
		maxConsecStopSignals = 4;						// stop tracking a site after 3 consecutive stop signals
		showPingCount = 5;	// show terminal pings, plus last one before disconnect
		trackerDBFile = "/usr/local/unomigear/phishtrack/trackers";	// file to serialize Trackers to
		archiveDBFile = "/usr/local/unomigear/phishtrack/trackers-archived";	// file to serialize the Archive to
		dbMessageLevel = 1;
		checkIntervalMsec = (long) (1000 * 60 * 7);			// check sites every 7 minutes
//		checkIntervalMsec = (long) (1000 * 60 * 1);			// check sites every 7 minutes
		waitForLockMsec = 2000;
		
		smtpServer = "smtp.agentzero.net";
		mailFrom = "phishes@cr-labs.com";
		mailTo = "phishes@cr-labs.com";

		connectTimeoutMsec = 20000;
		readTimeoutMsec = 60000;
		showServerEvents = 25; // how many to show
	}
}
