package com.challengeandresponse.phishtrack;

import java.net.HttpURLConnection;
import java.security.SecureRandom;
import java.util.*;

public class Tracked {

	public static final int STATUS_RUNNING = 1;
	public static final int STATUS_STOPPED = 2;
	
	public String uniqueID;				// internal ID
	
	public String label;
	public String url;
	public long startTime;
	
	private int status;						// RUNNING or STOPPED
	private long stopTime;					// when this site was "known down"
	private String initialTitle; 			// grabbed the first time
	private String	initialPageContent; 	// grabbed the first time
	private Vector <Ping> pings;	// Ping records from each time this url was surveyed
	private int stopSignals;	// count the number of consecutive errors so we can stop if there are too many
	private int maxStopSignals; // stop tracking when this many errors occur consecutively
	private ContentProfile contentProfile;	// is null until a profile is loaded
	
	private transient long	firstStopSignalTime; // the time of the FIRST stop signal, to be used as the stop-time if this Tracked actually terminates
	
	
	/**
	 * Call with prng = null to get an empty object for QBE use
	 * @param _maxStopSignals
	 * @param prng
	 */
	public Tracked(int _maxStopSignals, SecureRandom prng) {
		if (prng != null) {
			uniqueID = System.currentTimeMillis()+""+prng.nextInt();
			
			label = "";
			url = "";
			startTime = 0;
			
			status = STATUS_RUNNING;
			stopTime = 0;
			initialTitle = "";
			initialPageContent = "";
			pings = new Vector <Ping> ();
			stopSignals = 0;
			maxStopSignals = _maxStopSignals;
			contentProfile = null;

			firstStopSignalTime = -1;
		}
	}
	
	/**
	 * Add the ping to the collection, and also track the status of the contents of that ping... 
	 * @param p The Ping to record
	 * @param pageContent the page content so that if this is the first pass, the page can be cached
	 * @param userAgent the userAgent that was used to record this Ping... will be reused for ContentProfile fetching, so it is consistent for the  load of the entire page
	 * @param ptc the currentPhishTrackConfig w/ timeout settings in it, for subsequent fetches
	 */
	public void addPing(Ping p, String _basePageURL, String pageContent, String userAgent, int connectTimeoutMsec, int readTimeoutMsec) {
		// if there's no initial title or content yet (first pass)... 
		// ... save those things, provided we actually retrieved a page
		if (p.httpResult == HttpURLConnection.HTTP_OK) {
			// if the initial title has not been set, set it
			if (initialTitle.length() < 1)
					initialTitle = p.title;
			// if the initial content has not been set, set it
			if (initialPageContent.length() < 1)
				initialPageContent = pageContent;
			// if there's initialPageContent, but it hasn't been profile yet, give it one
			if ((initialPageContent.length() > 1) && (! hasContentProfile())) {
				contentProfile = new ContentProfile(pageContent);
			}
			// if the contentProfile isn't current, try to update it
			PhishTrack.addEvent("Checking for content profile build-out");
			PhishTrack.addEvent("hasContentProfile() "+hasContentProfile());
			PhishTrack.addEvent("contentProfile.valid() "+contentProfile.valid());
			PhishTrack.addEvent("userAgent "+userAgent);
			if (hasContentProfile() && (! contentProfile.valid()) && (userAgent != null) )
				contentProfile.buildProfile(userAgent,_basePageURL, connectTimeoutMsec,readTimeoutMsec);
			// and test for a change to the title as well, after a successful fetch
			if (! p.title.equals(initialTitle))
				stopSignals += 1;
			else // all good, so clear the stop-signal counter (stop signals are consecutive)
				stopSignals = 0;
		}
		else { // didn't get a page, that's a stop signal
			stopSignals += 1;
		}
		if (stopSignals == 1)
			firstStopSignalTime = System.currentTimeMillis();

		pings.add(p);

		// stop polling this site and mark it 'down' if the signal count is exceeded
		if (stopSignals >= maxStopSignals) {
			status = STATUS_STOPPED;
			stopTime = firstStopSignalTime;
		}
	}
	
	public int getPingCount() {
		return pings.size();
	}
	
	public Iterator <Ping> getPingIterator() {
		return pings.iterator();
	}
	
	/**
	 * Return the last howMany pings
	 * @param howMany
	 * @return
	 */
	public Iterator <Ping> getPingIterator(int howMany) {
		List <Ping> v = pings.subList(Math.max(pings.size()-howMany,0),pings.size());
		return v.iterator();
	}
	
	public Ping getLastPing() {
		if (! pings.isEmpty())
			return pings.lastElement();
		else 
			return null;
	}
	
	
	public int getStopSignalCount() {
		return stopSignals;
	}
	
	public long getStopSignalTime() {
		return stopTime;
	}
	
	public long getFirstStopSignalTime() {
		return firstStopSignalTime;
	}
	
	public String getInitialTitle() {
		return initialTitle;
	}
	
	public String getInitialPageContent() {
		return initialPageContent;
	}
	
	public int getMaxStopSignals() {
		return maxStopSignals;
	}

	public void stop() {
		status = STATUS_STOPPED;
		stopTime = System.currentTimeMillis();
	}
	
	public void start() {
		status = STATUS_RUNNING;
		stopTime = 0;
		stopSignals = 0;
	}
	
	public boolean running() {
		return (status == STATUS_RUNNING);
	}
	
	public boolean hasContentProfile() {
		return (contentProfile != null);
	}
	
	public void clearContentProfile() {
		contentProfile = null;
	}
	
	public ContentProfile getContentProfile() {
		return contentProfile;
	}
	
	public String getContentProfileString() {
		return contentProfile.toString();
	}
	
	public String getUniqueID() {
		return uniqueID;
	}
	
	/**
	 * Return the number of seconds that this has been alive... if it's stopped, then that is
	 * the time between startup and stopTime. If still running, it is hte 
	 * time between startup and Now.
	 * @return
	 */
	public int getDurationSec() {
		if (stopTime != 0)
			return (int) ((long) (stopTime-startTime)/1000L);
		else
			return (int) ((long) (System.currentTimeMillis()-startTime)/1000L);
	}
	

}
