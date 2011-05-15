package com.challengeandresponse.phishtrack;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.db4o.ObjectContainer;
import com.db4o.ObjectSet;

class RunSurvey extends TimerTask {

	private static final String[] USER_AGENTS = {
		"Mozilla/4.0 (compatible; MSIE 5.0; Windows NT)",
		"Mozilla/4.0 (compatible; MSIE 5.22; Mac_PowerPC)",
		"Mozilla/4.0 (compatible; MSIE 6.0; Windows 98)",
		"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)",
		"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)",
		"Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en) AppleWebKit/418.8 (KHTML, like Gecko) NetNewsWire/2.1.1b4",
		"Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.8.0.6) Gecko/20060728 Firefox/1.5.0.6",
		"Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.0rc1) Gecko/20020417",
		"Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.7.5) Gecko/20041107 Firefox/1.0",
		"Mozilla/5.0 (Windows; U; Windows NT 5.0; en-US; rv:1.7.12) Gecko/20050915 Firefox/1.0.7",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.8) Gecko/20050511 Firefox/1.0.4",
		"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.12) Gecko/20060202 CentOS/1.0.7-1.4.3.centos4 Firefox/1.0.7",
		"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8) Gecko/20060310 Firefox/1.5",
		"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.4) Gecko/20060508 Firefox/1.5.0.4",
		"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.6) Gecko/20060728 Firefox/1.5.0.6"
	};

	private static final Pattern 	titlePattern = Pattern.compile("<title>(.*?)<\\/title>",Pattern.CASE_INSENSITIVE);
	
	private ObjectContainer trackedSites;
	private PhishTrackConfig ptc;
	
	private int cumulativeUptimeSec;
	// random generator for selecting user-agent strings from the array USER_AGENTS
	private Random rand;
	
	
	public RunSurvey(ObjectContainer trackedSites, PhishTrackConfig ptc) {
		// constructor for this class
		this.trackedSites = trackedSites;
		this.ptc = ptc;
		rand = new Random();
	}

	public void run() {
		PhishTrack.addEvent("running");
		System.out.println("trackedSites: "+trackedSites);
		ObjectSet <Tracked> siteList = trackedSites.get(Tracked.class);
		Iterator <Tracked> i = siteList.iterator();
		PhishTrack.addEvent("trackedSites size is "+siteList.size());
		cumulativeUptimeSec = 0;
		while (i.hasNext()) {
			Tracked t = i.next();
			System.out.println("checking site with label:"+t.label+" and url:"+t.url);
			
			// only process items that are live
			if (! t.running()) {
				PhishTrack.addEvent("Site isn't live. Skipping: "+t.url);
				continue;
			}
			
			// skip, if we can't get an exclusive lock on the record
			if (! trackedSites.ext().setSemaphore(t.uniqueID, 0)) {
				PhishTrack.addEvent("Can't get exclusive lock. Skipping: "+t.url);
				continue;
			}

			// tally for the median and mean
			cumulativeUptimeSec += t.getDurationSec();
			
			Ping p = new Ping();
			String pageContent = "";
			BufferedReader in = null;
			try {
				String userAgent = USER_AGENTS[rand.nextInt(USER_AGENTS.length)];
				PhishTrack.addEvent("Connecting to "+t.url+" with User-Agent: "+userAgent);
				HttpURLConnection urlc = openURLConnection(t.url,userAgent);
				p.httpResult = urlc.getResponseCode();
				PhishTrack.addEvent(t.url+" "+p.httpResult);

				if (p.httpResult == HttpURLConnection.HTTP_OK) {
					PhishTrack.addEvent("Connection OK. Reading content.");
					in = new BufferedReader(new InputStreamReader(urlc.getInputStream()));
					String inputLine;
					StringBuffer wholePage = new StringBuffer();
					while ((inputLine = in.readLine()) != null)
						wholePage.append(inputLine);
					in.close();
					urlc = null;
					pageContent = wholePage.toString();
					// extract the title
					Matcher m = titlePattern.matcher(pageContent);
					if (m.find())
						p.title = m.group(1);
					else
						p.title="title not found";
				}
				// add this ping to t's ping set and analyze it (Tracked does the work)
				PhishTrack.addEvent("Recording ping");
				t.addPing(p,t.url,pageContent,userAgent,ptc.connectTimeoutMsec,ptc.readTimeoutMsec);
			}
			catch (SocketTimeoutException ste) {
				PhishTrack.addEvent("Socket timeout:"+ste.getMessage());
				// save this ping record, it's a countable stop-signal event too
				p.httpResult = -1; // give it an out of bounds code... so it's not counted as a successful fetch
				p.title = "Socket timeout:"+ste.getMessage();
				t.addPing(p,null,pageContent,null,0,0);
			}
			catch (IOException ioe) {
				PhishTrack.addEvent("IO Exception:"+ioe.getMessage());
				// save this ping record, it's a countable stop-signal event too
				p.httpResult = -1; // give it an out of bounds code... so it's not counted as a successful fetch
				p.title = "IO Exception:"+ioe.getMessage();
				t.addPing(p,null,pageContent,null,0,0);
			}
			// save the revised 't'
			trackedSites.set(t);
		}
	}

	

	private HttpURLConnection openURLConnection(String _url, String userAgent)
	throws IOException, SocketTimeoutException {
		return openURLConnection(new URL(_url),userAgent);
	}
	
	
	private HttpURLConnection openURLConnection(URL _url, String userAgent)
	throws IOException, SocketTimeoutException {
		HttpURLConnection urlc = (HttpURLConnection) _url.openConnection();
		urlc.setRequestProperty("User-Agent",userAgent);
		urlc.setInstanceFollowRedirects(true);
		urlc.setUseCaches(false);
		urlc.setConnectTimeout(ptc.connectTimeoutMsec);
		urlc.setReadTimeout(ptc.readTimeoutMsec);
		urlc.connect();
		return urlc;
	}

	
	
	
} 
