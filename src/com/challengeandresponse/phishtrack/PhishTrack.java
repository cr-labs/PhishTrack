package com.challengeandresponse.phishtrack;

import java.io.IOException;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.servlet.*;
import javax.servlet.http.*;

import com.db4o.*;
import com.db4o.config.Configuration;


/**
 * PhishTrack is a servlet that tracks phishing websites to measure the take-down time
 * and breadth of the exploit, as well as utilization of legitimate servers in support
 * of the phishing attack.
 * 
 * @author jim
 *
 */
public class PhishTrack extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	public static final String PRODUCT_SHORT = "PhishTrack";
	public static final String PRODUCT = "Challenge/Response PhishTrack Server BETA";
	public static final String VERSION = "2.0";
	public static final String VERSION_FULL = PRODUCT+" "+VERSION;
	public static final String COPYRIGHT = "Copyright (c) 2006-2007 Challenge/Response LLC, Cambridge, MA";
	
	static final String	ACTION_LABEL = "action";
	private static final String ACTION_ADDSITE = "addsite";
	private static final String	ACTION_ARCHIVESITE = "archivesite";
	private static final String	ACTION_UNARCHIVESITE = "unarchivesite";
	private static final String	ACTION_REMOVESITE = "removesite";
	private static final String	ACTION_REACTIVATESITE = "reactivatesite";
	private static final String	ACTION_CLEARCONTENTPROFILE = "clearcontentprofile";
	static final String ACTION_VIEW_ARCHIVE = "viewarchive";
	static final String ACTION_SUBMIT_PHISH = "submit";
	
	
	// fields on the forms
	private static final String FIELD_LABEL = "label";
	static final String FIELD_URL = "url";
	static final String FIELD_STARTTIME = "starttime";
	private static final String	FIELD_UNIQUEID = "uniqueid";
	static final String FIELD_EMAIL_CONTENTS = "emailcontents";
	
	// SHARED OBJECTS
	public static final String TRACKED_SITES = 	"PhishTrack:trackedsites";
	public static final String ARCHIVED_SITES = "PhishTrack:archivedsites";
	public static final String SERVER_EVENTS = 	"PhishTrack:serverevents";
	public static final String PHISHTRACK_CONFIG = "PhishTrack:config";
	
	public static final String DATE_FORMAT 	= "dd MMM yyyy HH:mm z"; // format for all dates in/out
	public static final String PCT_FORMAT 	= "##0.0%";
	public static final String BYTE_FORMAT 	= "#,###,##0"; 
	
	
	// private members
	private static Vector <String> events;		// server event log, one per 
	static {
		events = new Vector <String> ();
	}
		
	private PhishTrackConfig ptc;		// server configuration settings
	
	private java.util.Timer siteCheckTimer = null; 
	private SecureRandom prng;

	// date formatter/parser
	private SimpleDateFormat sdf = new SimpleDateFormat(DATE_FORMAT);
	
	// the ObjectContainers
	ObjectContainer trackedSites = null;
	ObjectContainer archivedSites = null;
	
	
	
	public PhishTrack() {
		super();
	}

	// Load everything that's held for the life of the servlet instance
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		System.out.println("Initializing "+VERSION_FULL);
		
		// Disable DNS caching
		java.security.Security.setProperty("networkaddress.cache.ttl" , "0");

		// ephemeral record of server events
		events = new Vector <String> ();

		// set the configuration params
		ptc = new PhishTrackConfig();
		
		// open databases
		Db4o.configure().exceptionsOnNotStorable (true); // for debugging
		Configuration conf = Db4o.newConfiguration();
		conf.allowVersionUpdates(true);
		conf.messageLevel(ptc.dbMessageLevel);
		conf.objectClass("com.challengeandresponse.phishtrack.Tracked").cascadeOnActivate(true);
		conf.objectClass("com.challengeandresponse.phishtrack.Tracked").cascadeOnUpdate(true);
		conf.objectClass("com.challengeandresponse.phishtrack.Tracked").cascadeOnDelete(true);
		conf.objectClass("com.challengeandresponse.phishtrack.ContentProfile").cascadeOnActivate(true);
		conf.objectClass("com.challengeandresponse.phishtrack.ContentProfile").cascadeOnUpdate(true);
		conf.objectClass("com.challengeandresponse.phishtrack.ContentProfile").cascadeOnDelete(true);
		conf.objectClass("com.challengeandresponse.phishtrack.ContentFeatures").cascadeOnActivate(true);
		conf.objectClass("com.challengeandresponse.phishtrack.ContentFeatures").cascadeOnUpdate(true);
		conf.objectClass("com.challengeandresponse.phishtrack.ContentFeatures").cascadeOnDelete(true);
		conf.activationDepth(5);
		conf.updateDepth(5);
		try {
			addEvent("Opening tracker database from file "+ptc.trackerDBFile);
			trackedSites = Db4o.openFile(conf,ptc.trackerDBFile);
			addEvent("Opening archive database from file "+ptc.archiveDBFile);
			archivedSites = Db4o.openFile(conf,ptc.archiveDBFile);
		}
		catch (com.db4o.ext.Db4oException db4oe) {
			throw new ServletException("Exception opening trackedSites or archivedSites DB:"+db4oe.getMessage());
		}
	
		siteCheckTimer = new java.util.Timer(false); 
		siteCheckTimer.schedule(new RunSurvey(trackedSites,ptc), 0, ptc.checkIntervalMsec);
		
		try {
			prng = SecureRandom.getInstance("SHA1PRNG");
		}
		catch (NoSuchAlgorithmException nsae) {
			throw new ServletException("Exception initializing SecureRandom: "+nsae.getMessage());
		}
		
		// publish the shared objects for PhishMonitor
		getServletContext().setAttribute(TRACKED_SITES,trackedSites);
		getServletContext().setAttribute(ARCHIVED_SITES,archivedSites);
		getServletContext().setAttribute(SERVER_EVENTS,events);
		getServletContext().setAttribute(PHISHTRACK_CONFIG,ptc);
	}
	
	
	public void destroy() {
		siteCheckTimer.cancel();
		trackedSites.close();
		archivedSites.close();
	}

	
	
	/**
	 * Handles HTTP <code>GET</code>, the only method supported here for now
	 * @param _request servlet request
	 * @param _response servlet response
	 */    
	public void doGet(HttpServletRequest _request,HttpServletResponse _response)
	throws ServletException, IOException {
		// configure the output stream so error messages can go back
		_response.setContentType("text/html");
		ServletOutputStream outStream = _response.getOutputStream();
		displayHeader(outStream);
		
		if (ACTION_VIEW_ARCHIVE.equals(_request.getParameter(ACTION_LABEL)))
			showTrackedSites(archivedSites,outStream,true);
		else {
			showTrackedSites(trackedSites,outStream,false);
			showAddForm(outStream);
			showServerLog(ptc.showServerEvents,outStream);
		}
		outStream.print("</body></html>");
		outStream.close();
	}

	
	
	public void doPost(HttpServletRequest _request,HttpServletResponse _response)
	throws ServletException, IOException {
		_response.setContentType("text/html");
		ServletOutputStream outStream = _response.getOutputStream();
		displayHeader(outStream);
		
		// interpret the form input and act accordingly
		String action = _request.getParameter(ACTION_LABEL);
		
		if (ACTION_ADDSITE.equals(action)) {
			try {
				Tracked t = new Tracked(ptc.maxConsecStopSignals,prng);
				t.label = _request.getParameter(FIELD_LABEL);
				t.url = new URL(_request.getParameter(FIELD_URL)).toString();// test for valid; exception will be thrown if it's not a good url else set with perfectly formed version from URL class
				t.startTime = sdf.parse(_request.getParameter(FIELD_STARTTIME)).getTime();
				t.start();
				trackedSites.set(t);
				trackedSites.commit();
			}
			catch (Exception e) {
				outStream.print("<font color='#FF3333'><b>Could not add item: "+e.getMessage()+"</b></font>");
			}
		}
		// Live sites can be archived if we can get an exclusive lock
		else if (ACTION_ARCHIVESITE.equals(action)) {
			String uniqueID = _request.getParameter(FIELD_UNIQUEID);
			Tracked t = null;
			if (uniqueID != null) {
				try {
					t = getOneTrackedByUniqueid(trackedSites,uniqueID);
					if ( (t != null) && setSemaphore(trackedSites,t) ) {
						t.stop();
						archivedSites.set(t);
						archivedSites.commit();
						trackedSites.delete(t);
						trackedSites.commit();
					}
					else {
						throw new Exception("Could not get exclusive lock on:"+t.uniqueID);
					}
				}
				catch (Exception e) {
					outStream.print("<font color='#FF3333'><b>Could not archive site: "+e.getMessage()+"</b></font>");
				}
				finally {
					releaseSemaphore(trackedSites,t);
				}
			}
		}
		// Archived sites can be made live again if we can get an exclusive lock
		else if (ACTION_UNARCHIVESITE.equals(action)) {
			String uniqueID = _request.getParameter(FIELD_UNIQUEID);
			Tracked t = null;
			if (uniqueID != null) {
				try {
					t = getOneTrackedByUniqueid(archivedSites,uniqueID);
					if ( (t != null) && setSemaphore(archivedSites,t) ) {
						t.start();
						trackedSites.set(t);
						trackedSites.commit();
						archivedSites.delete(t);
						archivedSites.commit();
					}
					else {
						throw new Exception("Could not get exclusive lock on:"+t.uniqueID);
					}
				}
				catch (Exception e) {
					outStream.print("<font color='#FF3333'><b>Could not unarchive site: "+e.getMessage()+"</b></font>");
				}
				finally {
					releaseSemaphore(archivedSites,t);
				}
			}
		}

		// Archived sites can be removed
		else if (ACTION_REMOVESITE.equals(action)) {
			String uniqueID = _request.getParameter(FIELD_UNIQUEID);
			Tracked t = null;
			if (uniqueID != null) {
				try {
					t = getOneTrackedByUniqueid(archivedSites,uniqueID);
					if ( (t != null) && setSemaphore(archivedSites,t))  {
						archivedSites.delete(t);
						archivedSites.commit();
					}
					else {
						outStream.print("<font color='#FF3333'><b>Could not delete archived site:"+t.uniqueID+"</b></font>");
					}
				}
				finally {
					releaseSemaphore(archivedSites,t);
				}
			}
		}
		// Halted sites can be restarted
		else if (ACTION_REACTIVATESITE.equals(action)) {
			String uniqueID = _request.getParameter(FIELD_UNIQUEID);
			Tracked t = null;
			if (uniqueID != null) {
				try {
					t = getOneTrackedByUniqueid(trackedSites,uniqueID);
					if ( (t != null) && setSemaphore(trackedSites,t) && (! t.running()) ) {
						t.start();
						trackedSites.set(t);
						trackedSites.commit();
					}
					else {
						outStream.print("<font color='#FF3333'><b>Could not delete archived site:"+t.uniqueID+"</b></font>");
					}
				}
				finally {
					releaseSemaphore(trackedSites,t);
				}
			}
		}
		// Content profile can be reset so it's reloaded on the next pass
		else if (ACTION_CLEARCONTENTPROFILE.equals(action)) {
			String uniqueID = _request.getParameter(FIELD_UNIQUEID);
			Tracked t = null;
			if (uniqueID != null) {
				try {
					t = getOneTrackedByUniqueid(trackedSites,uniqueID);
					if ( (t != null) && setSemaphore(trackedSites,t)) {
						t.clearContentProfile();
						trackedSites.set(t);
						trackedSites.commit();
					}
					else {
						outStream.print("<font color='#FF3333'><b>Could not clear content profile:"+t.uniqueID+"</b></font>");
					}
				}
				finally {
					releaseSemaphore(trackedSites,t);
				}
			}
		}
		
		
		
		
		if (ACTION_VIEW_ARCHIVE.equals(_request.getParameter(ACTION_LABEL)))
			showTrackedSites(archivedSites,outStream,true);
		else {
			showTrackedSites(trackedSites,outStream,false);
			showAddForm(outStream);
			showServerLog(ptc.showServerEvents,outStream);
		}
		outStream.print("</body></html>");
		outStream.close();
	}


	/**
	 * Display the page-top for either a get or post
	 * @param outStream
	 * @throws IOException
	 */
	public void displayHeader(ServletOutputStream outStream)
	throws IOException {
		outStream.print("<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN' 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>");
		outStream.print("<style type='text/css' media='all'>@import url('http://challengeandresponse.com/default.css');</style>");
		outStream.print("<html><head><title>"+PRODUCT+"</title>");
		outStream.print("</head><body>");
		outStream.print("<strong>"+VERSION_FULL+"</strong><br />");
		outStream.print("Server time: "+sdf.format(new Date())+"<br />");
		outStream.print("Check interval: "+ptc.checkIntervalMsec+" msec. Stop after "+ptc.maxConsecStopSignals+" consecutive stop signals<br />");
		outStream.print("Timeouts: Connect "+ptc.connectTimeoutMsec+" msec; Read "+ptc.readTimeoutMsec+" msec<br />");
		outStream.print("<a href='PhishTrack'>Refresh</a> | <a href='PhishTrack?action=viewarchive'>Archive</a>");
	}

		
	/**
	 * Display the sites that are tracked
	 * @param _request
	 * @param _response
	 * @param _outStream
	 * @throws IOException
	 */
	private void showTrackedSites(ObjectContainer _sites, ServletOutputStream _outStream, boolean viewingArchive) 
	throws IOException {
		StringBuffer content = new StringBuffer();
		content.append(viewingArchive ? "<p><strong>ARCHIVED sites</strong><br />" : "<p><strong>Currently monitored sites</strong><br />");
		content.append("<table>");
		
		ObjectSet <Tracked> siteList = _sites.get(Tracked.class);
		content.append("<tr><td colspan='7'>Tracking "+siteList.size()+" sites (running and/or stopped)</td></tr>");

		Iterator <Tracked> i = siteList.iterator();
		while (i.hasNext()) {
			Tracked t = i.next();
			if (! viewingArchive) 
				content.append("<tr><td><font size='+1'>"+t.label+"</font></td><td colspan='6'><font size='+1'><a href='"+t.url+"' target='_other'><b>"+t.url+"</b></a></font></td></tr>");
			else
				content.append("<tr><td><font size='+1'>"+t.label+"</font></td><td colspan='6'><font size='+1'><b>"+t.url+"</b></font></td></tr>");

			content.append("<tr><td>&nbsp;</td><td>&nbsp;</td><td><b>Received</b></td><td><b>Pings</b></td><td><b>Uptime</b></td><td><b>Stop signals</b></td><td><b>Status</b></td></tr>");
			content.append("<tr><td colspan='2'>&nbsp;</td><td>"+sdf.format(new Date(t.startTime))+"</td><td>"+t.getPingCount()+"</td><td>"+hoursAndMinutes((long) t.getDurationSec()*1000)+"</td><td>"+t.getStopSignalCount()+"</td><td>"+(t.running()?"Running":"Stopped")+"</td>");

			// the management buttons
			content.append("<td>");
			if (! viewingArchive) {
				// the ARCHIVE button
				content.append("<form action='PhishTrack' method='post'>");
				content.append("<input type='hidden' name='"+ACTION_LABEL+"' value='"+ACTION_ARCHIVESITE+"'>");
				content.append("<input type='hidden' name='"+FIELD_UNIQUEID+"' value='"+t.uniqueID+"'>");
				content.append("<input type='submit' value='Archive'>");
				content.append("</form>");
				content.append("<br />");
				// and if the item is stopped, a restart button
				if (! t.running()) {
					content.append("<form action='PhishTrack' method='post'>");
					content.append("<input type='hidden' name='"+ACTION_LABEL+"' value='"+ACTION_REACTIVATESITE+"'>");
					content.append("<input type='hidden' name='"+FIELD_UNIQUEID+"' value='"+t.uniqueID+"'>");
					content.append("<input type='submit' value='Reactivate'>");
					content.append("</form>");
					content.append("<br />");
				}
				// the CLEAR CONTENT PROFILE button
				content.append("<form action='PhishTrack' method='post'>");
				content.append("<input type='hidden' name='"+ACTION_LABEL+"' value='"+ACTION_CLEARCONTENTPROFILE+"'>");
				content.append("<input type='hidden' name='"+FIELD_UNIQUEID+"' value='"+t.uniqueID+"'>");
				content.append("<input type='submit' value='Clear content profile'>");
				content.append("</form>");
				content.append("<br />");
			}
			else {
				// the REMOVE button
				content.append("<form action='PhishTrack' method='post'>");
				content.append("<input type='hidden' name='"+ACTION_LABEL+"' value='"+ACTION_REMOVESITE+"'>");
				content.append("<input type='hidden' name='"+FIELD_UNIQUEID+"' value='"+t.uniqueID+"'>");
				content.append("<input type='submit' value='Remove'>");
				content.append("</form>");
				content.append("<br />");
				// the MOVE BACK TO ACTIVE LIST button ("unarchive")
				content.append("<form action='PhishTrack' method='post'>");
				content.append("<input type='hidden' name='"+ACTION_LABEL+"' value='"+ACTION_UNARCHIVESITE+"'>");
				content.append("<input type='hidden' name='"+FIELD_UNIQUEID+"' value='"+t.uniqueID+"'>");
				content.append("<input type='submit' value='Un-archive & make active'>");
				content.append("</form>");
				content.append("<br />");
			}
			content.append("</td>");
			content.append("</tr>");
			
			// Show the last few pings for this one 
			content.append("<tr><td>&nbsp;&nbsp;&nbsp;</td><td colspan='7'>");
			content.append("<b>Pings</b><br />");
			Iterator <Ping> iPing = t.getPingIterator(ptc.showPingCount);
			while (iPing.hasNext()) {
				Ping p = iPing.next();
				content.append (p.httpResult+" "+sdf.format(new Date(p.timestamp))+" "+p.title+"<br />");
			}
			content.append("</td></tr>");

			// Show its ContentProfile, if there is one
			if (t.hasContentProfile()) {
				content.append("<tr><td>&nbsp;&nbsp;&nbsp;</td><td colspan='7'>");
				content.append("<b>Content profile</b><br />");
				ContentProfile cp = t.getContentProfile();
				try {
					Object[] cts = cp.getHosts();
					int allBytes = cp.getAllBytes();
					int allLinks = cp.getAllLinks();
					for (int i2 = 0; i2 < cts.length; i2++) {
						int bytes = cp.getBytes((String) cts[i2]);
						int links = cp.getLinks((String) cts[i2]);
						content.append("Host: "+(String) cts[i2]);
						content.append(" Bytes: "+bytes+" ("+(int) ((double)bytes/(double)allBytes*100d)+"%)");
						content.append(" Links: "+links+" ("+(int) ((double)links/(double)allLinks*100d)+"%)");
						content.append("<br />");
					}
				}
				catch (InvalidProfileException ipe) {
				}
				content.append("</td></tr>");
			}

			// if this one is no longer running, summarize it for the record books
			if (! t.running()) {
				content.append("<tr><td>&nbsp;&nbsp;&nbsp;</td><td colspan='7'><font color='#FF3333'><b>Site down. Summary:</b></font><br />");
				Ping p = t.getLastPing();
				if (p != null)
					content.append ("Last ping result: "+p.httpResult+" "+sdf.format(new Date(p.timestamp))+" "+p.title+"<br />");
				content.append("Online not later than: "+sdf.format(new Date(t.startTime))+"<br />");
				content.append("Confirmed offline not later than: "+sdf.format(new Date(t.getStopSignalTime()))+"<br />");
				content.append("Phish uptime not less than: "+hoursAndMinutes(t.getStopSignalTime() - t.startTime)+"<br />");
				content.append("</td></tr>");
			}
			content.append("<tr><td colspan='8'><hr></td></tr>");
		}
		
		
		content.append("</table></p>");
		_outStream.print(content.toString());
	}
	
	
	private void showAddForm(ServletOutputStream _outStream) 
	throws IOException {
		StringBuffer content = new StringBuffer("<p><strong>Add a site</strong><br />");
		content.append("<form action='PhishTrack' method='post'>");
		content.append("<input type='hidden' name='"+ACTION_LABEL+"' value='"+ACTION_ADDSITE+"'>");
		content.append("Descriptive label: <input type='text' name='"+FIELD_LABEL+"'><br />");
		content.append("URL: <input type='text' name='"+FIELD_URL+"'><br />");
		content.append("Date/time message received: <input type='text' name='"+FIELD_STARTTIME+"'><font size='-1'>(dd mmm yyyy hh:mm z, example: 5 Aug 2006 18:44 EDT) use 24-hour time</font><br />");
		content.append("<input type='submit' value='"+ACTION_ADDSITE+"'><br />");
		content.append("</form></p>");
		_outStream.print(content.toString());
		
	}


	
	
	
	private void showServerLog(int _eventCount, ServletOutputStream _outStream)
	throws IOException {
		_outStream.print("<p><strong>Server log: last "+_eventCount+" events</strong><br />");
		List <String> v = events.subList(Math.max(events.size()-_eventCount,0),events.size());
		Iterator <String> i = v.iterator();
		while (i.hasNext()) {
			String s = i.next();
			_outStream.print(s+"<br />");
		}
		_outStream.print("</p>");
	} 
	

	
	
	private String hoursAndMinutes(long milliseconds) {
		int uptime = (int) (milliseconds/1000);
		int days = (uptime / 60 / 60 / 24);
		uptime -= days * 60 * 60 *24;
		int hours = (uptime / 60 / 60);
		uptime -= hours * 60 * 60;
		int minutes = uptime /60;
		
		StringBuffer s = new StringBuffer();
		if (days > 0) {
			s.append(days);
			s.append(" day");
			s.append(days > 1 ? "s ":" ");
		}
		if (hours > 0) {
			s.append(hours);
			s.append(" hour");
			s.append(hours > 1 ? "s ":" ");
		}
		s.append(minutes);
		s.append(" minute");
		s.append(minutes != 1 ? "s ":"");
		
		return s.toString();
	}
	
	
	private boolean setSemaphore(ObjectContainer oc,Tracked t) {
		if (t == null)
			return false;
		return oc.ext().setSemaphore(t.uniqueID, ptc.waitForLockMsec);
	}
	
	private void releaseSemaphore(ObjectContainer oc, Tracked t) {
		if (t == null)
			return;
		oc.ext().releaseSemaphore(t.uniqueID);
	}
	
	/**
	 * Get the first Tracked object matching the passed in uniqueid
	 * @param uniqueID the uniqueid of the record to fetch
	 * @return the first matching Tracked record, or null if there was no match
	 */
	private Tracked getOneTrackedByUniqueid(ObjectContainer oc, String uniqueID) {
		Tracked t = new Tracked(0,null);
		t.uniqueID = uniqueID;
		ObjectSet <Tracked> os = oc.get(t);
		if (os.size() > 0)
			return os.next();
		else
			return null;
	}

	
	public static void addEvent(String text) {
		String s = (new Date()).toString();
		events.add(s+" "+text);
	}

}
