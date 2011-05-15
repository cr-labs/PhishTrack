package com.challengeandresponse.phishtrack;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.Socket;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.servlet.*;
import javax.servlet.http.*;

import com.db4o.ObjectContainer;
import com.db4o.ObjectSet;


/**
 * PhishMonitor reads the tracking data of the PhishTrack server, and publishes
 * it in a pleasant and easy to read manner.
 * 
 * @author jim
 *
 */
public class PhishMonitor extends HttpServlet {
	private static final long serialVersionUID = 1L;
	
	public static final String PRODUCT_SHORT = "PhishMonitor";
	public static final String PRODUCT = "Challenge/Response PhishMonitor BETA";
	public static final String VERSION = "2.02";
	public static final String VERSION_FULL = PRODUCT+" "+VERSION;
	public static final String COPYRIGHT = "Copyright (c) 2006-2007 Challenge/Response LLC, Cambridge, MA";
	
	public static String FOOTER;
	
	static {
		FOOTER = "<p class='smallerLighter'>PhishMonitor is provided as a free public service by <a href='http://challengeandresponse.com/' target='cr'>Challenge/Response LLC</a>.<br />";
		FOOTER += "Results are copyright (c) 2006-2007 Challenge/Response LLC, Cambridge, MA<br />";
		FOOTER += "PhishMonitor is experimental technology, provided with no warranty, express or implied, regarding its fitness for any purpose.<br />";
		FOOTER += "These reports should not be considered accurate for evidentiary or other official uses.</p>";
		FOOTER += "</body></html>";
	}
	
	
	private static final String FONT_GREEN = 	"<font color='#009933'>";
	private static final String FONT_YELLOW = 	"<font color='#CCCC00'>";
	private static final String FONT_RED =		"<font color='#990000'>";
	
	private static final int 	MODE_CURRENT	= 1;
	private static final int	MODE_ARCHIVE	= 2;
	private static final int	MODE_SUBMIT		= 3;
	
	private boolean sharedObjectsBound;
	
	
	// date formatter/parser
	private SimpleDateFormat sdf = new SimpleDateFormat(PhishTrack.DATE_FORMAT);
	
	// data structures published for PhishMonitor by the PhishTrack server
	private ObjectContainer trackedSites;
	private ObjectContainer archivedSites;
	private PhishTrackConfig ptc;
	
	
	public PhishMonitor() {
		super();
		sharedObjectsBound = false;
	}
	
	
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		System.out.println("Initializing "+VERSION_FULL);
		bindSharedObjects();
	}
	
	public void destroy() {
	}
	
	private void bindSharedObjects() {
		trackedSites = (ObjectContainer) getServletContext().getAttribute(PhishTrack.TRACKED_SITES);
		archivedSites = (ObjectContainer) getServletContext().getAttribute(PhishTrack.ARCHIVED_SITES);
		ptc = (PhishTrackConfig) getServletContext().getAttribute(PhishTrack.PHISHTRACK_CONFIG);
		sharedObjectsBound =  ( (ptc != null) && (archivedSites != null) && (trackedSites != null));
	}
	
	
	
	
	/**
	 * Handles HTTP <code>GET</code> which is most pages
	 * @param _request servlet request
	 * @param _response servlet response
	 */    
	public void doGet(HttpServletRequest _request,HttpServletResponse _response)
	throws ServletException, IOException {
		int mode = MODE_CURRENT; // what are we doing?
		
		_response.setContentType("text/html");
		ServletOutputStream outStream = _response.getOutputStream();

		// if not connected to a  PhishTrack server, try to re-connect
		if (! sharedObjectsBound) 
			bindSharedObjects();
		// if can't connect, show an error message and return
		if (! sharedObjectsBound) {
			displayHeader(outStream,mode);
			outStream.println("<p>PhishMonitor is not currently available. Can't connect to PhishTrack server.</p>");
			return;
		}

		if (PhishTrack.ACTION_VIEW_ARCHIVE.equals(_request.getParameter(PhishTrack.ACTION_LABEL)))
			mode = MODE_ARCHIVE;
		else if (PhishTrack.ACTION_SUBMIT_PHISH.equals(_request.getParameter(PhishTrack.ACTION_LABEL)))
			mode = MODE_SUBMIT;

		// no matter what doing next, we show the page header
		displayHeader(outStream,mode);

		// then the mode-specific content
		if (mode == MODE_ARCHIVE)
			showTrackedSites(archivedSites,outStream,mode);
		else if (mode == MODE_SUBMIT)
			showPhishSubmitter(outStream);
		else // default to SHOW CURRENT
			showTrackedSites(trackedSites,outStream,mode);

		// and always show the footer and close the stream
		displayFooter(outStream);
		outStream.close();
	}
	
	
	/**
	 * Handles HTTP <code>POST</code> which is used here for PhishTrack submissions
	 * @param _request servlet request
	 * @param _response servlet response
	 */    
	public void doPost(HttpServletRequest _request,HttpServletResponse _response)
	throws ServletException, IOException {
		// configure the output stream so error messages can go back
		_response.setContentType("text/html");
		ServletOutputStream outStream = _response.getOutputStream();

		if (PhishTrack.ACTION_SUBMIT_PHISH.equals(_request.getParameter(PhishTrack.ACTION_LABEL))) {
			StringBuffer sb = new StringBuffer();
			sb.append("Sent from host: "+_request.getRemoteHost()+" ["+_request.getRemoteAddr()+"]\n");
			sb.append("URL: "+_request.getParameter(PhishTrack.FIELD_URL)+"\n");
			sb.append("Received:"+_request.getParameter(PhishTrack.FIELD_STARTTIME)+"\n");
			sb.append("Message:\n"+_request.getParameter(PhishTrack.FIELD_EMAIL_CONTENTS)+"\n");
			sendEmail("PhishTrack submission",sb.toString());
			PhishTrack.addEvent(sb.toString());
			displayHeader(outStream,MODE_SUBMIT);
			showPhishThankYou(outStream);
		}
		else {
			_response.sendRedirect("PhishTrack");
		}

		displayFooter(outStream);
		outStream.close();

	}




	
	
	/**
	 * Display the page-top for either a get or post
	 * @param outStream
	 * @throws IOException
	 */
	public void displayHeader(ServletOutputStream outStream, int mode)
	throws IOException {
		StringBuffer sb = new StringBuffer();
		sb.append("<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN' 'http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd'>");
		sb.append("<style type='text/css' media='all'>@import url('http://challengeandresponse.com/default.css');</style>");
		sb.append("<html><head><title>"+PRODUCT+"</title>");
		// auto-refresh the page unless it's a submission form
		if (sharedObjectsBound && (mode != MODE_SUBMIT))
			sb.append("<meta HTTP-EQUIV='Refresh' CONTENT='"+(ptc.checkIntervalMsec/1000)+";URL="+((mode == MODE_ARCHIVE)?"PhishMonitor?action=viewarchive":"PhishMonitor")+"'>");
		sb.append("</head><body>");
		sb.append("<img src='http://challengeandresponse.com/cr-symbolonly.png' align='left'>");
		sb.append("<p><strong>"+VERSION_FULL+"</strong><br />");
		sb.append("Server time: "+sdf.format(new Date())+"</p>");
		
		// the page-selectors at the top of the page
		sb.append("<p>");
		sb.append( (mode != MODE_CURRENT) ? "<a href='PhishMonitor'>CURRENT Sites</a>" : "CURRENT Sites");
		sb.append(" | ");
		sb.append( (mode != MODE_ARCHIVE) ? "<a href='PhishMonitor?action=viewarchive'>ARCHIVED Sites</a>" : "ARCHIVED Sites");
		sb.append(" | ");
		sb.append( (mode != MODE_SUBMIT) ? "<a href='PhishMonitor?action=submit'>SUBMIT a Phish</a>" : "SUBMIT a Phish");

		sb.append(" | ");
		sb.append("<a href='http://digg.com/security/Real_time_phishing_monitor_beta' target='digg'>DIGG this</a>");
		sb.append("</p><br clear='all'>");

		outStream.print(sb.toString());
	}
	
	/**
	 * Display the page-closer
	 */
	public void displayFooter(ServletOutputStream outStream)
	throws IOException {
		outStream.print("<hr>");
		outStream.print(FOOTER);
	}
	
	
	public void showPhishSubmitter(ServletOutputStream outStream)
	throws IOException {
		StringBuffer content = new StringBuffer();
		content.append("<p><span class='importantText'><strong>Submit a Phish</strong></span>");
		content.append("<br /><hr>");
		content.append("<form method='post' action='PhishMonitor?"+PhishTrack.ACTION_LABEL+"="+PhishTrack.ACTION_SUBMIT_PHISH+"'>");
		content.append("<input type='hidden' name='"+PhishTrack.ACTION_LABEL+"' value='"+PhishTrack.ACTION_SUBMIT_PHISH+"'>");
		content.append("Please provide all the information for section 1 or section 2 (or both if you wish):<br />");
		content.append("&nbsp;<br /><div class='inverted'>&nbsp;Section 1:&nbsp;</div><br />");
		content.append("URL of the fake site: <input size='100' maxlength='300' type='text' name='"+PhishTrack.FIELD_URL+"'><br />");
		content.append("Date/time message received: <input type='text' name='"+PhishTrack.FIELD_STARTTIME+"'><font size='-1'>(we need: day, month, year, hours, minutes and time zone. Example: 5 Aug 2006 18:44 EDT)</font><br />");
		content.append("&nbsp;<br /><div class='inverted'>&nbsp;<i> AND / OR...</i> Section 2:&nbsp;</div><br />");
		content.append("Paste the e-mail here with <i>full headers</i> (the headers are very important):<br />");
		content.append("<textarea name='"+PhishTrack.FIELD_EMAIL_CONTENTS+"' rows='10' cols='90'>");
		content.append("</textarea><br />");
		content.append("<input type='submit' value='Submit this Phish'> | <a href='PhishMonitor'><b>Cancel - go back to PhishMonitor</b></a><br />");
		content.append("</form></p>");
		outStream.print(content.toString());
	}
	
	public void showPhishThankYou(ServletOutputStream outStream)
	throws IOException {
		StringBuffer content = new StringBuffer();
		content.append("<p><span class='importantText'><strong>Thank you!</strong></span>");
		content.append("<br /><hr>");
		content.append("The phish has been submitted. We'll review it and add it to the database.<br />&nbsp;<br />");
		content.append("<a href='PhishMonitor'>Return to the PhishMonitor</a>");
		content.append("</p>");
		outStream.print(content.toString());
	}
	
	
	
	/**
	 * Display the sites that are tracked
	 * @param _outStream
	 * @throws IOException
	 */
	private void showTrackedSites(ObjectContainer oc,ServletOutputStream _outStream, int _mode) 
	throws IOException {
		// stats
		long totalTakeDownTime = 0;
		
		ObjectSet <Tracked> _sites = oc.get(Tracked.class);
		Iterator <Tracked> i = _sites.iterator();
		
		
		long[] medianItems = new long[_sites.size()];
		int medianI = 0;
		
		// page header
		StringBuffer content = new StringBuffer();
		content.append("<p><span class='importantText'><strong>"+_sites.size()+((_mode == MODE_ARCHIVE) ? " ARCHIVED site" : " CURRENTLY MONITORED site")+(_sites.size() != 1 ? "s":"")+"</strong></span>");
		content.append("<br />");
		if (_mode == MODE_CURRENT) 
			content.append("<p class='smallerLighter'>Note: The stats below are largely self-explanatory with one exception: occasionally the DNS for a malicious site is disabled, but the web server remains active.<br />We tally these as 'UP' until the DNS cache timer expires, or the server is actually taken down.... because once the site is in cache, it remains reachable by some potential victims.</p>");
		content.append("<hr>");
		content.append("<table>");

		while (i.hasNext()) {
			Tracked t = i.next();
			if (_mode != MODE_ARCHIVE) {
				content.append("<tr><td colspan='2'><a href='"+t.url+"' target='_other'><b>"+t.url+"</b></a></td></tr>");
				content.append("<tr><td>&nbsp;&nbsp;&nbsp;</td><td>");
			}
//			else {
//				content.append("<tr><td colspan='2'><b>"+t.url+"</b></td></tr>");
//				content.append("<tr><td>&nbsp;&nbsp;&nbsp;</td><td>");
//			}	
			if (t.label.length() > 0) 
				content.append("<b>"+t.label+"</b><br />");
			// only show status for CURRENT sites
			if (_mode != MODE_ARCHIVE) {
				content.append("<b>Status:</b> "+(t.running() ? "Actively monitoring":"Stopped monitoring")+"; site is ");
				// Status word and color
				String s;
				if (t.getStopSignalCount() == 0)
					s = FONT_RED+"<b>UP</b></font>";
				else if (t.getStopSignalCount() < t.getMaxStopSignals()) {
					s = FONT_YELLOW+"<b>POSSIBLY DOWN</b> ("+t.getStopSignalCount()+")";
					s += (t.getStopSignalTime() > 0) ? " since "+sdf.format(new Date(t.getStopSignalTime()))+"</font>" : "</font>";
				}
				else
					s = FONT_GREEN+"<b>DOWN</b></font>";
				content.append(s+"<br />");
			}
			
			// First contact and offline time (if offline)
			content.append("<b>First contact:</b> "+sdf.format(new Date(t.startTime))+"<br />");
			if (! t.running())
				content.append("<b>Confirmed offline at:</b> "+sdf.format(new Date(t.getStopSignalTime()))+"<br />");
			// uptime hours and minutes
			content.append("<b>Approximate uptime:</b> "+hoursAndMinutes((long) t.getDurationSec()*1000)+"<br />");
			// ping count and most recent ping result
//			content.append("<b>Pings:</b> "+t.getPingCount()+" latest: ");
//			Ping p = t.getLastPing();
//			if (p != null)
//				content.append("["+p.httpResult+"] "+sdf.format(new Date(p.timestamp))+" "+p.title+"<br />");
//			else
//				content.append("<i>no pings recorded</i><br />");
			
			if (t.hasContentProfile() && (_mode != MODE_ARCHIVE)) {
				content.append("<table border=1><tr><td align='center'><b>Host</b></td><td align='center'>Bytes</td><td align='center'>Links</td></tr>");
				ContentProfile cp = t.getContentProfile();
				DecimalFormat dfBytes = new DecimalFormat(PhishTrack.BYTE_FORMAT);
				DecimalFormat dfPct = new DecimalFormat(PhishTrack.PCT_FORMAT);
				try {
					Object[] cts = cp.getHosts();
					Arrays.sort(cts);
					int allBytes = cp.getAllBytes();
					int allLinks = cp.getAllLinks();
					for (int i2 = 0; i2 < cts.length; i2++) {
						int bytes = cp.getBytes((String) cts[i2]);
						int links = cp.getLinks((String) cts[i2]);
						content.append("<tr><td align='right'>"+(String) cts[i2]+"</td>");
						content.append("<td align='right'>&nbsp;"+dfBytes.format(bytes)+" ("+dfPct.format((double)bytes/(double)allBytes)+")</td>");
						content.append("<td align='right'>&nbsp;"+links+" ("+dfPct.format((double)links/(double)allLinks)+")</td>");
						content.append("</tr>");
					}
				}
				catch (InvalidProfileException ipe) {
					PhishTrack.addEvent("Invalid Profile Exception");
				}
				content.append("</table>");
			}
			else {
				content.append("&nbsp;<br />");
			}
			
			content.append("</td></tr>");
			
			// accumulate stats
			totalTakeDownTime += t.getDurationSec();
			medianItems[medianI] = t.getDurationSec();
			medianI++;
		}
		content.append("</table></p>");
		
		if (_sites.size() > 1) {
			content.append("<p class='importantText'><b>Mean (average) uptime of the sites above: "+hoursAndMinutes((long) (totalTakeDownTime *1000L)/_sites.size())+"</b></p>");
			content.append("<p class='importantText'><b>Median uptime of the sites above: "+hoursAndMinutes(calcMedian(medianItems)*1000L)+"</b></p>");
		}
		_outStream.print(content.toString());
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
	

	private long calcMedian(long[] items) {
		int medianPointer;
		
		if (items.length < 1)
			return 0;
		
		// order by value
		Arrays.sort(items);

		// if odd count, pick the middle item
		medianPointer = (int) (items.length / 2);
		
		System.out.println("MedianPointer: "+medianPointer);
		System.out.println(items.length);
		
		
		if ( (items.length & 0xFFFFFFFE) != items.length) {
			System.out.println("items.length is odd "+items.length);
			return items[medianPointer];
		}
		// if even count, pick the middle two and average them
		else { 
			System.out.println("Items.length is even "+items.length);
			return (int) ((items[medianPointer-1] + items[medianPointer])/2);
		}
	}
	
	
	
	
	
	public void sendEmail(String subject, String message) {
		PhishTrack.addEvent("Sending mail to "+ptc.mailTo);
		try {
			// get a socket connection to the 'galaxy' mail
			// server at SMTP port 25
			Socket socket = new Socket(ptc.smtpServer, 25);
			// Create an output stream for sending message
			PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
			// send mail using SMTP protocol
			out.println("ehlo phishmonitor");
			out.println("mail from:" + "<"+ptc.mailFrom+">");
			out.println("rcpt to:" + "<"+ptc.mailTo+">");
			out.println("data");  // Skip line after DATA
			out.println("Subject:"+subject);
			out.println("To:"+ptc.mailTo);
			out.println(message);
			out.println(".");       // End message with a single period
			out.flush();
		}
		catch (Exception e)
		{
			PhishTrack.addEvent("Failed to send email: " + e);
		}
	}
	
	
	
	
}
