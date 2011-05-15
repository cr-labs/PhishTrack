package com.challengeandresponse.phishtrack;

import java.io.IOException;
import java.net.*;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Encapsulates a "study" of the phish site, using the page contents that were captured
 * at the time of the first ping.</p>
 * <p>The information of interest is a collection of hosts from which the phish page 
 * pulls content, the number of links to each host (indicating how many connections will
 * be made to it), and the number of bytes of content in total, behind those links</p>
 * <p>The ContentProfile helps to show how the burden of servicing a phish web page
 * is distributed among fake and legitimate servers.</p>
 * <p>To use this:<br />
 * <pre>
 * 	// some content to process
 *		StringBuffer sb = new StringBuffer();
 *		sb.append("<html><head><title></title></head>");
 *		sb.append("<body bgcolor='#FFFFFF'>");
 *		sb.append("<IMG src    =      \"http://agentzero.com/agentzero.gif\">");
 *		sb.append("</body></html>");
 *		ContentProfile cp = new ContentProfile(sb.toString());
 *		try {
 *			cp.buildProfile("Mozilla",new URL("http://agentzero.com/"),0,0);
 *			System.out.println("All links: "+cp.getAllLinks());
 *			System.out.println("Hosts:");
 *			Object[] cts = cp.getHosts();
 *			for (int i = 0; i < cts.length; i++) {
 *				System.out.print("Host: "+(String) cts[i]);
 *				System.out.println(" Bytes: "+cp.getBytes((String) cts[i]));
 *				System.out.println(" Links: "+cp.getLinks((String) cts[i]));
 *			}
 *		}
 *		catch (InvalidProfileException ipe) {
 *			System.out.println("Invalid profile exception");
 *		}
 *		catch (MalformedURLException mue) {
 *			System.out.println("Malformed URL exception");
 *		}
 *
 * String pageContent = "(the content of the page)";
 * ContentProfile cp = new ContentProfile(pageContent);
 * cp.buildProfile();
 * System.out.println("Number of links on the page: "+cp.getAllLinks());
 * // etcetera
 * </pre>
 * 
 * @see Tracked.initialPageContent
 * @author jim
 * @version 1.01 2006-08-11
 * 
 * Copyright (c) 2006 Challenge/Response, LLC, Cambridge, MA
 *
 */

public class ContentProfile {

	/**
	 * One entry per content type (e.g. image/jpeg, text/html, etc) keyed by content type
	 * Hashtable objects are objects of the private class contentFeatures
	 */
	private Hashtable <String,ContentFeatures> contentTotals;
	private String pageContent;
	private boolean validProfile; // set true if buildProfile() completed successfully

	// MODEL for the pattern: <  a  href="http://adfsdf.dssdfsd">
	private static final Pattern TAG_PATTERN = Pattern.compile("<(.*?)>");
	private static final Pattern CONTENT_PATTERN = Pattern.compile("(\\s*?\\S+?\\s+?).*?((http|https)://.+?)(\\\"|\\\').*?");



	/**
	 * 
	 * @param _pageContent The content to scan for links when buildProfile() is called
	 */
	public ContentProfile(String _pageContent) {
		pageContent = _pageContent;
		contentTotals = new Hashtable <String,ContentFeatures> ();
		validProfile = false;
	}


	private String hostnameAndIP(String hostName) {
		try {
			InetAddress ia = InetAddress.getByName(hostName);
			return hostName+" ["+ia.getHostAddress()+"]";
		}
		catch (UnknownHostException uhe) {
			return hostName+" [unknown IP]";
		}
	}


	public void buildProfile(String userAgent, String basePageURL, int connectTimeoutMsec, int readTimeoutMsec) {
		try {
			URL u = new URL(basePageURL);

			PhishTrack.addEvent("in buildProfile for host "+u.getHost());

			// add the base page URL to the baseline data
			tallyContent(hostnameAndIP(u.getHost()),pageContent.length());

			// if we made it here at all, have to call it "valid" - it'll at least have its home page in the list
			validProfile = true;

			// step through all the <...href= items
			Matcher mTag = TAG_PATTERN.matcher(pageContent);
			while (mTag.find()) {
				Matcher mLink = CONTENT_PATTERN.matcher(mTag.group(1));
				if (mLink.matches()) {
					System.out.println("checking "+mLink.group(2));
					// Tally <a> links separately... no need to retrieve, just count it
					if (mLink.group(1).trim().toLowerCase().equals("a")) {
						tallyContent("hyperlinks to other pages",0);
						continue;
					}
					// otherwise, retrieve the Content-Type and size of the content pointed to by this link
					URL url = new URL(mLink.group(2));
					HttpURLConnection urlc = openURLConnection(url,userAgent,connectTimeoutMsec,readTimeoutMsec);
					int contentLength = urlc.getContentLength();
					if (contentLength > -1) {
						tallyContent(hostnameAndIP(url.getHost()),contentLength);
					}
					urlc.disconnect();
				}
			}
		}
		catch (MalformedURLException mue) {
			System.out.println("MalformedURLException:"+mue.getMessage());
		}
		catch (SocketTimeoutException ste) {
			System.out.println("SocketTimeoutException:"+ste.getMessage());
		}
		catch (IOException ioe) {
			System.out.println("IOException:"+ioe.getMessage());
		}
	}




	/**
	 * Add a content feature if we haven't tallied it yet, or increment its totals
	 * Total bytes is increased by _bytes, and links is incremented by 1
	 * 
	 * @param _host
	 * @param _bytes The number of bytes this content item is
	 */
	private void tallyContent(String _host, int _bytes) {
		PhishTrack.addEvent("Tallying "+_host+" "+_bytes);

		ContentFeatures cf = (ContentFeatures) contentTotals.get(_host);
		if (cf == null)
			cf = new ContentFeatures();
		cf.bytes += _bytes;
		cf.links++;
		contentTotals.put(_host.trim().toLowerCase(),cf);
	}




	/**
	 * get the number of bytes of the given content type, or 0 if it's not on file
	 * @param _host The host that holds the content
	 * @return the number of bytes of the given content type
	 * @throws InvalidProfileException if the profile is not current and valid (buildProfile() must have been called and must have completed successfully)
	 */
	public int getBytes(String _host)
	throws InvalidProfileException {
		if (! validProfile)
			throw new InvalidProfileException();

		ContentFeatures cf = (ContentFeatures) contentTotals.get(_host.toLowerCase());
		if (cf != null)
			return cf.bytes;
		else
			return 0;
	}

	/**
	 * 
	 * @param _host The host that holds the content
	 * @return
	 * @throws InvalidProfileException if the profile is not current and valid (buildProfile() must have been called and must have completed successfully)
	 */
	public int getLinks(String _host)
	throws InvalidProfileException {
		if (! validProfile)
			throw new InvalidProfileException();

		ContentFeatures cf = (ContentFeatures) contentTotals.get(_host.toLowerCase());
		if (cf != null)
			return cf.links;
		else
			return 0;
	}


	/**
	 * @return
	 * @throws InvalidProfileException if the profile is not current and valid (buildProfile() must have been called and must have completed successfully)
	 */	
	public int getAllBytes()
	throws InvalidProfileException {
		if (! validProfile)
			throw new InvalidProfileException();

		Enumeration <String> e = contentTotals.keys();
		int totalBytes = 0;

		while (e.hasMoreElements()) {
			ContentFeatures cf = contentTotals.get(e.nextElement());
			if (cf == null) 
				continue;
			totalBytes += cf.bytes;
		}
		return totalBytes;
	}


	/**
	 * @return
	 * @throws InvalidProfileException if the profile is not current and valid (buildProfile() must have been called and must have completed successfully)
	 */	
	public int getAllLinks()
	throws InvalidProfileException {
		if (! validProfile)
			throw new InvalidProfileException();

		Enumeration <String> e = contentTotals.keys();
		int totalLinks = 0;

		while (e.hasMoreElements()) {
			ContentFeatures cf = contentTotals.get(e.nextElement());
			if (cf == null) 
				continue;
			totalLinks += cf.links;
		}
		return totalLinks;
	}


	/**
	 * @return an Object[] of the Hosts that are present in this ContentProfile
	 * @throws InvalidProfileException if the profile is not current and valid (buildProfile() must have been called and must have completed successfully)
	 */
	public Object[] getHosts()
	throws InvalidProfileException {
		if (! validProfile)
			throw new InvalidProfileException();

		return contentTotals.keySet().toArray();
	}


	public boolean valid() {
		return validProfile;
	}


	

	/**
	 * 
	 * @param lineEnd line ending code (e.g.: &lt;br /&gt; for html output)
	 * @return
	 */
	public String toString() {
		try {
			Object[] cts = getHosts();
			StringBuffer sb = new StringBuffer();
			for (int i = 0; i < cts.length; i++) {
				sb.append("Host: "+(String) cts[i]);
				sb.append(" Bytes: "+getBytes((String) cts[i]));
				sb.append(" Links: "+getLinks((String) cts[i]));
			}
			return sb.toString();
		}
		catch (InvalidProfileException ipe) {
			return "";
		}
	}

	private HttpURLConnection openURLConnection(URL url, String userAgent, int connectTimeoutMsec, int readTimeoutMsec)
	throws IOException, SocketTimeoutException, MalformedURLException {
		HttpURLConnection urlc = (HttpURLConnection) url.openConnection();
		urlc.setRequestProperty("User-Agent",userAgent);
		urlc.setInstanceFollowRedirects(true);
		urlc.setUseCaches(false);
		urlc.setConnectTimeout(connectTimeoutMsec);
		urlc.setReadTimeout(readTimeoutMsec);
		urlc.connect();
		return urlc;
	}




	public static void main(String[] args) {

		// some content to process
		StringBuffer sb = new StringBuffer();
		sb.append("<html><head><title></title></head>");
		sb.append("<body bgcolor='#FFFFFF'>");
		sb.append("<IMG src    =      \"http://agentzero.com/agentzero.gif\">");
		sb.append("<  a   href =  'http://www.agentzero.com/eggbert/fun.html'>");
		sb.append("</body></html>");

		ContentProfile cp = new ContentProfile(sb.toString());

		try {
			cp.buildProfile("Mozilla","http://agentzero.com/",0,0);
			System.out.println("All links: "+cp.getAllLinks());
			System.out.println("Hosts:");
			Object[] cts = cp.getHosts();
			for (int i = 0; i < cts.length; i++) {
				System.out.print("Host: "+(String) cts[i]);
				System.out.print(" Bytes: "+cp.getBytes((String) cts[i]));
				System.out.println(" Links: "+cp.getLinks((String) cts[i]));
			}
		}
		catch (InvalidProfileException ipe) {
			System.out.println("Invalid profile exception");
		}
	}


}
