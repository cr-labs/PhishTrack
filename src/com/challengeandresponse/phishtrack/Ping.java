package com.challengeandresponse.phishtrack;

public class Ping {

	long 	timestamp;
	int		httpResult;
	String	title;

	
	public Ping() {
		super();
		timestamp = System.currentTimeMillis();
		title = "";
		httpResult = 0;
	}

}
