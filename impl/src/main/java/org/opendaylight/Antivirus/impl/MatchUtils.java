/*
 * Copyright © 2017 Sana and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.Antivirus.impl;

import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.Ipv4Prefix;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.inet.types.rev130715.PortNumber;
import org.opendaylight.yang.gen.v1.urn.ietf.params.xml.ns.yang.ietf.yang.types.rev130715.MacAddress;
import org.opendaylight.yang.gen.v1.urn.opendaylight.flow.types.rev131026.flow.mod.removed.MatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.l2.types.rev130827.EtherType;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.ethernet.match.fields.EthernetDestinationBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.ethernet.match.fields.EthernetSourceBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.ethernet.match.fields.EthernetTypeBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.EthernetMatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.IpMatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.layer._3.match.Ipv4MatchBuilder;
import org.opendaylight.yang.gen.v1.urn.opendaylight.model.match.types.rev131026.match.layer._4.match.TcpMatchBuilder;

public class MatchUtils {

		// For now, creating matching object for source and destination MAC, source and destination IP, source and destination Port.
	 	public static final long IPV4_LONG = (long) 0x800;
	 
	 	public static MatchBuilder createEthSrcDstMatch(MatchBuilder matchBuilder, MacAddress srcMac, MacAddress dstMac) {
		   // Match on source MAC and destination MAC.
		   EthernetMatchBuilder ethernetMatch = new EthernetMatchBuilder();
	        if (srcMac != null) {
	            EthernetSourceBuilder ethSourceBuilder = new EthernetSourceBuilder();
	            ethSourceBuilder.setAddress(srcMac);
	            ethernetMatch.setEthernetSource(ethSourceBuilder.build());
	        }
	        if (dstMac != null) {
	            EthernetDestinationBuilder ethDestinationBuild = new EthernetDestinationBuilder();
	            ethDestinationBuild.setAddress(dstMac);
	            ethernetMatch.setEthernetDestination(ethDestinationBuild.build());
	        }
	        if (matchBuilder.getEthernetMatch() != null && matchBuilder.getEthernetMatch().getEthernetType() != null) {
	            ethernetMatch.setEthernetType(matchBuilder.getEthernetMatch().getEthernetType());
	        }

	        matchBuilder.setEthernetMatch(ethernetMatch.build());

	        return matchBuilder;
	    }
	   
	 	public static MatchBuilder createIPSrcDstMatch(MatchBuilder matchBuilder, Ipv4Prefix dstIp, Ipv4Prefix srcIp) {
	 		// Match on source IP and destination IP
		    EthernetMatchBuilder eth = new EthernetMatchBuilder();
		    EthernetTypeBuilder ethTypeBuilder = new EthernetTypeBuilder();
		    ethTypeBuilder.setType(new EtherType(IPV4_LONG));
		    eth.setEthernetType(ethTypeBuilder.build());
		    matchBuilder.setEthernetMatch(eth.build());

		    Ipv4MatchBuilder ipv4match = new Ipv4MatchBuilder();
		    ipv4match.setIpv4Destination(dstIp);
		    ipv4match.setIpv4Source(srcIp);
		    matchBuilder.setLayer3Match(ipv4match.build());

		    return matchBuilder;
		}
	 	
	 	 public static MatchBuilder createSetDstTcpMatch(MatchBuilder matchBuilder, PortNumber tcpDstPort, PortNumber tcpSrcPort) {
	 		// Match on source Port and destination Port
	 	    EthernetMatchBuilder ethType = new EthernetMatchBuilder();
	 	    EthernetTypeBuilder ethTypeBuilder = new EthernetTypeBuilder();
	 	    boolean matchSet = false;

	 	    ethTypeBuilder.setType(new EtherType(IPV4_LONG));
	 	    ethType.setEthernetType(ethTypeBuilder.build());
	 	    matchBuilder.setEthernetMatch(ethType.build());

	 	    TcpMatchBuilder tcpmatch = new TcpMatchBuilder();

	 	    if(tcpDstPort.getValue() != 0) { // why != 0, is it required....?
	 	    	tcpmatch.setTcpDestinationPort(tcpDstPort);
	 	    	matchSet = true;
	 	    }
	 	    if(tcpSrcPort.getValue() != 0) {
	 	    	tcpmatch.setTcpSourcePort(tcpSrcPort);
	 	    	matchSet = true;
	 	    }
	 	    if(matchSet) {
	 	        IpMatchBuilder ipmatch = new IpMatchBuilder();
	 	        ipmatch.setIpProtocol((short) 6);
	 	        matchBuilder.setIpMatch(ipmatch.build());
	 	        matchBuilder.setLayer4Match(tcpmatch.build());
	 	    }
	 	    return matchBuilder;
	 	}
}

/*
Reference: https://www.programcreek.com/java-api-examples/?code=opendaylight/faas/faas-master/fabrics/vxlan-fabric/adapters/ovs-adapter/src/main/java/org/opendaylight/faas/fabrics/vxlan/adapters/ovs/utils/OfMatchUtils.java */
