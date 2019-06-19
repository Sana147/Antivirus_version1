/*
 * Copyright © 2017 Sana and others.  All rights reserved.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 */

package org.opendaylight.Antivirus.impl;

/* IMPORTANT NOTE: 
 * This file is written using FlowGuard as reference.
 */

public class PacketHeader {
	
	public String dl_src; // Source MAC Address
	public String dl_dst; // Destination MAC Address
	public short dl_type = 0; // An Opcode of 0x800 means the format is IPv4.
	public int nw_src_prefix = 0; // Source IP Address, the part before "/", i.e., 10.0.0.2 in 10.0.0.2/26.
	public int nw_src_maskbits = 0; // Masked bits from Source IP Address, the part after "/", i.e., 26 in 10.0.0.2/26.
	public int nw_dst_prefix = 0; // Destination IP Address, the part after "/"
	public int nw_dst_maskbits = 0; // Masked bits from Destination IP Address, the part after "/" 
	public int tcp_src = 0; // Source Port
	public int tcp_dst = 0; // Destination Port
	
	public PacketHeader packetheader () {
		PacketHeader PH = new PacketHeader();
		PH.dl_src = this.dl_src;
		PH.dl_dst = this.dl_dst;
		PH.dl_type = this.dl_type;
		PH.nw_src_prefix = this.nw_src_prefix;
		PH.nw_src_maskbits = this.nw_src_maskbits;
		PH.nw_dst_prefix = this.nw_dst_prefix;
		PH.nw_dst_maskbits = this.nw_dst_maskbits;
		PH.tcp_src = this.tcp_src;
		PH.tcp_dst = this.tcp_dst;
		
		return PH;
	}
}
